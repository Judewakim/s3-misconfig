"""
S3 Sentry — Responder Lambda (Function URL)

Handles the signed links in the scan email.

  GET  ?token=…   verify the link, read the bucket's live settings, show what
                  will change, what can break, and whether it can be undone
  POST token=…    verify again, spend the single-use nonce, act, log

Actions (the token's `action` field)
  FIX       snapshot -> confirm snapshot readable -> apply -> verify -> log,
            then offer a signed ROLLBACK link (48 h)
  ROLLBACK  restore from the vault snapshot -> verify -> log
  IGNORE    suppress the finding in future emails -> log
  UNIGNORE  remove the suppression -> log
  LOG       (GET only, reusable for 7 days) download every action as CSV/JSON

Safety
  - Signature and expiry are checked on GET as well as POST, so a forged link
    can't make S3 Sentry read anyone's bucket.
  - FIX/IGNORE links die when a newer scan runs (scan_sequence). ROLLBACK and
    LOG links don't, so a daily scan can't void the undo window.
  - Nonces are spent with a conditional write: a link can't be replayed.
  - DRY_RUN=true (default) records what would happen and changes nothing.
"""

import base64
import csv
import hashlib
import html
import io
import json
import logging
import os
import re
from datetime import datetime, timedelta, timezone
from urllib.parse import parse_qs

import boto3
from boto3.dynamodb.conditions import Attr, Key
from botocore.exceptions import ClientError, ParamValidationError

import remediation
from token_utils import (
    TokenError,
    TokenExpiredError,
    TokenSequenceError,
    TokenSignatureError,
    generate_action_token,
    get_signing_key,
    validate_action_token,
)

logger = logging.getLogger()
logger.setLevel(logging.INFO)

DYNAMODB_TABLE  = os.environ.get("DYNAMODB_TABLE", "S3Sentry")
HMAC_KEY_PATH   = os.environ.get("HMAC_KEY_PATH", "/s3sentry/hmac_signing_key")
S3_VAULT_BUCKET = os.environ["S3_VAULT_BUCKET"]
DRY_RUN         = os.environ.get("DRY_RUN", "true").lower() == "true"

ROLLBACK_HOURS = 48
LOG_HOURS = 24 * 7
ACTIONS = ("FIX", "IGNORE", "UNIGNORE", "ROLLBACK", "LOG")
SEQUENCE_BOUND = ("FIX", "IGNORE")

_dynamodb    = boto3.resource("dynamodb")
_table       = _dynamodb.Table(DYNAMODB_TABLE)
_sts         = boto3.client("sts")
_provider_s3 = boto3.client("s3")


class ActionError(Exception):
    def __init__(self, message, code=400):
        super().__init__(message)
        self.message, self.code = message, code


def _now():
    return datetime.now(timezone.utc)


# ── HTML ──────────────────────────────────────────────────────────────────────

_CSS = """
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,sans-serif;background:#f6f7f5;
     color:#2b2b2c;display:flex;justify-content:center;padding:32px 16px;line-height:1.55}
.card{background:#fff;border:1px solid #e4e6e2;border-radius:14px;max-width:640px;width:100%;overflow:hidden}
.head{display:flex;justify-content:space-between;align-items:center;padding:18px 24px;border-bottom:1px solid #e4e6e2}
.brand{font-weight:700}.brand b{color:#4b7a22}
.pill{font-size:12px;font-weight:600;padding:3px 10px;border-radius:999px;background:#eef5e6;color:#4b7a22}
.pill.warn{background:#fbf4df;color:#8a6a0f}.pill.err{background:#fbeceb;color:#c23a2f}
.body{padding:24px;display:grid;gap:16px}
h1{font-size:20px;line-height:1.3}
.meta{font-size:13px;color:#6e6e70}.meta code{color:#2b2b2c}
.diff{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.diff div{font-size:12px;color:#6e6e70}
pre{margin-top:4px;padding:10px;background:#f6f7f5;border:1px solid #e4e6e2;border-radius:8px;
    font:12px/1.5 ui-monospace,Menlo,monospace;color:#2b2b2c;white-space:pre-wrap;word-break:break-word}
.after pre{border-color:#83b552}
.box{padding:14px 16px;border-radius:10px;background:#fbf4df;font-size:14px}
.box.ok{background:#eef5e6}.box.err{background:#fbeceb}
.box h2{font-size:13px;margin-bottom:6px}
ul{padding-left:18px}li+li{margin-top:4px}
.row{display:flex;gap:10px;flex-wrap:wrap;align-items:center}
button,.btn{font:600 15px/1 inherit;padding:12px 20px;border-radius:999px;border:0;cursor:pointer;
            background:#2b2b2c;color:#fff;text-decoration:none;display:inline-block}
.btn.ghost{background:#fff;color:#2b2b2c;border:1.5px solid #cfd2cc}
.fine{font-size:13px;color:#6e6e70}
.dry{background:#fbf4df;color:#8a6a0f;font-size:13px;padding:8px 24px;border-bottom:1px solid #e4e6e2}
@media(max-width:520px){.diff{grid-template-columns:1fr}}
"""

e = html.escape


def _page(title, body, pill="", pill_cls=""):
    dry = ('<div class="dry">Practice mode is on. S3 Sentry records what it would do '
           'and changes nothing in your account.</div>') if DRY_RUN else ""
    pill_html = f'<span class="pill {pill_cls}">{e(pill)}</span>' if pill else ""
    return (f"<!DOCTYPE html><html lang='en'><head><meta charset='utf-8'>"
            f"<meta name='viewport' content='width=device-width,initial-scale=1'>"
            f"<title>{e(title)} — S3 Sentry</title><style>{_CSS}</style></head><body>"
            f"<div class='card'><div class='head'><span class='brand'>S3 <b>Sentry</b></span>{pill_html}</div>"
            f"{dry}<div class='body'>{body}</div></div></body></html>")


def _json_block(d):
    return e(json.dumps(d, indent=2, sort_keys=True))


def _form(token, label, confirm_drift=False):
    tick = ("<p><label><input type='checkbox' name='confirm_drift' value='1' required> "
            "Overwrite the later changes too</label></p>") if confirm_drift else ""
    return (f"<form method='POST'><input type='hidden' name='token' value='{e(token, quote=True)}'>{tick}"
            f"<div class='row'><button type='submit'>{e(label)}</button>"
            f"<span class='fine'>Close this tab to cancel.</span></div></form>")


def error_page(message, code=400):
    return _page("Error", f"<h1>That didn't work</h1><div class='box err'>{e(message)}</div>",
                 f"Error {code}", "err")


def respond(status, body, content_type="text/html; charset=utf-8", extra=None):
    headers = {
        "Content-Type": content_type,
        "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; "
                                   "form-action 'self'; frame-ancestors 'none'; base-uri 'none'",
        "X-Content-Type-Options": "nosniff",
        "Referrer-Policy": "no-referrer",
        "Cache-Control": "no-store",
    }
    headers.update(extra or {})
    return {"statusCode": status, "headers": headers, "body": body}


# ── Token handling ────────────────────────────────────────────────────────────

def _peek(token):
    """Unverified decode, only to find which tenant's sequence to check against."""
    try:
        b64 = token.split(".")[0]
        b64 += "=" * (-len(b64) % 4)
        return json.loads(base64.urlsafe_b64decode(b64))
    except Exception:
        return None


def _get_tenant(account_id):
    return _table.get_item(Key={"PK": f"ACC#{account_id}", "SK": "METADATA"}).get("Item")


def verify(token):
    """Full signature, expiry and (where relevant) freshness check.
    Returns (payload, tenant). Raises ActionError."""
    peek = _peek(token)
    if not peek or not isinstance(peek, dict):
        raise ActionError("This link is malformed.", 400)
    tenant = _get_tenant(str(peek.get("account_id", "")))
    if not tenant:
        raise ActionError("This link doesn't match an S3 Sentry account.", 400)
    action = peek.get("action")
    try:
        payload = validate_action_token(
            token, get_signing_key(HMAC_KEY_PATH), int(tenant.get("ScanSequence", 0)),
            check_sequence=action in SEQUENCE_BOUND,
        )
    except TokenSignatureError:
        raise ActionError("This link's signature is invalid. It may have been altered.", 400)
    except TokenExpiredError:
        raise ActionError("This link has expired.", 410)
    except TokenSequenceError:
        raise ActionError("A newer scan has run since this email. Use the links in your latest email.", 409)
    except TokenError:
        raise ActionError("This link is invalid.", 400)
    if payload.get("action") not in ACTIONS:
        raise ActionError("Unknown action.", 400)
    return payload, tenant


def spend_nonce(payload):
    try:
        _table.put_item(
            Item={"PK": f"TOKEN#{payload['jti']}", "SK": "USED", "UsedAt": _now().isoformat(),
                  "AccountId": payload["account_id"], "ttl": int(payload["exp"]) + 86400},
            ConditionExpression=Attr("PK").not_exists(),
        )
    except _dynamodb.meta.client.exceptions.ConditionalCheckFailedException:
        raise ActionError("This link has already been used. Each link works once.", 409)


def _mint(payload_base, action, hours, **extra):
    p = {k: payload_base[k] for k in ("account_id", "check_id", "resource_id", "recipient_email", "scan_sequence")}
    p.update(action=action, **extra)
    return generate_action_token(p, get_signing_key(HMAC_KEY_PATH), hours)


# ── AWS helpers ───────────────────────────────────────────────────────────────

def _source_identity(actor):
    """STS SourceIdentity allows 2-64 chars of letters, digits and _+=,.@-; drop anything else."""
    clean = re.sub(r"[^\w+=,.@-]", "", actor or "")[:64]
    return clean if len(clean) >= 2 else None


def _customer_s3(tenant, account_id, actor):
    kwargs = dict(RoleArn=tenant["RoleArn"], RoleSessionName=f"s3sentry-{account_id}",
                  ExternalId=tenant["ExternalId"], DurationSeconds=900)
    # SourceIdentity puts the approving person in the customer's CloudTrail.
    # Customers onboarded before sts:SetSourceIdentity was in the trust policy
    # reject it, so retry without it on AccessDenied / ValidationError.
    ident = _source_identity(actor)
    if ident:
        kwargs["SourceIdentity"] = ident
    unreachable = ActionError("S3 Sentry can't reach your account. Is the S3 Sentry role still deployed?", 502)
    try:
        creds = _sts.assume_role(**kwargs)["Credentials"]
    except ParamValidationError:
        raise ActionError("This account's S3 Sentry setup is incomplete. Contact support.", 500)
    except ClientError as err:
        code = err.response.get("Error", {}).get("Code", "")
        if "SourceIdentity" not in kwargs or code not in ("AccessDenied", "ValidationError"):
            raise unreachable
        kwargs.pop("SourceIdentity")
        try:
            creds = _sts.assume_role(**kwargs)["Credentials"]
        except ClientError:
            raise unreachable
    return boto3.client("s3", aws_access_key_id=creds["AccessKeyId"],
                        aws_secret_access_key=creds["SecretAccessKey"],
                        aws_session_token=creds["SessionToken"])


def _handler_for(check_id):
    r = remediation.for_check(check_id)
    if not r:
        raise ActionError("S3 Sentry can't fix this check automatically. The scan email explains how to fix it by hand.", 422)
    return r


def write_snapshot(account_id, check_id, bucket, state):
    """Store the pre-fix settings, then read them back. A fix only proceeds if
    the snapshot is retrievable and intact, so rollback is known to work."""
    doc = {"schema": 1, "account_id": account_id, "check_id": check_id, "bucket": bucket,
           "captured_at": _now().isoformat(), "state": state}
    body = remediation.canonical(doc).encode()
    digest = hashlib.sha256(body).hexdigest()
    key = f"{account_id}/{bucket}/{check_id}/{_now().strftime('%Y%m%dT%H%M%S%fZ')}.json"
    _provider_s3.put_object(Bucket=S3_VAULT_BUCKET, Key=key, Body=body,
                            ContentType="application/json", ServerSideEncryption="AES256")
    read_snapshot(key, digest)          # proves the undo path before any change
    return key, digest


def read_snapshot(key, digest):
    try:
        body = _provider_s3.get_object(Bucket=S3_VAULT_BUCKET, Key=key)["Body"].read()
    except ClientError:
        raise ActionError("The saved copy of your settings couldn't be read, so nothing was changed.", 500)
    if hashlib.sha256(body).hexdigest() != digest:
        raise ActionError("The saved copy of your settings failed its integrity check, so nothing was changed.", 500)
    return json.loads(body)


def _fields(fields):
    return {k: (json.dumps(v, default=str) if isinstance(v, (dict, list)) else v)
            for k, v in fields.items() if v is not None}


def audit_update(account_id, sk, status, **fields):
    vals = {"Status": status, **_fields(fields)}
    names = {f"#k{i}": k for i, k in enumerate(vals)}
    _table.update_item(
        Key={"PK": f"ACC#{account_id}", "SK": sk},
        UpdateExpression="SET " + ", ".join(f"#k{i} = :v{i}" for i in range(len(vals))),
        ExpressionAttributeNames=names,
        ExpressionAttributeValues={f":v{i}": v for i, v in enumerate(vals.values())},
    )


def audit(account_id, action, check_id, bucket, actor, status, **fields):
    ts = _now().isoformat()
    sk = f"AUDIT#{ts}#{action}#{check_id}#{bucket}"
    item = {"PK": f"ACC#{account_id}", "SK": sk, "Action": action, "Status": status,
            "CheckID": check_id, "ResourceID": bucket, "Actor": actor or "", "At": ts,
            "DryRun": DRY_RUN}
    item.update(_fields(fields))
    _table.put_item(Item=item)
    return sk


# ── Pages (GET) ───────────────────────────────────────────────────────────────

def _undo_text(plan):
    if plan.undo == remediation.FULL:
        return (f"Yes. You'll get an Undo link that works for {ROLLBACK_HOURS} hours and restores "
                f"the exact settings saved before the change.")
    if plan.undo == remediation.PARTIAL:
        return "Partly. " + plan.undo_note
    return "No. AWS can't reverse this change."


def page_fix(token, payload, tenant):
    r = _handler_for(payload["check_id"])
    s3 = _customer_s3(tenant, payload["account_id"], None)
    plan = r.plan(r.read(s3, payload["resource_id"]), payload["check_id"])
    meta = (f"<p class='meta'>Bucket <code>{e(payload['resource_id'])}</code> &nbsp;·&nbsp; "
            f"Account <code>{e(payload['account_id'])}</code></p>")
    if not plan.changes_needed:
        return _page("Already fixed", f"<h1>{e(r.title)}</h1>{meta}"
                     f"<div class='box ok'>This bucket already has the right settings. Nothing to change.</div>",
                     "No change needed")
    warn = "".join(f"<li>{e(w)}</li>" for w in plan.warnings)
    cost = f"<p class='fine'>Cost: {e(plan.cost_note)}</p>" if plan.cost_note else ""
    undo_cls = "ok" if plan.undo == remediation.FULL else ""
    body = (f"<h1>{e(r.title)}</h1>{meta}<p>{e(r.action)}</p>"
            f"<div class='diff'><div>Now<pre>{_json_block(plan.before)}</pre></div>"
            f"<div class='after'>After the fix<pre>{_json_block(plan.after)}</pre></div></div>"
            f"<div class='box'><h2>What can break</h2><ul>{warn}</ul>{cost}</div>"
            f"<div class='box {undo_cls}'><h2>Can it be undone?</h2>{e(_undo_text(plan))}</div>"
            f"{_form(token, 'Apply the fix')}"
            f"<p class='fine'>Your current settings are saved before anything changes. "
            f"The change is recorded in your action log.</p>")
    return _page("Confirm fix", body, "Review before applying", "warn")


def page_rollback(token, payload, tenant):
    item = _load_fix(payload)
    snap = read_snapshot(item["VaultKey"], item["VaultSha256"])
    r = _handler_for(payload["check_id"])
    s3 = _customer_s3(tenant, payload["account_id"], None)
    current = r.read(s3, payload["resource_id"])
    target = r.restorable_state(snap["state"])
    note = ""
    drift = _drifted(r, current, item)
    if drift:
        note += ("<div class='box err'><h2>Settings changed since the fix</h2>Someone changed this "
                 "bucket after S3 Sentry fixed it. Undoing will overwrite those later changes too. "
                 "Tick the box below only if that's what you want.</div>")
    if remediation.canonical(target) != remediation.canonical(snap["state"]):
        note += ("<div class='box'><h2>Partial undo</h2>AWS can't return this bucket exactly to how it "
                "was. It will be set as shown on the right.</div>")
    body = (f"<h1>Undo: {e(r.title)}</h1>"
            f"<p class='meta'>Bucket <code>{e(payload['resource_id'])}</code> &nbsp;·&nbsp; "
            f"fixed {e(item['At'][:16].replace('T', ' '))} UTC</p>"
            f"<div class='diff'><div>Now<pre>{_json_block(current)}</pre></div>"
            f"<div class='after'>After undo<pre>{_json_block(target)}</pre></div></div>{note}"
            f"<div class='box'><h2>Heads up</h2>Undoing re-opens the risk the fix closed.</div>"
            f"{_form(token, 'Undo the fix', confirm_drift=drift)}")
    return _page("Confirm undo", body, "Review before undoing", "warn")


def page_simple(token, payload, verb, explain):
    body = (f"<h1>{e(verb)} this finding?</h1>"
            f"<p class='meta'>Bucket <code>{e(payload['resource_id'])}</code> &nbsp;·&nbsp; "
            f"Check <code>{e(payload['check_id'])}</code></p><p>{e(explain)}</p>{_form(token, verb)}")
    return _page(verb, body)


# ── Actions (POST) ────────────────────────────────────────────────────────────

def _who(payload):
    return (payload["account_id"], payload["check_id"], payload["resource_id"],
            payload.get("recipient_email", ""))


def _code(err):
    return getattr(err, "response", {}).get("Error", {}).get("Code", "")


def do_fix(payload, tenant):
    account, check, bucket, actor = _who(payload)
    r = _handler_for(check)
    if tenant.get("RemediationEnabled") is False:
        raise ActionError("This account was set up read-only, so S3 Sentry can't make changes. "
                          "Redeploy the S3 Sentry stack with remediation enabled to use fixes.", 403)
    s3 = _customer_s3(tenant, account, actor)
    before = r.read(s3, bucket)
    plan = r.plan(before, check)
    if not plan.changes_needed:
        audit(account, "FIX", check, bucket, actor, "NO_CHANGE_NEEDED", Before=before)
        return _page("No change needed", "<h1>Nothing to change</h1><div class='box ok'>This bucket "
                     "already had the right settings.</div>", "Done")

    key, digest = write_snapshot(account, check, bucket, before)
    # Record intent BEFORE touching the bucket, so a crash mid-change still
    # leaves an audit trail pointing at the snapshot.
    sk = audit(account, "FIX", check, bucket, actor, "PENDING", Before=before, After=plan.after,
               VaultKey=key, VaultSha256=digest, Undo=plan.undo,
               RollbackUntil=(_now() + timedelta(hours=ROLLBACK_HOURS)).isoformat())
    status, error = "SUCCEEDED", None
    if not DRY_RUN:
        try:
            r.apply(s3, bucket, plan.after)
            r.verify(s3, bucket, plan.after)
        except Exception as err:                           # noqa: BLE001
            error = str(err)[:500]
            if _code(err) == "AccessDenied":
                status = "NOT_PERMITTED"                    # the change was refused; nothing moved
            else:
                status = "FAILED"
                try:                                        # put it back the way it was
                    r.restore(s3, bucket, before)
                    r.verify(s3, bucket, r.restorable_state(before))
                    status = "FAILED_RESTORED"
                except Exception as rerr:                   # noqa: BLE001
                    error += f" | auto-restore failed: {str(rerr)[:300]}"
    try:
        audit_update(account, sk, status, Error=error)
    except Exception:                                       # noqa: BLE001
        logger.exception("audit update failed for %s", sk)  # PENDING record still exists
        if status == "SUCCEEDED":
            return _page("Fix not recorded", "<h1>Fix applied, but not fully recorded</h1>"
                         "<div class='box err'>The change was made, but S3 Sentry couldn't finish "
                         "recording it, so no Undo link can be issued. Your previous settings are "
                         "saved; contact support to undo this change.</div>", "Needs attention", "err")
    if status == "NOT_PERMITTED":
        return _page("Not permitted", "<h1>Fix not permitted</h1><div class='box err'>Your account's "
                     "S3 Sentry role doesn't allow this change, so nothing was changed.</div>", "Failed", "err")
    if status != "SUCCEEDED":
        msg = ("The change didn't take, so S3 Sentry put your settings back the way they were."
               if status == "FAILED_RESTORED" else
               "The change failed and S3 Sentry could not confirm your settings were restored. "
               "Check the bucket now; the saved copy is in your action log.")
        return _page("Fix failed", f"<h1>Fix failed</h1><div class='box err'>{e(msg)}</div>", "Failed", "err")

    undo_link = ""
    if plan.undo != remediation.NONE:
        rb = _mint(payload, "ROLLBACK", ROLLBACK_HOURS, audit_sk=sk)
        undo_link = f"<a class='btn ghost' href='?token={e(rb, quote=True)}'>Undo this fix</a>"
    log_link = (f"<a class='btn ghost' href='?token={e(_mint(payload, 'LOG', LOG_HOURS), quote=True)}'>"
                f"Action log</a>")
    done = "recorded (practice mode)" if DRY_RUN else "applied and verified"
    body = (f"<h1>Fix {done}</h1><p class='meta'>Bucket <code>{e(bucket)}</code></p>"
            f"<div class='box ok'>{e(r.title)}. Your previous settings are saved.</div>"
            f"<div class='row'>{undo_link}{log_link}</div>"
            f"<p class='fine'>The Undo link works once, for {ROLLBACK_HOURS} hours. "
            f"Bookmark this page if you might need it.</p>")
    return _page("Fix applied", body, "Done")


def _load_fix(payload):
    sk = payload.get("audit_sk", "")
    item = _table.get_item(Key={"PK": f"ACC#{payload['account_id']}", "SK": sk}).get("Item") if sk else None
    if (not item or item.get("Action") != "FIX" or item.get("Status") != "SUCCEEDED"
            or item.get("CheckID") != payload["check_id"] or item.get("ResourceID") != payload["resource_id"]):
        raise ActionError("There's no successful fix to undo for this link.", 404)
    if item.get("RolledBackAt"):
        raise ActionError("This fix was already undone.", 409)
    until = item.get("RollbackUntil", "")
    if until and _now().isoformat() > until:
        raise ActionError("The undo window for this fix has closed.", 410)
    if bool(item.get("DryRun")) != DRY_RUN:
        # A practice-run fix changed nothing, so there's nothing real to undo;
        # undoing it live would overwrite whatever the bucket has now.
        raise ActionError("This fix was a practice run, so there's nothing to undo." if item.get("DryRun")
                          else "This fix was live, but S3 Sentry is in practice mode. Contact support to undo it.", 409)
    return item


def _drifted(r, current, item):
    """True if the bucket no longer looks the way the fix left it."""
    try:
        after = json.loads(item.get("After") or "{}")
    except ValueError:
        return True
    return not r.matches(current, after)


def precheck_rollback(payload, tenant, form):
    """Runs before the nonce is spent, so a refused undo leaves the link usable."""
    item = _load_fix(payload)
    snap = read_snapshot(item["VaultKey"], item["VaultSha256"])
    r = _handler_for(payload["check_id"])
    s3 = _customer_s3(tenant, payload["account_id"], payload.get("recipient_email", ""))
    current = r.read(s3, payload["resource_id"])
    if _drifted(r, current, item) and form.get("confirm_drift") != "1":
        raise ActionError("This bucket changed after the fix. Open the Undo link again and confirm "
                          "you want to overwrite those changes.", 409)
    return {"item": item, "snap": snap, "r": r, "s3": s3, "current": current}


CLAIM_STALE = timedelta(minutes=15)


def _claim(item, now):
    _table.update_item(
        Key={"PK": item["PK"], "SK": item["SK"]},
        UpdateExpression="SET RollbackClaim = :t",
        ConditionExpression=Attr("RolledBackAt").not_exists()
                            & (Attr("RollbackClaim").not_exists()
                               | Attr("RollbackClaim").lt((now - CLAIM_STALE).isoformat())),
        ExpressionAttributeValues={":t": now.isoformat()},
    )


def do_rollback(payload, tenant, ctx):  # noqa: ARG001
    account, check, bucket, actor = _who(payload)
    item, snap, r, s3, current = ctx["item"], ctx["snap"], ctx["r"], ctx["s3"], ctx["current"]
    target = r.restorable_state(snap["state"])
    # Claim the fix first so two undo links can't race. A claim older than
    # CLAIM_STALE (e.g. the Lambda timed out mid-restore) can be taken over.
    now = _now()
    try:
        _claim(item, now)
    except _dynamodb.meta.client.exceptions.ConditionalCheckFailedException:
        raise ActionError("An undo for this fix is already in progress or done.", 409)
    status, error = "SUCCEEDED", None
    if not DRY_RUN:
        try:
            r.restore(s3, bucket, snap["state"])
            r.verify(s3, bucket, target)
        except Exception as err:                            # noqa: BLE001
            status, error = "FAILED", str(err)[:500]
    try:
        if status == "SUCCEEDED":
            _table.update_item(Key={"PK": item["PK"], "SK": item["SK"]},
                               UpdateExpression="SET RolledBackAt = :t REMOVE RollbackClaim",
                               ExpressionAttributeValues={":t": _now().isoformat()})
        else:   # release the claim so the owner can retry
            _table.update_item(Key={"PK": item["PK"], "SK": item["SK"]},
                               UpdateExpression="REMOVE RollbackClaim")
    except Exception:                                       # noqa: BLE001
        logger.exception("rollback claim update failed for %s", item["SK"])
    try:
        audit(account, "ROLLBACK", check, bucket, actor, status, Before=current, After=target,
              VaultKey=item["VaultKey"], FixAuditSK=item["SK"], Error=error)
    except Exception:                                       # noqa: BLE001
        logger.exception("rollback audit write failed for %s", item["SK"])
    if status != "SUCCEEDED":
        # Retry link never outlives the original undo window.
        remaining = (datetime.fromisoformat(item["RollbackUntil"]) - _now()).total_seconds() / 3600 \
            if item.get("RollbackUntil") else ROLLBACK_HOURS
        retry_html = ""
        if remaining > 0:
            retry = _mint(payload, "ROLLBACK", max(1, int(remaining)), audit_sk=item["SK"])
            retry_html = (f"<div class='row'><a class='btn ghost' href='?token={e(retry, quote=True)}'>"
                          f"Try the undo again</a></div>")
        return _page("Undo failed", "<h1>Undo failed</h1><div class='box err'>S3 Sentry couldn't "
                     "confirm the settings were restored. Check the bucket, then try again.</div>"
                     f"{retry_html}", "Failed", "err")
    done = "recorded (practice mode)" if DRY_RUN else "restored and verified"
    return _page("Undone", f"<h1>Undo {done}</h1><p class='meta'>Bucket <code>{e(bucket)}</code></p>"
                 f"<div class='box ok'>Settings are back to the saved copy.</div>", "Done")


def do_ignore(payload, tenant):  # noqa: ARG001
    account, check, bucket, actor = _who(payload)
    _table.put_item(Item={"PK": f"ACC#{account}", "SK": f"SUPPRESS#{check}#{bucket}",
                          "CheckID": check, "ResourceID": bucket,
                          "SuppressedAt": _now().isoformat(), "Actor": actor})
    audit(account, "IGNORE", check, bucket, actor, "SUCCEEDED")
    un = _mint(payload, "UNIGNORE", LOG_HOURS)
    return _page("Ignored", f"<h1>Finding ignored</h1><p class='meta'>Bucket <code>{e(bucket)}</code></p>"
                 f"<div class='box ok'>It won't appear in future scan emails.</div>"
                 f"<div class='row'><a class='btn ghost' href='?token={e(un, quote=True)}'>Stop ignoring</a></div>",
                 "Done")


def do_unignore(payload, tenant):  # noqa: ARG001
    account, check, bucket, actor = _who(payload)
    _table.delete_item(Key={"PK": f"ACC#{account}", "SK": f"SUPPRESS#{check}#{bucket}"})
    audit(account, "UNIGNORE", check, bucket, actor, "SUCCEEDED")
    return _page("Restored", "<h1>Finding restored</h1><div class='box ok'>It will appear in scan "
                 "emails again.</div>", "Done")


# ── Action log ────────────────────────────────────────────────────────────────

LOG_FIELDS = ("At", "Action", "Status", "DryRun", "CheckID", "ResourceID", "Actor",
              "Undo", "Before", "After", "VaultKey", "RolledBackAt", "Error")


def audit_items(account_id):
    items = []
    kwargs = {"KeyConditionExpression": Key("PK").eq(f"ACC#{account_id}") & Key("SK").begins_with("AUDIT#")}
    while True:
        resp = _table.query(**kwargs)
        items += resp.get("Items", [])
        if "LastEvaluatedKey" not in resp:
            break
        kwargs["ExclusiveStartKey"] = resp["LastEvaluatedKey"]
    rows = []
    for it in items:
        row = {f: it.get(f, "") for f in LOG_FIELDS}
        for f in ("Before", "After"):
            if isinstance(row[f], str) and row[f]:
                try:
                    row[f] = json.loads(row[f])
                except ValueError:
                    pass
        rows.append(row)
    rows.sort(key=lambda r: r["At"], reverse=True)
    return rows


def _csv_cell(v):
    if isinstance(v, (dict, list)):
        return json.dumps(v, sort_keys=True)
    if isinstance(v, str) and v[:1] in ("=", "+", "-", "@", "\t", "\r"):
        return "'" + v                         # stop spreadsheet formula injection
    return v


def log_response(payload, fmt):
    rows = audit_items(payload["account_id"])
    stamp = _now().strftime("%Y%m%d")
    if fmt == "json":
        return respond(200, json.dumps(rows, indent=2, default=str), "application/json",
                       {"Content-Disposition": f'attachment; filename="s3sentry-log-{stamp}.json"'})
    if fmt == "csv":
        buf = io.StringIO()
        w = csv.DictWriter(buf, fieldnames=LOG_FIELDS)
        w.writeheader()
        for row in rows:
            w.writerow({k: _csv_cell(v) for k, v in row.items()})
        return respond(200, buf.getvalue(), "text/csv; charset=utf-8",
                       {"Content-Disposition": f'attachment; filename="s3sentry-log-{stamp}.csv"'})
    token = e(payload["_raw"], quote=True)
    recent = "".join(
        f"<li>{e(r['At'][:16].replace('T', ' '))} — {e(r['Action'])} {e(r['Status'])}"
        f"{' (practice)' if r['DryRun'] is True else ''} — <code>{e(r['ResourceID'])}</code></li>"
        for r in rows[:10]) or "<li>No actions yet.</li>"
    body = (f"<h1>Action log</h1><p class='meta'>Account <code>{e(payload['account_id'])}</code>"
            f" &nbsp;·&nbsp; {len(rows)} entries</p><ul>{recent}</ul><div class='row'>"
            f"<a class='btn' href='?token={token}&amp;format=csv'>Download CSV</a>"
            f"<a class='btn ghost' href='?token={token}&amp;format=json'>Download JSON</a></div>"
            f"<p class='fine'>Every fix, undo, ignore and practice run, newest first. "
            f"This link works for 7 days.</p>")
    return respond(200, _page("Action log", body))


# ── Entry point ───────────────────────────────────────────────────────────────

POST_ACTIONS = {"FIX": do_fix, "ROLLBACK": do_rollback, "IGNORE": do_ignore, "UNIGNORE": do_unignore}


def handle_get(token, params):
    payload, tenant = verify(token)
    payload["_raw"] = token
    action = payload["action"]
    if action == "LOG":
        return log_response(payload, (params.get("format") or "").lower())
    if action == "FIX":
        return respond(200, page_fix(token, payload, tenant))
    if action == "ROLLBACK":
        return respond(200, page_rollback(token, payload, tenant))
    if action == "IGNORE":
        return respond(200, page_simple(token, payload, "Ignore",
                                        "S3 Sentry will stop reporting this finding for this bucket. "
                                        "You can undo this at any time."))
    return respond(200, page_simple(token, payload, "Stop ignoring",
                                    "This finding will appear in scan emails again."))


def handle_post(token, form):
    payload, tenant = verify(token)
    action = payload["action"]
    if action not in POST_ACTIONS:
        raise ActionError("This link can't be used to make changes.", 400)
    if _table.get_item(Key={"PK": f"TOKEN#{payload['jti']}", "SK": "USED"}).get("Item"):
        raise ActionError("This link has already been used. Each link works once.", 409)
    ctx = precheck_rollback(payload, tenant, form) if action == "ROLLBACK" else None
    spend_nonce(payload)
    if action == "ROLLBACK":
        return respond(200, do_rollback(payload, tenant, ctx))
    return respond(200, POST_ACTIONS[action](payload, tenant))


def handler(event, context):  # noqa: ARG001
    method = event.get("requestContext", {}).get("http", {}).get("method", "GET").upper()
    try:
        if method == "GET":
            params = event.get("queryStringParameters") or {}
            token = (params.get("token") or "").strip()
            if not token:
                raise ActionError("This link is missing its token.", 400)
            return handle_get(token, params)
        if method == "POST":
            raw = event.get("body") or ""
            if event.get("isBase64Encoded"):
                raw = base64.b64decode(raw).decode("utf-8")
            form = {k: v[0] for k, v in parse_qs(raw).items()}
            token = (form.get("token") or "").strip()
            if not token:
                raise ActionError("The form was missing its token.", 400)
            return handle_post(token, form)
        raise ActionError("Method not allowed.", 405)
    except ActionError as err:
        return respond(err.code, error_page(err.message, err.code))
    except Exception:                                     # noqa: BLE001
        logger.exception("Unhandled responder error")
        return respond(500, error_page("Something went wrong on our side. If a change was in progress, "
                                       "it's recorded in your action log with the saved copy of your settings.", 500))
