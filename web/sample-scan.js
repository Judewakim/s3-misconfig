/*
 * Sample scan for a FICTIONAL company. Same shape as the live API's result,
 * so the page renders both with one code path. No real account or bucket.
 */
(function () {
  "use strict";

  // The 14 checks S3 Sentry runs (lambda_handler.S3_CHECKS), with NIST CSF 1.1 mapping.
  var CHECKS = [
    ["s3_bucket_level_public_access_block", "Bucket-level Block Public Access is on", "high", ["PR.AC-3", "PR.DS-3", "DE.CM-7"]],
    ["s3_account_level_public_access_blocks", "Account-level Block Public Access is on", "high", ["PR.AC-3", "PR.DS-3", "DE.CM-7"]],
    ["s3_bucket_public_access", "Bucket is not publicly accessible", "critical", ["PR.AC-3", "PR.DS-5", "DE.CM-7"]],
    ["s3_bucket_public_list_acl", "Bucket ACL does not allow public listing", "critical", ["PR.AC-3", "PR.DS-5"]],
    ["s3_bucket_public_write_acl", "Bucket ACL does not allow public writes", "critical", ["PR.AC-3", "PR.DS-5"]],
    ["s3_bucket_policy_public_write_access", "Bucket policy does not allow public writes", "critical", ["PR.AC-3", "PR.DS-5"]],
    ["s3_bucket_acl_prohibited", "ACLs are disabled (bucket owner enforced)", "medium", ["PR.AC-3", "PR.DS-1"]],
    ["s3_bucket_default_encryption", "Default encryption is enabled", "medium", ["PR.DS-1", "PR.DS-2"]],
    ["s3_bucket_kms_encryption", "Encrypted with a KMS key", "medium", ["PR.DS-1", "PR.DS-2"]],
    ["s3_bucket_object_versioning", "Versioning is enabled", "medium", ["PR.IP-4", "RC.RP-1"]],
    ["s3_bucket_object_lock", "Object Lock is enabled", "low", ["PR.IP-4", "PR.DS-1"]],
    ["s3_bucket_no_mfa_delete", "MFA Delete is enabled", "medium", ["PR.IP-4", "PR.AC-5"]],
    ["s3_bucket_server_access_logging_enabled", "Server access logging is enabled", "medium", ["DE.CM-7", "DE.AE-3", "RS.AN-1"]],
    ["s3_bucket_secure_transport_policy", "Policy requires HTTPS (aws:SecureTransport)", "medium", ["PR.DS-2", "PR.PT-4"]]
  ];

  // Per bucket: which checks FAIL, and the scanner's explanation for each.
  var BUCKETS = [
    ["acme-customer-exports", {
      s3_bucket_public_access: "Bucket policy grants s3:GetObject to Principal \"*\". Anyone with the URL can download customer exports.",
      s3_bucket_level_public_access_block: "Block Public Access is off for this bucket.",
      s3_bucket_public_list_acl: "ACL grants READ to AllUsers, so the object list is public.",
      s3_bucket_object_versioning: "Versioning is suspended. Overwritten or deleted exports cannot be recovered.",
      s3_bucket_server_access_logging_enabled: "No access logs. You could not tell who downloaded what.",
      s3_bucket_secure_transport_policy: "Policy does not deny requests over plain HTTP."
    }],
    ["acme-prod-db-backups", {
      s3_bucket_default_encryption: "No default encryption configured. New backups are stored unencrypted.",
      s3_bucket_kms_encryption: "Not using SSE-KMS.",
      s3_bucket_object_lock: "Object Lock is off. Ransomware with write access could delete every backup.",
      s3_bucket_no_mfa_delete: "MFA Delete is off."
    }],
    ["acme-marketing-site", {
      s3_bucket_public_access: "Bucket is public for static website hosting. Confirm nothing private is stored here.",
      s3_bucket_level_public_access_block: "Block Public Access is off for this bucket.",
      s3_bucket_acl_prohibited: "Object ACLs are still in use (ObjectWriter ownership).",
      s3_bucket_kms_encryption: "Not using SSE-KMS.",
      s3_bucket_object_lock: "Object Lock is off.",
      s3_bucket_no_mfa_delete: "MFA Delete is off."
    }],
    ["acme-app-uploads", {
      s3_bucket_public_write_acl: "ACL grants WRITE to AuthenticatedUsers, so any AWS account can upload files here.",
      s3_bucket_kms_encryption: "Not using SSE-KMS.",
      s3_bucket_server_access_logging_enabled: "No access logs.",
      s3_bucket_object_lock: "Object Lock is off.",
      s3_bucket_no_mfa_delete: "MFA Delete is off."
    }],
    ["acme-cloudtrail-logs", {
      s3_bucket_no_mfa_delete: "MFA Delete is off.",
      s3_bucket_object_lock: "Object Lock is off. An attacker could erase the audit trail."
    }],
    ["acme-terraform-state", {
      s3_bucket_object_lock: "Object Lock is off."
    }]
  ];

  var findings = [];
  BUCKETS.forEach(function (b) {
    var name = b[0], fails = b[1];
    CHECKS.forEach(function (c) {
      var failed = Object.prototype.hasOwnProperty.call(fails, c[0]);
      findings.push({
        check: c[0], title: c[1], severity: c[2], nist: c[3],
        status: failed ? "FAIL" : "PASS",
        resource: name,
        detail: failed ? fails[c[0]] : "Check passed."
      });
    });
  });

  // Fix previews: the exact before/after the Responder would write (via the Safety Vault).
  var FIX_PREVIEWS = {
    s3_bucket_level_public_access_block: {
      action: "Turn on all four Block Public Access settings for this bucket.",
      before: { BlockPublicAcls: false, IgnorePublicAcls: false, BlockPublicPolicy: false, RestrictPublicBuckets: false },
      after:  { BlockPublicAcls: true,  IgnorePublicAcls: true,  BlockPublicPolicy: true,  RestrictPublicBuckets: true }
    },
    s3_bucket_default_encryption: {
      action: "Set AES-256 as the default encryption for new objects.",
      before: {},
      after: { Rules: [{ ApplyServerSideEncryptionByDefault: { SSEAlgorithm: "AES256" } }] }
    }
  };

  var sev = { critical: 0, high: 0, medium: 0, low: 0 };
  var failBuckets = {};
  findings.forEach(function (f) {
    if (f.status === "FAIL") { sev[f.severity] += 1; failBuckets[f.resource] = true; }
  });

  window.S3SENTRY_SAMPLE = {
    checks: CHECKS.map(function (c) { return c[0]; }),
    fixPreviews: FIX_PREVIEWS,
    result: {
      accountId: "acme-retail",
      sample: true,
      checksRun: CHECKS.length,
      bucketsScanned: BUCKETS.length,
      totalFindings: findings.length,
      failCount: sev.critical + sev.high + sev.medium + sev.low,
      bucketsAffected: Object.keys(failBuckets).length,
      severity: sev,
      findings: findings,
      truncated: false
    }
  };
})();
