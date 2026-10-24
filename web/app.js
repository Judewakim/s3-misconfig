/*
 * S3 Sentry demo page. Plain JS, no dependencies.
 * Every value from the API is written with textContent, never innerHTML.
 */
(function () {
  "use strict";

  var SAMPLE = window.S3SENTRY_SAMPLE;
  var API = ((window.S3SENTRY_CONFIG || {}).apiUrl || "").replace(/\/+$/, "");
  var reduceMotion = window.matchMedia("(prefers-reduced-motion: reduce)").matches;
  var SEV_RANK = { critical: 0, high: 1, medium: 2, low: 3 };
  var SEV_LABEL = { critical: "Critical", high: "High", medium: "Medium", low: "Low" };

  function $(id) { return document.getElementById(id); }
  function el(tag, cls, text) {
    var n = document.createElement(tag);
    if (cls) n.className = cls;
    if (text != null) n.textContent = text;
    return n;
  }

  /* ---------------------------------------------------------- bucket wall */

  function groupByBucket(findings, checks) {
    var map = {}, order = [];
    findings.forEach(function (f) {
      if (!map[f.resource]) { map[f.resource] = {}; order.push(f.resource); }
      map[f.resource][f.check] = f;
    });
    return order.map(function (name) {
      return { name: name, cells: checks.map(function (c) { return map[name][c] || null; }) };
    });
  }

  function worst(cells) {
    var w = null;
    cells.forEach(function (f) {
      if (f && f.status === "FAIL" && (w === null || SEV_RANK[f.severity] < SEV_RANK[w])) w = f.severity;
    });
    return w;
  }

  function buildWall(result, checks) {
    var wall = $("wall");
    wall.textContent = "";
    // Account-level checks report the 12-digit account as their resource; the
    // wall is per bucket, so leave those rows to the findings list.
    var buckets = groupByBucket(result.findings.filter(function (f) {
      return f.resource && !/^\d{12}$/.test(f.resource);
    }), checks);
    var MAX = 24;
    buckets.slice(0, MAX).forEach(function (b) {
      var li = el("li", "bucket");
      li.appendChild(el("span", "bucket-name", b.name));
      var pips = el("span", "pips");
      pips.setAttribute("aria-hidden", "true");
      b.cells.forEach(function (f) {
        var p = el("i", "pip");
        p.dataset.status = f ? f.status : "NA";
        p.dataset.sev = f ? f.severity : "";
        p.title = f ? (f.title + ": " + (f.status === "FAIL" ? "failed" : "passed")) : "";
        pips.appendChild(p);
      });
      li.appendChild(pips);
      var verdict = el("span", "verdict");
      li.appendChild(verdict);
      li._worst = worst(b.cells);
      li._fails = b.cells.filter(function (f) { return f && f.status === "FAIL"; }).length;
      wall.appendChild(li);
    });
    if (buckets.length > MAX) {
      wall.appendChild(el("li", "more", "+ " + (buckets.length - MAX) + " more buckets in the list below"));
    }
    return buckets;
  }

  function settle(li) {
    var v = li.querySelector(".verdict");
    if (li._fails === 0) { v.textContent = "Clean"; li.classList.add("clean"); }
    else { v.textContent = li._fails + " issue" + (li._fails > 1 ? "s" : ""); li.dataset.worst = li._worst; }
  }

  function animateWall(done) {
    var items = Array.prototype.slice.call(document.querySelectorAll("#wall .bucket"));
    if (!items.length) { progress.textContent = "No buckets found"; done(); return; }
    var progress = $("wall-progress");
    var total = items.reduce(function (n, li) { return n + li.querySelectorAll(".pip").length; }, 0);
    if (reduceMotion) {
      items.forEach(function (li) {
        li.querySelectorAll(".pip").forEach(function (p) { p.classList.add("on"); });
        settle(li);
      });
      progress.textContent = "Scan complete";
      done();
      return;
    }
    var i = 0, all = [];
    items.forEach(function (li) {
      li.querySelectorAll(".pip").forEach(function (p) { all.push([li, p]); });
    });
    progress.textContent = "Scanning";
    var timer = setInterval(function () {
      for (var k = 0; k < 2 && i < all.length; k++, i++) {
        all[i][1].classList.add("on");
        var li = all[i][0];
        if (i === all.length - 1 || all[i + 1][0] !== li) settle(li);
      }
      progress.textContent = "Checked " + i + " of " + total;
      if (i >= all.length) { clearInterval(timer); progress.textContent = "Scan complete"; done(); }
    }, 28);
  }

  /* ------------------------------------------------------------- findings */

  var current = null;
  var filter = "FAIL";
  var expanded = false;
  $("show-more").addEventListener("click", function () {
    expanded = true;
    renderFindings();
    var items = document.querySelectorAll("#findings .finding");
    if (items[8]) items[8].querySelector("h3").setAttribute("tabindex", "-1"), items[8].querySelector("h3").focus();
  });

  function summaryText(r) {
    if (r.failCount === 0) {
      return "No failed checks across " + r.bucketsScanned + " buckets. Every bucket passed all " + r.checksRun + " checks.";
    }
    var parts = ["critical", "high", "medium", "low"].filter(function (s) { return r.severity[s]; })
      .map(function (s) { return r.severity[s] + " " + s; });
    var acct = r.accountFailCount || 0;
    var where = r.bucketsAffected + " of " + r.bucketsScanned + " buckets" +
      (acct ? " and " + acct + " account-wide setting" + (acct > 1 ? "s" : "") : "");
    return r.failCount + " failed checks across " + where + ": " + parts.join(", ") + ".";
  }

  function renderFindings() {
    var list = $("findings");
    list.textContent = "";
    var rows = current.findings.filter(function (f) { return filter === "ALL" || f.status === "FAIL"; });
    rows.sort(function (a, b) {
      return (a.status === "FAIL" ? 0 : 1) - (b.status === "FAIL" ? 0 : 1) ||
        (SEV_RANK[a.severity] - SEV_RANK[b.severity]) || a.resource.localeCompare(b.resource);
    });
    if (!rows.length) {
      list.appendChild(el("li", "empty", "Nothing failed. Switch to All checks to see what passed."));
      return;
    }
    var LIMIT = 8;
    var shown = expanded ? rows : rows.slice(0, LIMIT);
    shown.forEach(function (f) { list.appendChild(findingRow(f)); });
    var more = $("show-more");
    more.hidden = expanded || rows.length <= LIMIT;
    more.textContent = "Show all " + rows.length;
  }

  function findingRow(f) {
    var li = el("li", "finding");
    li.dataset.status = f.status;
    if (f.status === "FAIL") li.dataset.sev = f.severity;

    var tag = el("span", "tag", f.status === "FAIL" ? SEV_LABEL[f.severity] || f.severity : "Passed");
    var body = el("div", "finding-body");
    var h = el("h3", null, f.title);
    var res = el("code", "res", f.resource);
    var detail = el("p", "detail", f.detail);
    body.appendChild(h);
    body.appendChild(res);
    body.appendChild(detail);
    if (f.nist && f.nist.length) body.appendChild(el("p", "nist", "NIST CSF " + f.nist.join(", ")));

    if (f.status === "FAIL") {
      var preview = SAMPLE.fixPreviews[f.check];
      var actions = el("div", "finding-actions");
      if (!current.sample && preview) {
        actions.appendChild(el("p", "fine",
          "Customers can fix this with one click from their scan email. The live demo is read-only, so it can't change anything in your account."));
        body.appendChild(actions);
      } else if (current.sample && preview) {
        var btn = el("button", "btn ghost small", "Preview the fix");
        btn.type = "button";
        btn.setAttribute("aria-expanded", "false");
        var panel = fixPanel(preview, f.resource);
        panel.hidden = true;
        btn.addEventListener("click", function () {
          var open = panel.hidden;
          panel.hidden = !open;
          btn.setAttribute("aria-expanded", String(open));
        });
        actions.appendChild(btn);
        body.appendChild(actions);
        body.appendChild(panel);
      }
    }
    li.appendChild(tag);
    li.appendChild(body);
    return li;
  }

  function fixPanel(p, bucket) {
    var wrap = el("div", "fix");
    wrap.appendChild(el("p", null, p.action));
    var grid = el("div", "diff");
    var a = el("div", "side"), b = el("div", "side");
    a.appendChild(el("span", "side-label", "Saved to the vault before the fix"));
    a.appendChild(el("pre", null, JSON.stringify(p.before, null, 2)));
    b.appendChild(el("span", "side-label", "Applied to " + bucket));
    b.appendChild(el("pre", null, JSON.stringify(p.after, null, 2)));
    grid.appendChild(a);
    grid.appendChild(b);
    wrap.appendChild(grid);
    wrap.appendChild(el("p", "fine",
      "In the full version this runs only after the bucket owner confirms a signed, single-use link from the scan email. The saved copy is kept so the change can be reversed."));
    return wrap;
  }

  function showResults(result) {
    current = result;
    expanded = false;
    $("results").hidden = false;
    $("results-summary").textContent = summaryText(result);
    $("results-note").textContent = result.sample
      ? "Sample data for a fictional company."
      : "Live results for account " + result.accountId + ". Deleted automatically after 24 hours." +
        (result.truncated ? " Showing the first 500 results." : "");
    renderFindings();
  }

  Array.prototype.forEach.call(document.querySelectorAll(".chip"), function (chip) {
    chip.addEventListener("click", function () {
      filter = chip.dataset.filter;
      expanded = false;
      Array.prototype.forEach.call(document.querySelectorAll(".chip"), function (c) {
        c.setAttribute("aria-pressed", String(c === chip));
      });
      if (current) renderFindings();
    });
  });

  function runScan(result, label) {
    $("wall-account").textContent = label;
    buildWall(result, SAMPLE.checks);
    $("results").hidden = true;
    animateWall(function () { showResults(result); });
  }

  var runBtn = $("run-sample");
  runBtn.addEventListener("click", function () {
    runBtn.disabled = true;
    runScan(SAMPLE.result, "acme-retail, " + SAMPLE.result.bucketsScanned + " buckets (sample)");
    setTimeout(function () { runBtn.disabled = false; runBtn.textContent = "Run it again"; }, reduceMotion ? 0 : 2600);
  });

  // Show the wall in its idle state on load.
  buildWall(SAMPLE.result, SAMPLE.checks);

  /* ------------------------------------------------------------ live demo */

  var SESSION_KEY = "s3sentry.demo.session";

  function store(k, v) { try { v == null ? sessionStorage.removeItem(k) : sessionStorage.setItem(k, v); } catch (e) {} }
  function load(k) { try { return sessionStorage.getItem(k); } catch (e) { return null; } }

  function api(path, body) {
    return fetch(API + path, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body || {}),
      credentials: "omit",
      referrerPolicy: "no-referrer"
    }).then(function (r) {
      return r.json().catch(function () { return {}; }).then(function (j) { j._status = r.status; return j; });
    });
  }

  function setStep(n) {
    Array.prototype.forEach.call(document.querySelectorAll(".step"), function (s) {
      var k = Number(s.dataset.step);
      s.setAttribute("aria-disabled", String(k > n));
      s.classList.toggle("done", k < n);
    });
    var launch = $("launch-link");
    launch.setAttribute("aria-disabled", String(n < 2));
    $("start-session").disabled = n > 1;
    $("account-id").disabled = n !== 3;
    $("scan-btn").disabled = n !== 3;
  }

  function say(id, text, tone) {
    var s = $(id);
    s.textContent = text || "";
    s.dataset.tone = tone || "";
  }

  if (!API) {
    $("live-off").hidden = false;
    $("steps").hidden = true;
    return;
  }

  setStep(1);
  var session = null;
  try { session = JSON.parse(load(SESSION_KEY) || "null"); } catch (e) { session = null; }
  if (session && session.expiresAt * 1000 > Date.now()) {
    $("launch-link").href = session.launchUrl;
    say("s1-status", "Your demo link is ready.", "ok");
    refreshLaunch();
    setStep(3);
    poll(true);
  } else {
    store(SESSION_KEY, null);
    session = null;
  }

  $("start-session").addEventListener("click", function () {
    var btn = this;
    btn.disabled = true;
    say("s1-status", "Creating your link…");
    api("/sessions").then(function (j) {
      btn.disabled = false;
      if (j._status !== 201) { say("s1-status", j.message || "Couldn't create a session. Try again.", "err"); return; }
      session = { id: j.sessionId, launchUrl: j.launchUrl, expiresAt: j.expiresAt };
      scheduleRefresh();
      store(SESSION_KEY, JSON.stringify(session));
      $("launch-link").href = j.launchUrl;
      say("s1-status", "Your demo link is ready. It expires in 24 hours.", "ok");
      setStep(3);
      $("launch-link").focus();
    }).catch(function () {
      btn.disabled = false;
      say("s1-status", "Couldn't reach the scanner. Check your connection and try again.", "err");
    });
  });

  // The CloudFormation link carries a template URL that is signed for one
  // hour (the template bucket is private). Keep the link fresh while the
  // visitor still needs it.
  var refreshTimer = null;
  function scheduleRefresh() {
    clearInterval(refreshTimer);
    refreshTimer = setInterval(refreshLaunch, 45 * 60 * 1000);
  }
  function refreshLaunch() {
    if (!session) return;
    api("/sessions/launch", { sessionId: session.id }).then(function (j) {
      if (j._status !== 200 || !j.launchUrl) { clearInterval(refreshTimer); return; }
      session.launchUrl = j.launchUrl;
      store(SESSION_KEY, JSON.stringify(session));
      $("launch-link").href = j.launchUrl;
      scheduleRefresh();
    }).catch(function () {});
  }

  $("launch-link").addEventListener("click", function (e) {
    if (this.getAttribute("aria-disabled") === "true") e.preventDefault();
  });

  $("account-id").addEventListener("input", function () {
    var d = this.value.replace(/\D/g, "").slice(0, 12);
    this.value = d.replace(/(\d{4})(?=\d)/g, "$1 ");
  });

  $("scan-form").addEventListener("submit", function (e) {
    e.preventDefault();
    var acct = $("account-id").value.replace(/\D/g, "");
    if (acct.length !== 12) { say("s3-status", "Account IDs are 12 digits. You'll find yours in the stack's Outputs tab.", "err"); return; }
    $("scan-btn").disabled = true;
    say("s3-status", "Checking that the role is deployed…");
    api("/sessions/scan", { sessionId: session.id, accountId: acct }).then(function (j) {
      if (j._status === 409) {
        $("scan-btn").disabled = false;
        say("s3-status", j.message, "err");
        return;
      }
      if (j._status >= 400) {
        $("scan-btn").disabled = false;
        say("s3-status", j.message || "Couldn't start the scan. Try again.", "err");
        return;
      }
      say("s3-status", "Scanning. This usually takes one to three minutes.");
      poll(false);
    }).catch(function () {
      $("scan-btn").disabled = false;
      say("s3-status", "Couldn't reach the scanner. Check your connection and try again.", "err");
    });
  });

  var polling = false;
  function poll(quiet) {
    if (polling || !session) return;
    polling = true;
    var started = Date.now();
    (function tick() {
      api("/sessions/status", { sessionId: session.id }).then(function (j) {
        if (j._status === 404) {
          polling = false; store(SESSION_KEY, null); session = null; setStep(1);
          say("s1-status", "That session expired. Create a new link.", "err");
          return;
        }
        if (j.status === "PENDING") { polling = false; return; }
        if (j.status === "SCANNING") {
          $("scan-btn").disabled = true;
          if (!quiet) say("s3-status", "Scanning. This usually takes one to three minutes.");
          if (Date.now() - started > 12 * 60 * 1000) {
            polling = false;
            say("s3-status", "The scan is taking longer than expected. Reload the page in a few minutes to check again.", "err");
            return;
          }
          setTimeout(tick, 5000);
          return;
        }
        polling = false;
        if (j.status === "DONE") {
          setStep(4);
          say("s3-status", "Scan complete. Your results are at the top of the page.", "ok");
          runScan(j.result, "Account " + j.result.accountId + ", " + j.result.bucketsScanned + " buckets");
          $("results").scrollIntoView({ behavior: reduceMotion ? "auto" : "smooth" });
        } else if (j.status === "ERROR") {
          say("s3-status", j.error, "err");
        }
      }).catch(function () { setTimeout(tick, 8000); });
    })();
  }
})();
