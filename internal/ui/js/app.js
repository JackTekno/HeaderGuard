"use strict";

/* Utilities */

const $ = (sel) => document.querySelector(sel);

function esc(s) {
    return String(s == null ? "" : s).replace(/[&<>"']/g, (c) => ({
        "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;", "'": "&#39;",
    }[c]));
}

const STATUS_LABEL = {
    ok: "OK", warn: "WARNING", missing: "MISSING", info: "INFO",
    error: "FAILED", "n/a": "N/A", partial: "PARTIAL",
};

function chip(status) {
    const s = status || "na";
    return `<span class="chip chip-${s}">${STATUS_LABEL[s] || esc(s)}</span>`;
}

function gradeClass(letter) {
    if (letter === "A+" || letter === "A") return "grade-A";
    if (letter === "B" || letter === "C") return "grade-B";
    if (letter === "D" || letter === "E" || letter === "F") return "grade-D";
    return "grade-dash";
}

let currentResult = null;
let scanController = null;
let elapsedTimer = null;

/* Tabs */

document.querySelectorAll(".tab").forEach((btn) => {
    btn.addEventListener("click", () => {
        document.querySelectorAll(".tab").forEach((b) => b.classList.remove("active"));
        document.querySelectorAll(".panel").forEach((p) => p.classList.remove("active"));
        btn.classList.add("active");
        $("#panel-" + btn.dataset.tab).classList.add("active");
    });
});

/* Scanning */

async function runScan() {
    const target = $("#target").value.trim();
    if (!target) {
        $("#scanStatus").textContent = "Enter a target URL first.";
        return;
    }
    if (scanController) scanController.abort();
    scanController = new AbortController();

    const btn = $("#scanBtn");
    btn.disabled = true;
    btn.textContent = "Scanning...";
    $("#scanStatus").textContent = "Scanning " + target + " ...";
    const t0 = performance.now();
    elapsedTimer = setInterval(() => {
        $("#elapsed").textContent = ((performance.now() - t0) / 1000).toFixed(1) + " s";
    }, 100);

    try {
        const resp = await fetch("/api/scan", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({
                target,
                follow_redirects: $("#followRedirects").checked,
                timeout_seconds: 30,
            }),
            signal: scanController.signal,
        });
        if (!resp.ok) {
            const e = await resp.json().catch(() => ({}));
            throw new Error(e.error || ("HTTP " + resp.status));
        }
        const data = await resp.json();
        currentResult = data;
        render(data);
        pushHistory(data);
        updateShareURL(target);
        if (data.meta.status === "error") {
            $("#scanStatus").textContent = "Failed: " + data.meta.error;
        } else {
            $("#scanStatus").textContent =
                "Done — grade " + data.grade.letter + " (" + data.grade.score + "/100)";
        }
    } catch (err) {
        if (err.name !== "AbortError") {
            renderError(err.message);
            $("#scanStatus").textContent = "Failed: " + err.message;
        }
    } finally {
        clearInterval(elapsedTimer);
        btn.disabled = false;
        btn.textContent = "Scan";
    }
}

$("#scanBtn").addEventListener("click", runScan);
$("#target").addEventListener("keydown", (e) => { if (e.key === "Enter") runScan(); });

function renderError(msg) {
    for (const id of ["summaryContent", "headersContent", "cookiesContent", "tlsContent",
        "redirectsContent", "dnsContent", "preloadContent"]) {
        $("#" + id).innerHTML = `<div class="error-banner">Scan failed: ${esc(msg)}</div>`;
    }
    $("#clickjackingVerdict").innerHTML = "";
}

/* Main renderer */

function render(data) {
    renderSummary(data);
    renderHeaders(data);
    renderClickjacking(data);
    renderCookies(data);
    renderTLS(data);
    renderRedirects(data);
    renderDNS(data);
    renderPreload(data);
}

/* Summary */

function renderSummary(data) {
    const el = $("#summaryContent");
    if (data.meta.status === "error") {
        el.innerHTML = `<div class="error-banner">Scan failed: ${esc(data.meta.error)}</div>
            <div class="meta-grid">
                <div class="meta-item"><span class="k">Target</span>${esc(data.meta.target)}</div>
            </div>`;
        return;
    }
    const g = data.grade;
    const cats = [
        ["headers", "Security Headers"], ["cookies", "Cookies"],
        ["tls", "TLS & HTTPS"], ["dns", "DNS & HSTS Preload"],
    ];
    let bars = "";
    for (const [key, label] of cats) {
        const cs = g.breakdown[key];
        if (!cs || cs.applicable === 0) continue;
        const pct = Math.round((100 * cs.earned) / cs.applicable);
        const cls = pct >= 75 ? "fill-good" : pct >= 40 ? "fill-mid" : "fill-bad";
        bars += `<div class="cat-bar">
            <span class="label">${label}</span>
            <div class="track"><div class="fill ${cls}" style="width:${pct}%"></div></div>
            <span class="val">${cs.earned}/${cs.applicable}</span>
        </div>`;
    }
    let findings = "";
    if (data.findings && data.findings.length) {
        findings = `<h3>Key Findings</h3><ul class="findings-list">` +
            data.findings.map((f) => `<li>${esc(f)}</li>`).join("") + `</ul>`;
    }
    let caps = "";
    if (g.caps_applied && g.caps_applied.length) {
        caps = `<ul class="findings-list caps-list">` +
            g.caps_applied.map((c) => `<li>${esc(c)}</li>`).join("") + `</ul>`;
    }
    el.innerHTML = `
        <div class="grade-box">
            <div>
                <div class="grade-letter ${gradeClass(g.letter)}">${esc(g.letter || "-")}</div>
                <div class="grade-score">${g.score}/100</div>
            </div>
            <div style="flex:1;min-width:240px">${bars}${caps}</div>
        </div>
        ${findings}
        <h3>Metadata</h3>
        <div class="meta-grid">
            <div class="meta-item"><span class="k">Target</span>${esc(data.meta.target)}</div>
            <div class="meta-item"><span class="k">Final URL</span>${esc(data.meta.final_url)}</div>
            <div class="meta-item"><span class="k">Time</span>${esc(data.meta.scanned_at)}</div>
            <div class="meta-item"><span class="k">Duration</span>${data.meta.duration_ms} ms</div>
        </div>
        ${data.notes && data.notes.length ? `<h3>Notes</h3>` + data.notes.map((n) => `<div class="muted small">- ${esc(n)}</div>`).join("") : ""}`;
}

/* Security Headers */

function renderHeaders(data) {
    const el = $("#headersContent");
    if (data.meta.status === "error") {
        el.innerHTML = `<div class="error-banner">Could not analyze: ${esc(data.meta.error)}</div>`;
        return;
    }
    const scored = data.headers.items.filter((i) => i.weight > 0);
    const info = data.headers.items.filter((i) => i.weight === 0);
    const s = data.headers.summary;
    let cards = scored.map((it) => `
        <div class="card">
            <div class="card-head">
                <span class="name">${esc(it.name)}</span>
                <span style="display:flex;gap:6px;align-items:center">
                    <span class="severity">${esc(it.severity)}</span>
                    ${chip(it.status)}
                    <span class="muted small">${it.earned}/${it.weight}</span>
                </span>
            </div>
            ${it.raw_values && it.raw_values.length ? `<div class="raw">${it.raw_values.map(esc).join(" | ")}</div>` : ""}
            <div class="details">${esc(it.details)}</div>
            ${it.fix ? `<div class="fix">Fix: ${esc(it.fix)}</div>` : ""}
        </div>`).join("");
    let infoCards = info.map((it) => `
        <div class="card">
            <div class="card-head">
                <span class="name">${esc(it.name)}</span>
                ${chip(it.status)}
            </div>
            ${it.raw_values && it.raw_values.length ? `<div class="raw">${it.raw_values.map(esc).join(" | ")}</div>` : ""}
            <div class="details">${esc(it.details)}</div>
        </div>`).join("");
    el.innerHTML = `
        <div class="muted small" style="margin-bottom:10px">
            Summary: ${s.ok} ok, ${s.warn} warnings, ${s.missing} missing, ${s.info} informational
        </div>
        <div class="grid">${cards}</div>
        <details>
            <summary class="muted" style="cursor:pointer">Informational (does not affect the score) — ${info.length}</summary>
            <div class="grid" style="margin-top:10px">${infoCards}</div>
        </details>`;
}

/* Clickjacking */

const VERDICT_LABEL = { protected: "Protected", warning: "At Risk", vulnerable: "Vulnerable" };

function renderClickjacking(data) {
    const el = $("#clickjackingVerdict");
    if (data.meta.status === "error") {
        el.innerHTML = `<div class="error-banner">No verdict available: ${esc(data.meta.error)}</div>`;
        return;
    }
    const cj = data.clickjacking;
    const xfo = cj.xfo.present ? cj.xfo.values.join(" | ") : "not set";
    const fa = cj.csp_frame_ancestors.present
        ? "frame-ancestors " + cj.csp_frame_ancestors.values.join(" ")
        : "not set";
    el.innerHTML = `
        <div class="verdict-banner verdict-${esc(cj.verdict)}">
            Verdict: ${esc(VERDICT_LABEL[cj.verdict] || cj.verdict)}
        </div>
        <div class="card">
            <div class="card-head"><span class="name">Explanation</span></div>
            <div class="details">${esc(cj.explanation)}</div>
        </div>
        <div class="card">
            <div class="card-head"><span class="name">X-Frame-Options</span></div>
            <div class="raw">${esc(xfo)}</div>
        </div>
        <div class="card">
            <div class="card-head"><span class="name">CSP frame-ancestors</span></div>
            <div class="raw">${esc(fa)}</div>
        </div>`;
    // Prefill the iframe simulation with the final URL of the scan. The
    // final URL always carries a scheme (raw input like "siberin.id" would
    // otherwise load as a relative path on this server and 404).
    $("#cjFrameUrl").value = data.meta.final_url || data.meta.target;
}

/* Iframe simulation (ported from the original tool) */

let cjTransparent = false;
let cjOverlayVisible = true;

window.cjLoad = function () {
    let url = $("#cjFrameUrl").value.trim();
    if (!url) {
        $("#cjStatus").textContent = "Enter a URL first.";
        return;
    }
    // Without a scheme the browser treats the value as a relative path on
    // this server (404). Default to https like the scanner does.
    if (!/^https?:\/\//i.test(url)) {
        url = "https://" + url;
        $("#cjFrameUrl").value = url;
    }
    $("#cjFrame").src = url;
    $("#cjStatus").textContent = "Loading " + url + " ...";
};

document.getElementById("cjFrame").addEventListener("load", () => {
    const src = document.getElementById("cjFrame").src;
    if (src === "about:blank") return;
    $("#cjStatus").textContent =
        "The site loaded inside the iframe, so it visually appears frameable. Note that " +
        "some browsers load the page but block interaction, so the header verdict above " +
        "remains authoritative.";
});

window.cjToggleTransparency = function () {
    cjTransparent = !cjTransparent;
    $("#cjFrame").classList.toggle("transparent", cjTransparent);
};

window.cjToggleOverlay = function () {
    cjOverlayVisible = !cjOverlayVisible;
    $("#cjOverlayBtn").classList.toggle("hidden", !cjOverlayVisible);
};

window.cjOverlayClick = function () {
    alert("Overlay clicked! In a real attack, this could be a malicious button placed over the real one.");
};

/* Cookies */

function renderCookies(data) {
    const el = $("#cookiesContent");
    if (data.meta.status === "error") {
        el.innerHTML = `<div class="error-banner">Could not analyze: ${esc(data.meta.error)}</div>`;
        return;
    }
    let fatal = "";
    if (data.cookies.fatal && data.cookies.fatal.length) {
        fatal = `<div class="fatal-banner">FATAL: ${data.cookies.fatal.map(esc).join("<br>")}</div>`;
    }
    if (!data.cookies.applicable || !data.cookies.items.length) {
        el.innerHTML = fatal + `<div class="card">No cookies were set anywhere in the response chain.</div>`;
        return;
    }
    const rows = data.cookies.items.map((c) => `
        <tr>
            <td><strong>${esc(c.name)}</strong></td>
            <td class="small mono">${esc(c.domain || "-")}</td>
            <td>${c.secure ? '<span class="flag-yes">Yes</span>' : '<span class="flag-no">No</span>'}</td>
            <td>${c.httponly ? '<span class="flag-yes">Yes</span>' : '<span class="flag-no">No</span>'}</td>
            <td>${esc(c.samesite || "-")}</td>
            <td class="small mono">${esc(c.path || "-")}</td>
            <td>${chip(c.status)}</td>
        </tr>
        ${c.issues && c.issues.length ? `<tr><td colspan="7"><ul class="issues">` +
            c.issues.map((i) => `<li>${esc(i)}</li>`).join("") + `</ul></td></tr>` : ""}`).join("");
    el.innerHTML = fatal + `
        <table class="cookie-table">
            <thead><tr>
                <th>Name</th><th>Domain</th><th>Secure</th><th>HttpOnly</th>
                <th>SameSite</th><th>Path</th><th>Status</th>
            </tr></thead>
            <tbody>${rows}</tbody>
        </table>`;
}

/* TLS */

function renderTLS(data) {
    const el = $("#tlsContent");
    if (data.meta.status === "error") {
        el.innerHTML = `<div class="error-banner">Could not analyze: ${esc(data.meta.error)}</div>`;
        return;
    }
    if (data.tls.status !== "ok") {
        el.innerHTML = `<div class="card">TLS module failed: ${esc(data.tls.error || "TLS is not available")}</div>`;
        return;
    }
    const proto = ["TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0"].map((v) => {
        const on = data.tls.protocols && data.tls.protocols[v];
        return `<div class="proto-cell ${on ? "proto-on" : "proto-off"}">
            <div class="v">${v}</div><div class="s">${on ? "Supported" : "Not supported"}</div>
        </div>`;
    }).join("");
    let cert = "";
    if (data.tls.cert) {
        const c = data.tls.cert;
        cert = `<h3>Certificate</h3><div class="cert-grid">
            <div class="meta-item"><span class="k">Subject</span>${esc(c.subject)}</div>
            <div class="meta-item"><span class="k">Issuer</span>${esc(c.issuer)}</div>
            <div class="meta-item"><span class="k">Valid from</span>${esc(c.not_before)}</div>
            <div class="meta-item"><span class="k">Valid until</span>${esc(c.not_after)}</div>
            <div class="meta-item"><span class="k">Days left</span>${c.days_remaining}</div>
            <div class="meta-item"><span class="k">Signature</span>${esc(c.signature_algorithm)}</div>
            <div class="meta-item"><span class="k">Chain valid</span>${c.chain_valid ? "Yes" : "No"}</div>
            <div class="meta-item"><span class="k">Hostname match</span>${c.hostname_match ? "Yes" : "No"}</div>
            ${c.expired ? `<div class="meta-item"><span class="k">Status</span><span class="flag-no">EXPIRED</span></div>` : ""}
            ${c.not_yet_valid ? `<div class="meta-item"><span class="k">Status</span><span class="flag-no">NOT YET VALID</span></div>` : ""}
            ${c.expiring_soon ? `<div class="meta-item"><span class="k">Status</span><span class="flag-no">EXPIRING SOON</span></div>` : ""}
        </div>
        ${c.san && c.san.length ? `<div class="muted small">SAN: ${c.san.map(esc).join(", ")}</div>` : ""}`;
    }
    el.innerHTML = `<h3>Supported Protocols</h3><div class="proto-matrix">${proto}</div>${cert}`;
}

/* Redirects */

function renderRedirects(data) {
    const el = $("#redirectsContent");
    if (data.meta.status === "error") {
        el.innerHTML = `<div class="error-banner">Could not analyze: ${esc(data.meta.error)}</div>`;
        return;
    }
    const r = data.redirects;
    if (!r.hops || r.hops.length === 0) {
        el.innerHTML = `<div class="card">No redirects — the server responded directly.</div>`;
        return;
    }
    const hops = r.hops.map((h) => `
        <div class="hop ${h.scheme_upgrade ? "hop-upgrade" : ""}">
            <span class="idx">${h.index}</span>
            <span class="code">${h.status_code}</span>
            <span class="url">${esc(h.url)} -> ${esc(h.location || "-")}</span>
            ${h.scheme_upgrade ? '<span class="badge-upgrade">http->https upgrade</span>' : ""}
        </div>`).join("");
    let notes = "";
    if (r.capped) notes += `<div class="card">The redirect chain hit the 10-hop limit — possible loop.</div>`;
    if (r.scheme_downgrade) notes += `<div class="card">Detected an https->http downgrade in the redirect chain.</div>`;
    if (r.http_to_https && !r.scheme_downgrade) {
        notes += `<div class="card">Good: an http->https redirect is in place.</div>`;
    }
    el.innerHTML = `<div class="muted small" style="margin-bottom:8px">${r.hop_count} hops</div>${hops}${notes}`;
}

/* DNS */

const DNS_NAMES = { dnssec: "DNSSEC", caa: "CAA", spf: "SPF", dmarc: "DMARC" };

function renderDNS(data) {
    const el = $("#dnsContent");
    if (data.meta.status === "error") {
        el.innerHTML = `<div class="error-banner">Could not analyze: ${esc(data.meta.error)}</div>`;
        return;
    }
    if (data.dns.status === "n/a") {
        el.innerHTML = `<div class="card">N/A — the target is an IP address, so DNS checks were skipped.</div>`;
        return;
    }
    if (data.dns.status === "error") {
        el.innerHTML = `<div class="card">Could not reach any DNS-over-HTTPS provider (Google & Cloudflare).</div>`;
        return;
    }
    let cards = "";
    for (const [key, label] of Object.entries(DNS_NAMES)) {
        const ch = data.dns.checks[key];
        if (!ch) continue;
        cards += `<div class="card">
            <div class="card-head">
                <span class="name">${label}</span>
                <span style="display:flex;gap:6px;align-items:center">
                    ${ch.ad ? '<span class="chip chip-ok">AD</span>' : ""}
                    ${chip(ch.status)}
                </span>
            </div>
            ${ch.records && ch.records.length ? ch.records.map((r) => `<div class="dns-record">${esc(r)}</div>`).join("") : ""}
            <div class="details">${esc(ch.details)}</div>
        </div>`;
    }
    el.innerHTML = `
        <div class="muted small" style="margin-bottom:10px">
            Provider: ${esc(data.dns.provider || "?")}${data.dns.fallback_used ? " (used Cloudflare fallback)" : ""}
        </div>${cards}`;
}

/* HSTS Preload */

function renderPreload(data) {
    const el = $("#preloadContent");
    if (data.meta.status === "error") {
        el.innerHTML = `<div class="error-banner">Could not analyze: ${esc(data.meta.error)}</div>`;
        return;
    }
    const p = data.hsts_preload;
    el.innerHTML = `<div class="card">
        <div class="card-head">
            <span class="name">Domain status on hstspreload.org</span>
            ${chip(p.status === "n/a" ? "na" : p.status)}
        </div>
        ${p.domain_status ? `<div class="raw">${esc(p.domain_status)}${p.preloaded ? " — REGISTERED" : ""}</div>` : ""}
        <div class="details">${esc(p.note)}</div>
    </div>`;
}

/* Report & history */

function hostOf(target) {
    try {
        const u = new URL(target.startsWith("http") ? target : "https://" + target);
        return u.hostname.replace(/[^a-z0-9.-]/gi, "_");
    } catch { return "target"; }
}

window.downloadJSON = function () {
    if (!currentResult) return;
    const blob = new Blob([JSON.stringify(currentResult, null, 2)], { type: "application/json" });
    triggerDownload(blob, "headerguard-" + hostOf(currentResult.meta.target) + ".json");
};

window.downloadMarkdown = function () {
    if (!currentResult) return;
    const blob = new Blob([buildMarkdown(currentResult)], { type: "text/markdown" });
    triggerDownload(blob, "headerguard-" + hostOf(currentResult.meta.target) + ".md");
};

window.copyReport = async function () {
    if (!currentResult) return;
    try {
        await navigator.clipboard.writeText(buildMarkdown(currentResult));
        $("#scanStatus").textContent = "Report copied to the clipboard.";
    } catch {
        $("#scanStatus").textContent = "Clipboard is not available in this browser.";
    }
};

window.copyShareURL = async function () {
    if (!currentResult) return;
    try {
        await navigator.clipboard.writeText(location.origin + "/?target=" +
            encodeURIComponent(currentResult.meta.target));
        $("#scanStatus").textContent = "Share link copied.";
    } catch {
        $("#scanStatus").textContent = "Clipboard is not available in this browser.";
    }
};

function triggerDownload(blob, name) {
    const a = document.createElement("a");
    a.href = URL.createObjectURL(blob);
    a.download = name;
    a.click();
    URL.revokeObjectURL(a.href);
}

function updateShareURL(target) {
    history.replaceState(null, "", "/?target=" + encodeURIComponent(target));
}

/* History (localStorage) */

const HISTORY_KEY = "headerguard.history";
const HISTORY_MAX = 20;

function loadHistory() {
    try {
        return JSON.parse(localStorage.getItem(HISTORY_KEY) || "[]");
    } catch { return []; }
}

function pushHistory(data) {
    if (data.meta.status === "error") return;
    let h = loadHistory();
    h.unshift({
        target: data.meta.target,
        letter: data.grade.letter,
        score: data.grade.score,
        time: new Date().toISOString(),
    });
    if (h.length > HISTORY_MAX) h = h.slice(0, HISTORY_MAX);
    localStorage.setItem(HISTORY_KEY, JSON.stringify(h));
    renderHistory();
}

function renderHistory() {
    const el = $("#historyList");
    const h = loadHistory();
    if (!h.length) {
        el.innerHTML = `<div class="muted small">No history yet.</div>`;
        return;
    }
    el.innerHTML = h.map((item, i) => `
        <div class="history-item" data-idx="${i}">
            <span class="grade-letter ${gradeClass(item.letter)}" style="font-size:22px;min-width:44px">${esc(item.letter)}</span>
            <span class="t">${esc(item.target)}</span>
            <span class="time">${new Date(item.time).toLocaleString("en-GB")}</span>
            <span class="muted small">${item.score}/100</span>
        </div>`).join("");
    el.querySelectorAll(".history-item").forEach((item) => {
        item.addEventListener("click", () => {
            const entry = loadHistory()[Number(item.dataset.idx)];
            if (entry) {
                $("#target").value = entry.target;
                runScan();
            }
        });
    });
}

window.clearHistory = function () {
    localStorage.removeItem(HISTORY_KEY);
    renderHistory();
};

/* Markdown report */

function buildMarkdown(data) {
    const L = [];
    L.push("# HeaderGuard — Web Security Header Analysis Report");
    L.push("");
    L.push("**Target:** " + data.meta.target + "  ");
    L.push("**Final URL:** " + data.meta.final_url + "  ");
    L.push("**Time:** " + data.meta.scanned_at + "  ");
    L.push("**Duration:** " + data.meta.duration_ms + " ms");
    L.push("");
    if (data.meta.status === "error") {
        L.push("## FAILED");
        L.push(data.meta.error);
        return L.join("\n");
    }
    L.push("## Summary");
    L.push("");
    L.push("**Grade: " + data.grade.letter + "** — score " + data.grade.score + "/100");
    L.push("");
    const cats = [["headers", "Security Headers"], ["cookies", "Cookies"], ["tls", "TLS & HTTPS"], ["dns", "DNS & HSTS Preload"]];
    for (const [key, label] of cats) {
        const cs = data.grade.breakdown[key];
        if (cs && cs.applicable > 0) L.push("- " + label + ": " + cs.earned + "/" + cs.applicable);
    }
    if (data.findings && data.findings.length) {
        L.push("");
        L.push("### Key Findings");
        for (const f of data.findings) L.push("- " + f);
    }
    L.push("");
    L.push("## Clickjacking");
    L.push("Verdict: **" + (VERDICT_LABEL[data.clickjacking.verdict] || data.clickjacking.verdict) + "** — " + data.clickjacking.explanation);
    L.push("");
    L.push("## Security Headers");
    for (const it of data.headers.items) {
        const lbl = STATUS_LABEL[it.status] || it.status;
        L.push("### " + it.name + " [" + lbl + "] " + it.earned + "/" + it.weight);
        if (it.raw_values && it.raw_values.length) L.push("```\n" + it.raw_values.join(" | ") + "\n```");
        L.push(it.details);
        if (it.fix) L.push("_Fix: " + it.fix + "_");
        L.push("");
    }
    L.push("## Cookies");
    if (!data.cookies.applicable || !data.cookies.items.length) {
        L.push("No cookies were set.");
    } else {
        for (const c of data.cookies.items) {
            L.push("- **" + c.name + "**: Secure=" + (c.secure ? "yes" : "no") +
                ", HttpOnly=" + (c.httponly ? "yes" : "no") +
                ", SameSite=" + (c.samesite || "-"));
            for (const i of c.issues) L.push("  - " + i);
        }
        for (const f of data.cookies.fatal) L.push("- **FATAL:** " + f);
    }
    L.push("");
    L.push("## TLS");
    if (data.tls.status !== "ok") {
        L.push("TLS is not available: " + (data.tls.error || ""));
    } else {
        const supported = ["TLSv1.3", "TLSv1.2", "TLSv1.1", "TLSv1.0"]
            .filter((v) => data.tls.protocols && data.tls.protocols[v]);
        L.push("Supported protocols: " + (supported.join(", ") || "-"));
        if (data.tls.cert) {
            const c = data.tls.cert;
            L.push("- Subject: " + c.subject);
            L.push("- Issuer: " + c.issuer);
            L.push("- Valid: " + c.not_before + " to " + c.not_after + " (" + c.days_remaining + " days left)");
            L.push("- Chain valid: " + (c.chain_valid ? "yes" : "no") + ", hostname match: " + (c.hostname_match ? "yes" : "no"));
        }
    }
    L.push("");
    L.push("## Redirects & HTTPS");
    if (!data.redirects.hops || !data.redirects.hops.length) {
        L.push("No redirects.");
    } else {
        for (const h of data.redirects.hops) {
            L.push(h.index + ". " + h.url + " -> " + h.status_code + " " + (h.location || ""));
        }
    }
    L.push("");
    L.push("## DNS");
    if (data.dns.status === "n/a") {
        L.push("N/A — the target is an IP address.");
    } else if (data.dns.status === "error") {
        L.push("Could not reach any DoH provider.");
    } else {
        for (const [key, label] of Object.entries(DNS_NAMES)) {
            const ch = data.dns.checks[key];
            if (!ch) continue;
            L.push("- **" + label + "** [" + (STATUS_LABEL[ch.status] || ch.status) + "]: " + ch.details);
            for (const r of ch.records || []) L.push("  ```\n  " + r + "\n  ```");
        }
    }
    L.push("");
    L.push("## HSTS Preload");
    L.push("Status: " + (data.hsts_preload.domain_status || "n/a") + " — " + data.hsts_preload.note);
    L.push("");
    L.push("---");
    L.push("_Generated by HeaderGuard v" + data.meta.version + " — authorized testing only._");
    return L.join("\n");
}

/* Initialization */

renderHistory();
const params = new URLSearchParams(location.search);
const initialTarget = params.get("target");
if (initialTarget) {
    $("#target").value = initialTarget;
    runScan();
}
