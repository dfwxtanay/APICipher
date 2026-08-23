"""Render scored findings into a self-contained HTML dashboard.

Deliberately dependency-free: the output is one HTML file with inline CSS and JS,
so it opens offline in any browser and commits to the repo without needing a
server. Styling favours density and typography over decoration - this is meant to
read like a security report, not a marketing page.
"""

import html
import json
import os
from string import Template

FINDINGS_PATH = "reports/findings.json"
OUTPUT_PATH = "dashboard/index.html"

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW")

CSS = """
:root {
  --paper:#fbfbfa; --ink:#16161a; --muted:#6f6f78; --faint:#9a9aa3;
  --rule:#e2e2df; --rule-strong:#c9c9c4; --panel:#f4f4f1; --code:#f0f0ec;
  --crit:#a81f24; --high:#b35a17; --med:#8a6d0b; --low:#2f6f4a;
}
@media (prefers-color-scheme: dark) {
  :root {
    --paper:#111114; --ink:#e8e8ea; --muted:#8f8f99; --faint:#63636d;
    --rule:#26262b; --rule-strong:#35353c; --panel:#1a1a1e; --code:#0d0d10;
    --crit:#e0575c; --high:#e0873f; --med:#cfae2e; --low:#5aa87b;
  }
}
* { box-sizing:border-box; }
body {
  margin:0; background:var(--paper); color:var(--ink);
  font:14px/1.5 -apple-system, BlinkMacSystemFont, "Segoe UI", Helvetica, sans-serif;
  -webkit-font-smoothing:antialiased;
}
.mono { font-family:ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.wrap { max-width:1000px; margin:0 auto; padding:0 28px 90px; }

/* masthead */
.masthead {
  display:flex; align-items:baseline; justify-content:space-between;
  gap:24px; flex-wrap:wrap;
  padding:34px 0 14px; border-bottom:2px solid var(--ink);
}
.brand {
  font-family:ui-monospace, SFMono-Regular, Menlo, monospace;
  font-size:19px; font-weight:600; letter-spacing:.22em; text-transform:uppercase;
}
.brand em { font-style:normal; color:var(--crit); }
.tagline { color:var(--muted); font-size:12px; letter-spacing:.02em; }
.meta { display:flex; gap:26px; font-size:11px; }
.meta div { display:flex; flex-direction:column; gap:3px; }
.meta dt {
  color:var(--faint); text-transform:uppercase; letter-spacing:.12em; font-size:9.5px;
}
.meta dd { margin:0; font-family:ui-monospace, Menlo, monospace; font-size:11.5px; }

/* verdict */
.verdict { display:flex; align-items:flex-end; gap:44px; flex-wrap:wrap;
           padding:26px 0 20px; border-bottom:1px solid var(--rule); }
.verdict-label { font-size:10px; letter-spacing:.14em; text-transform:uppercase;
                 color:var(--faint); margin-bottom:5px; }
.verdict-value { font-size:34px; font-weight:600; letter-spacing:-.015em; line-height:1; }
.stats { display:flex; gap:34px; margin-left:auto; }
.stat b { display:block; font-size:23px; font-weight:600; line-height:1.15;
          font-family:ui-monospace, Menlo, monospace; }
.stat span { font-size:10px; letter-spacing:.1em; text-transform:uppercase; color:var(--faint); }

/* distribution */
.dist { padding:18px 0 20px; border-bottom:1px solid var(--rule); }
.bar { display:flex; height:7px; overflow:hidden; margin-bottom:11px; }
.bar i { display:block; }
.bar i + i { margin-left:2px; }
.legend { display:flex; gap:22px; flex-wrap:wrap; font-size:11.5px; }
.legend span { display:flex; align-items:center; gap:7px; color:var(--muted); }
.legend b { width:8px; height:8px; display:inline-block; }
.legend em { font-style:normal; color:var(--ink); font-family:ui-monospace, Menlo, monospace; }

.sect { display:flex; align-items:center; gap:12px; margin:34px 0 12px; }
.sect h2 { font-size:10.5px; letter-spacing:.16em; text-transform:uppercase;
           color:var(--muted); margin:0; font-weight:600; }
.sect hr { flex:1; border:0; border-top:1px solid var(--rule); }

/* toolbar */
.toolbar { display:flex; gap:8px; align-items:center; flex-wrap:wrap; margin-bottom:2px; }
.tab {
  background:none; border:1px solid var(--rule-strong); color:var(--muted);
  padding:5px 11px; font-size:11.5px; border-radius:2px; cursor:pointer;
  font-family:inherit; letter-spacing:.03em;
}
.tab:hover { border-color:var(--ink); color:var(--ink); }
.tab[aria-pressed="true"] { background:var(--ink); border-color:var(--ink); color:var(--paper); }
.tab u { text-decoration:none; opacity:.6; margin-left:5px;
         font-family:ui-monospace, Menlo, monospace; }
.spacer { flex:1; }
.search {
  border:1px solid var(--rule-strong); background:transparent; color:var(--ink);
  padding:5px 10px; font-size:11.5px; border-radius:2px; width:190px; font-family:inherit;
}
.search:focus { outline:none; border-color:var(--ink); }
.linkish { background:none; border:0; color:var(--muted); font-size:11.5px;
           cursor:pointer; text-decoration:underline; text-underline-offset:3px;
           font-family:inherit; padding:5px 2px; }
.linkish:hover { color:var(--ink); }

/* findings table */
table { width:100%; border-collapse:collapse; }
thead th {
  text-align:left; font-size:9.5px; letter-spacing:.13em; text-transform:uppercase;
  color:var(--faint); font-weight:600; padding:11px 10px; border-bottom:1px solid var(--rule-strong);
}
thead th.num { text-align:right; }
tbody.f { border-bottom:1px solid var(--rule); }
tr.row { cursor:pointer; }
tr.row:hover td { background:var(--panel); }
tr.row td { padding:11px 10px; vertical-align:middle; }
td.tick { width:14px; color:var(--faint); font-size:10px; padding-right:0; }
.tick s { text-decoration:none; display:inline-block; transition:transform .12s ease; }
tbody.f.open .tick s { transform:rotate(90deg); }
td.id { width:78px; white-space:nowrap; font-family:ui-monospace, Menlo, monospace;
        font-size:11.5px; color:var(--muted); }
td.sev { width:104px; }
.chip { display:inline-flex; align-items:center; gap:6px; font-size:10px;
        letter-spacing:.1em; font-weight:600; }
.chip b { width:7px; height:7px; display:inline-block; }
td.name { font-weight:500; }
td.ep { color:var(--muted); font-family:ui-monospace, Menlo, monospace; font-size:11.5px; }
td.score { width:96px; text-align:right; }
.score-n { font-family:ui-monospace, Menlo, monospace; font-weight:600; font-size:13px; }
.score-bar { display:block; height:2px; background:var(--rule); margin-top:5px; }
.score-bar i { display:block; height:2px; }

/* detail */
tr.detail { display:none; }
tbody.f.open tr.detail { display:table-row; }
tr.detail > td { padding:4px 10px 26px 34px; }
.grid { display:grid; grid-template-columns:repeat(auto-fit,minmax(190px,1fr));
        gap:16px 26px; padding:14px 0 18px; border-bottom:1px solid var(--rule); }
.grid dt { font-size:9.5px; letter-spacing:.12em; text-transform:uppercase;
           color:var(--faint); margin-bottom:4px; }
.grid dd { margin:0; font-size:12.5px; }
h4 { font-size:9.5px; letter-spacing:.13em; text-transform:uppercase;
     color:var(--faint); margin:20px 0 8px; font-weight:600; }
.calc { font-size:12.5px; color:var(--muted); margin:0; }
.calc b { color:var(--ink); font-family:ui-monospace, Menlo, monospace; }
pre {
  margin:0; padding:13px 15px; background:var(--code); border:1px solid var(--rule);
  border-radius:2px; overflow-x:auto; font-size:11.5px; line-height:1.65;
  font-family:ui-monospace, SFMono-Regular, Menlo, monospace; color:var(--ink);
}
pre .dim { color:var(--faint); }
.assert { font-size:11.5px; color:var(--muted); margin:9px 0 0; }
.assert code { color:var(--crit); font-family:ui-monospace, Menlo, monospace; }
.fix { font-size:12.5px; line-height:1.65; margin:0; max-width:74ch; }

/* passed + empty */
.passed { display:flex; flex-wrap:wrap; gap:7px; }
.passed span { font-family:ui-monospace, Menlo, monospace; font-size:11px;
               border:1px solid var(--rule-strong); color:var(--muted);
               padding:3px 8px; border-radius:2px; }
.passed span::before { content:"\\2713"; color:var(--low); margin-right:6px; }
.empty { padding:44px 0; text-align:center; color:var(--muted); font-size:13px; }
.empty strong { display:block; font-size:17px; color:var(--ink); margin-bottom:7px; font-weight:600; }
.none { padding:26px 0; color:var(--faint); font-size:12.5px; }

footer { margin-top:52px; padding-top:16px; border-top:1px solid var(--rule);
         color:var(--faint); font-size:11px; display:flex; justify-content:space-between;
         gap:16px; flex-wrap:wrap; }
@media (max-width:720px) {
  td.ep, thead th.ep { display:none; }
  .stats { margin-left:0; }
}
"""

JS = """
(function () {
  var tbodies = Array.prototype.slice.call(document.querySelectorAll("tbody.f"));
  var tabs = Array.prototype.slice.call(document.querySelectorAll(".tab"));
  var search = document.getElementById("q");
  var toggleAll = document.getElementById("toggle-all");
  var empty = document.getElementById("empty");
  var filter = "ALL";

  tbodies.forEach(function (tb) {
    tb.querySelector("tr.row").addEventListener("click", function () {
      tb.classList.toggle("open");
    });
  });

  function apply() {
    var q = (search.value || "").toLowerCase().trim();
    var shown = 0;

    tbodies.forEach(function (tb) {
      var okSev = filter === "ALL" || tb.dataset.severity === filter;
      var okText = !q || tb.dataset.haystack.indexOf(q) !== -1;
      var show = okSev && okText;
      tb.style.display = show ? "" : "none";
      if (show) { shown++; }
    });

    empty.style.display = shown ? "none" : "";
  }

  tabs.forEach(function (tab) {
    tab.addEventListener("click", function () {
      tabs.forEach(function (t) { t.setAttribute("aria-pressed", "false"); });
      tab.setAttribute("aria-pressed", "true");
      filter = tab.dataset.filter;
      apply();
    });
  });

  search.addEventListener("input", apply);

  toggleAll.addEventListener("click", function () {
    var anyClosed = tbodies.some(function (tb) {
      return tb.style.display !== "none" && !tb.classList.contains("open");
    });
    tbodies.forEach(function (tb) {
      if (tb.style.display === "none") { return; }
      tb.classList.toggle("open", anyClosed);
    });
    toggleAll.textContent = anyClosed ? "Collapse all" : "Expand all";
  });
})();
"""

PAGE = Template("""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>APICipher - $target</title>
<style>$css</style>
</head>
<body>
<div class="wrap">

  <header class="masthead">
    <div>
      <div class="brand">API<em>Cipher</em></div>
      <div class="tagline">Automated API security assessment</div>
    </div>
    <dl class="meta">
      <div><dt>Target</dt><dd>$target</dd></div>
      <div><dt>Scan</dt><dd>$scan_id</dd></div>
      <div><dt>Generated</dt><dd>$timestamp</dd></div>
    </dl>
  </header>

  <section class="verdict">
    <div>
      <div class="verdict-label">Overall risk</div>
      <div class="verdict-value" style="color:$overall_colour">$overall</div>
    </div>
    <div class="stats">
      <div class="stat"><b>$total</b><span>Findings</span></div>
      <div class="stat"><b>$passed</b><span>Passed</span></div>
      <div class="stat"><b>$controls</b><span>Controls</span></div>
    </div>
  </section>

  $distribution

  <div class="sect"><h2>Findings</h2><hr></div>

  <div class="toolbar">
    $tabs
    <span class="spacer"></span>
    <input id="q" class="search" type="search" placeholder="Filter findings" aria-label="Filter findings">
    <button id="toggle-all" class="linkish" type="button">Expand all</button>
  </div>

  $table

  <div class="sect"><h2>Controls passed</h2><hr></div>
  $passed_block

  <footer>
    <span>Generated by APICipher - credential material redacted from evidence</span>
    <span class="mono">$scan_id</span>
  </footer>
</div>
<script>$js</script>
</body>
</html>
""")


def _colour(severity: str) -> str:
    return {
        "CRITICAL": "var(--crit)",
        "HIGH": "var(--high)",
        "MEDIUM": "var(--med)",
        "LOW": "var(--low)",
        "NONE": "var(--low)",
    }.get(severity, "var(--muted)")


def _distribution(counts: dict, total: int) -> str:
    if not total:
        return ""

    segments = "".join(
        f'<i style="background:{_colour(sev)};width:{counts[sev] / total * 100:.4f}%"></i>'
        for sev in SEVERITIES if counts[sev]
    )
    legend = "".join(
        f'<span><b style="background:{_colour(sev)}"></b>{sev.title()} '
        f'<em>{counts[sev]}</em></span>'
        for sev in SEVERITIES
    )
    return f'<section class="dist"><div class="bar">{segments}</div>' \
           f'<div class="legend">{legend}</div></section>'


def _tabs(counts: dict, total: int) -> str:
    buttons = [
        '<button class="tab" data-filter="ALL" aria-pressed="true">'
        f'All <u>{total}</u></button>'
    ]
    for sev in SEVERITIES:
        if counts[sev]:
            buttons.append(
                f'<button class="tab" data-filter="{sev}" aria-pressed="false">'
                f'{sev.title()} <u>{counts[sev]}</u></button>'
            )
    return "".join(buttons)


def _row(finding: dict) -> str:
    ev = finding["evidence"]
    sc = finding["scoring"]
    colour = _colour(finding["severity"])

    body = html.escape(ev["response_body"] or "(empty response)")
    if ev.get("response_truncated"):
        body += '\n<span class="dim">... truncated</span>'

    product = sc["likelihood"] * sc["impact"] * sc["exposure"]
    haystack = html.escape(
        " ".join([
            finding["id"], finding["vulnerability"], finding["endpoint"],
            finding["description"], finding["owasp"], finding["vuln_type"],
        ]).lower()
    )

    return f"""
    <tbody class="f" data-severity="{finding['severity']}" data-haystack="{haystack}">
      <tr class="row">
        <td class="tick"><s>&#9656;</s></td>
        <td class="id">{finding['id']}</td>
        <td class="sev"><span class="chip" style="color:{colour}">
          <b style="background:{colour}"></b>{finding['severity']}</span></td>
        <td class="name">{html.escape(finding['vulnerability'])}</td>
        <td class="ep">{html.escape(finding['endpoint'])}</td>
        <td class="score">
          <span class="score-n" style="color:{colour}">{finding['risk_score']}</span>
          <span class="score-bar"><i style="background:{colour};
            width:{finding['risk_score'] * 10:.0f}%"></i></span>
        </td>
      </tr>
      <tr class="detail">
        <td colspan="6">
          <dl class="grid">
            <div><dt>OWASP</dt><dd>{html.escape(finding['owasp'])}</dd></div>
            <div><dt>CWE</dt><dd>{html.escape(finding['cwe'])}</dd></div>
            <div><dt>Method</dt><dd>{finding['method']}</dd></div>
            <div><dt>Status</dt><dd>{finding['status']}</dd></div>
            <div style="grid-column:1/-1"><dt>Expected behaviour</dt>
              <dd>{html.escape(finding['description'])}</dd></div>
          </dl>

          <h4>Risk calculation</h4>
          <p class="calc">Likelihood <b>{sc['likelihood']}</b> &times; Impact
            <b>{sc['impact']}</b> &times; Exposure <b>{sc['exposure']}</b>
            = {product}/125 &rarr;
            <b style="color:{colour}">{finding['risk_score']}/10</b></p>

          <h4>Evidence</h4>
          <pre>{html.escape(ev['request'])}
<span class="dim">&#8595;</span>
HTTP {ev['status_code']}
{body}</pre>
          <p class="assert">Assertion failed: <code>{html.escape(ev['assertion_error'])}</code></p>

          <h4>Remediation</h4>
          <p class="fix">{html.escape(finding['remediation'])}</p>
        </td>
      </tr>
    </tbody>"""


def _table(findings: list) -> str:
    if not findings:
        return """
    <div class="empty">
      <strong>No vulnerabilities detected</strong>
      Every security control passed against this build.
    </div>"""

    rows = "".join(_row(f) for f in findings)
    return f"""
    <table>
      <thead><tr>
        <th></th><th>ID</th><th>Severity</th><th>Vulnerability</th>
        <th class="ep">Endpoint</th><th class="num">Score</th>
      </tr></thead>
      {rows}
    </table>
    <div class="empty" id="empty" style="display:none">No findings match this filter.</div>"""


def generate(findings_path: str = FINDINGS_PATH) -> str:
    with open(findings_path) as handle:
        scan = json.load(handle)

    summary = scan["summary"]
    counts = summary["severity_counts"]
    total = summary["vulnerabilities_found"]
    findings = scan["findings"]

    passed = scan.get("passed_controls", [])
    passed_block = (
        '<div class="passed">'
        + "".join(f"<span>{html.escape(c)}</span>" for c in passed)
        + "</div>"
        if passed
        else '<p class="none">No controls passed in this run.</p>'
    )

    table = _table(findings)
    if not findings:
        # keep the JS happy - it always looks for #empty
        table += '<div id="empty" style="display:none"></div>'

    return PAGE.substitute(
        css=CSS,
        js=JS,
        target=html.escape(scan["target"]),
        scan_id=html.escape(scan["scan_id"]),
        timestamp=scan["timestamp"][:19].replace("T", " ") + " UTC",
        overall=summary["overall_risk"],
        overall_colour=_colour(summary["overall_risk"]),
        total=total,
        passed=summary["tests_passed"],
        controls=summary["assertions_total"],
        distribution=_distribution(counts, total),
        tabs=_tabs(counts, total),
        table=table,
        passed_block=passed_block,
    )


def main():
    if not os.path.exists(FINDINGS_PATH):
        raise SystemExit(
            f"No findings at {FINDINGS_PATH}. Run the scanner first:\n"
            "  python -m scanner.scanner"
        )

    with open(OUTPUT_PATH, "w") as handle:
        handle.write(generate())

    print(f"  Dashboard written to {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
