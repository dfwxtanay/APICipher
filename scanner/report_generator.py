"""Render scored findings into a human-readable Markdown security report."""

import json
import os

from .risk_engine import CRITICAL_THRESHOLD, HIGH_THRESHOLD, MEDIUM_THRESHOLD

FINDINGS_PATH = "reports/findings.json"
REPORT_PATH = "reports/APICipher-Security-Report.md"

SEVERITY_ICONS = {
    "CRITICAL": "[CRITICAL]",
    "HIGH": "[HIGH]",
    "MEDIUM": "[MEDIUM]",
    "LOW": "[LOW]",
}


def _risk_bar(score: float, width: int = 20) -> str:
    filled = int(round(score / 10 * width))
    return "#" * filled + "." * (width - filled)


def _summary_section(scan: dict) -> list:
    summary = scan["summary"]
    counts = summary["severity_counts"]

    lines = [
        "## Executive Summary",
        "",
        f"**Overall risk rating: {summary['overall_risk']}**",
        "",
        f"An automated security assessment of `{scan['target']}` executed "
        f"{summary['assertions_total']} security controls, of which "
        f"{summary['vulnerabilities_found']} failed and "
        f"{summary['tests_passed']} passed.",
        "",
        "| Severity | Count |",
        "| --- | --- |",
        f"| Critical | {counts['CRITICAL']} |",
        f"| High | {counts['HIGH']} |",
        f"| Medium | {counts['MEDIUM']} |",
        f"| Low | {counts['LOW']} |",
        f"| **Total** | **{summary['vulnerabilities_found']}** |",
        "",
    ]

    critical_and_high = [
        f for f in scan["findings"] if f["severity"] in ("CRITICAL", "HIGH")
    ]
    if critical_and_high:
        top = critical_and_high[0]
        lines += [
            f"The highest-rated issue is **{top['id']} - {top['vulnerability']}** "
            f"({top['risk_score']}/10) on `{top['endpoint']}`. "
            f"{len(critical_and_high)} finding(s) are rated High or above and "
            "should be remediated before this API is exposed to untrusted networks.",
            "",
        ]

    return lines


def _top_risks_section(scan: dict) -> list:
    lines = [
        "## Top Risks",
        "",
        "| Rank | ID | Vulnerability | Endpoint | Severity | Score |",
        "| --- | --- | --- | --- | --- | --- |",
    ]

    for rank, finding in enumerate(scan["findings"][:5], start=1):
        lines.append(
            f"| {rank} | {finding['id']} | {finding['vulnerability']} | "
            f"`{finding['endpoint']}` | {finding['severity']} | {finding['risk_score']} |"
        )

    lines.append("")
    return lines


def _finding_section(finding: dict) -> list:
    scoring = finding["scoring"]
    evidence = finding["evidence"]

    body = evidence["response_body"]
    if evidence.get("response_truncated"):
        body += "\n... [truncated]"

    return [
        f"### {finding['id']} - {finding['vulnerability']}",
        "",
        f"{SEVERITY_ICONS.get(finding['severity'], '')} "
        f"**{finding['severity']}** | Risk score **{finding['risk_score']}/10** "
        f"`{_risk_bar(finding['risk_score'])}`",
        "",
        "| | |",
        "| --- | --- |",
        f"| Endpoint | `{finding['endpoint']}` |",
        f"| Expectation | {finding['description']} |",
        f"| OWASP | {finding['owasp']} |",
        f"| CWE | {finding['cwe']} |",
        f"| Status | {finding['status']} |",
        "",
        "**Risk calculation**",
        "",
        f"Likelihood {scoring['likelihood']}/5 x Impact {scoring['impact']}/5 "
        f"x Exposure {scoring['exposure']}/5 = "
        f"{scoring['likelihood'] * scoring['impact'] * scoring['exposure']}/125 "
        f"-> **{finding['risk_score']}/10**",
        "",
        "**Evidence**",
        "",
        "```http",
        evidence["request"],
        "",
        f"HTTP {evidence['status_code']}",
        body,
        "```",
        "",
        f"Assertion failure: `{evidence['assertion_error']}`",
        "",
        "**Remediation**",
        "",
        finding["remediation"],
        "",
        "---",
        "",
    ]


def _methodology_section() -> list:
    return [
        "## Methodology",
        "",
        "Each security control is expressed as a test asserting *secure* behaviour, "
        "so a failing assertion is a detected vulnerability. Findings are scored on "
        "three axes, each rated 1-5:",
        "",
        "- **Likelihood** - how easily the weakness can be exploited",
        "- **Impact** - the consequence of successful exploitation",
        "- **Exposure** - who can reach the affected endpoint "
        "(5 = unauthenticated, 4 = any authenticated user, 2 = administrators only)",
        "",
        "```",
        "Risk Score = (Likelihood x Impact x Exposure) / 125 x 10",
        "```",
        "",
        "The axes are multiplied rather than averaged so that an unreachable "
        "weakness collapses toward zero regardless of its theoretical severity. "
        "This is why identical data exposure scores 10.0 when anonymous and 4.0 "
        "when it requires an administrator account.",
        "",
        "| Band | Range |",
        "| --- | --- |",
        f"| CRITICAL | >= {CRITICAL_THRESHOLD} |",
        f"| HIGH | {HIGH_THRESHOLD} - {CRITICAL_THRESHOLD - 0.1:.1f} |",
        f"| MEDIUM | {MEDIUM_THRESHOLD} - {HIGH_THRESHOLD - 0.1:.1f} |",
        f"| LOW | < {MEDIUM_THRESHOLD} |",
        "",
    ]


def _passed_section(scan: dict) -> list:
    passed = scan.get("passed_controls", [])
    if not passed:
        return []

    return [
        "## Controls Passed",
        "",
        "The following controls were tested and found to be correctly implemented. "
        "They are listed to demonstrate that the test suite distinguishes secure "
        "behaviour from insecure behaviour rather than reporting every check as a failure.",
        "",
        "".join(f"- `{control}`\n" for control in passed),
        "",
    ]


def generate(findings_path: str = FINDINGS_PATH) -> str:
    with open(findings_path) as handle:
        scan = json.load(handle)

    lines = [
        "# APICipher Security Assessment",
        "",
        f"**Scan ID:** `{scan['scan_id']}`  ",
        f"**Target:** {scan['target']}  ",
        f"**Generated:** {scan['timestamp']}",
        "",
        "---",
        "",
    ]

    lines += _summary_section(scan)
    lines += _top_risks_section(scan)

    lines += ["## Findings", ""]
    for finding in scan["findings"]:
        lines += _finding_section(finding)

    lines += _passed_section(scan)
    lines += _methodology_section()

    return "\n".join(lines)


def main():
    if not os.path.exists(FINDINGS_PATH):
        raise SystemExit(
            f"No findings at {FINDINGS_PATH}. Run the scanner first:\n"
            "  python -m scanner.scanner"
        )

    report = generate()

    with open(REPORT_PATH, "w") as handle:
        handle.write(report)

    print(f"  Report written to {REPORT_PATH} ({len(report.splitlines())} lines)")


if __name__ == "__main__":
    main()
