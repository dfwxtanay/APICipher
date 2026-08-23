"""Parse a Newman run report into scored, evidence-backed security findings.

Every Postman assertion asserts SECURE behaviour, so a FAILED assertion is a
detected vulnerability. Assertion names carry their own metadata:

    APC-001 | BOLA | GET /users/{user_id} | Must deny cross-user object access
"""

import json
import os
import re
from datetime import datetime, timezone

from .vulnerability_rules import get_rule, get_exposure, get_likelihood
from .risk_engine import calculate_risk, severity_band, sort_key

RESULTS_PATH = "reports/newman-results.json"
FINDINGS_PATH = "reports/findings.json"

EVIDENCE_BODY_LIMIT = 300

# Evidence must prove the leak without reproducing the leaked secret itself - a
# report that quotes real password hashes recreates the vulnerability it reports.
REDACTIONS = (
    (re.compile(r"\$argon2[a-z0-9]*\$[^\"]+"), "$argon2id$[REDACTED]"),
    (re.compile(r"\bey[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"), "[JWT_REDACTED]"),
    (re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}"), "[EMAIL_REDACTED]"),
)


def redact(text: str) -> str:
    for pattern, replacement in REDACTIONS:
        text = pattern.sub(replacement, text)
    return text


def _decode_stream(stream) -> str:
    """Newman stores response bodies as a JSON-encoded Buffer."""
    if not stream or "data" not in stream:
        return ""
    try:
        return bytes(stream["data"]).decode("utf-8", errors="replace")
    except (TypeError, ValueError):
        return ""


def _rebuild_url(url) -> str:
    """Newman drops the raw URL from the report, so reassemble it."""
    if isinstance(url, str):
        return url

    host = ".".join(url.get("host", []))
    port = url.get("port")
    path = "/".join(url.get("path", []))

    authority = f"{host}:{port}" if port else host
    return f"{url.get('protocol', 'http')}://{authority}/{path}"


def parse_assertion_name(name: str):
    """Split 'ID | TYPE | ENDPOINT | Description' into its four parts."""
    parts = [part.strip() for part in name.split("|")]
    if len(parts) < 4:
        return None

    return {
        "id": parts[0],
        "vuln_type": parts[1],
        "endpoint": parts[2],
        "description": parts[3],
    }


def build_finding(meta: dict, execution: dict, error_message: str) -> dict:
    rule = get_rule(meta["vuln_type"])
    exposure = get_exposure(meta["id"], rule)
    likelihood = get_likelihood(meta["id"], rule)

    score = calculate_risk(likelihood, rule["impact"], exposure)

    request = execution.get("request", {})
    response = execution.get("response", {})
    body = redact(_decode_stream(response.get("stream")))

    return {
        "id": meta["id"],
        "vulnerability": rule["title"],
        "vuln_type": meta["vuln_type"],
        "endpoint": meta["endpoint"],
        "method": request.get("method", "UNKNOWN"),
        "description": meta["description"],
        "severity": severity_band(score),
        "risk_score": score,
        "scoring": {
            "likelihood": likelihood,
            "impact": rule["impact"],
            "exposure": exposure,
        },
        "owasp": rule["owasp"],
        "cwe": rule["cwe"],
        "evidence": {
            "request": f"{request.get('method', '?')} {_rebuild_url(request.get('url', ''))}",
            "status_code": response.get("code"),
            "assertion_error": error_message,
            "response_body": body[:EVIDENCE_BODY_LIMIT],
            "response_truncated": len(body) > EVIDENCE_BODY_LIMIT,
        },
        "remediation": rule["remediation"],
        "status": "OPEN",
    }


def scan(results_path: str = RESULTS_PATH) -> dict:
    with open(results_path) as handle:
        report = json.load(handle)

    run = report["run"]
    executions = run.get("executions", [])
    target = report.get("collection", {}).get("info", {}).get("name", "Unknown target")

    findings = []
    passed = []

    for execution in executions:
        for assertion in execution.get("assertions", []):
            meta = parse_assertion_name(assertion.get("assertion", ""))
            if meta is None:
                continue  # setup scripts and anything not following the convention

            if assertion.get("error"):
                findings.append(
                    build_finding(meta, execution, assertion["error"].get("message", ""))
                )
            else:
                passed.append(meta["id"])

    findings.sort(key=sort_key)

    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    for finding in findings:
        counts[finding["severity"]] += 1

    if counts["CRITICAL"]:
        overall = "CRITICAL"
    elif counts["HIGH"]:
        overall = "HIGH"
    elif counts["MEDIUM"]:
        overall = "MEDIUM"
    elif counts["LOW"]:
        overall = "LOW"
    else:
        overall = "NONE"

    return {
        "scan_id": datetime.now(timezone.utc).strftime("APICIPHER-%Y%m%d-%H%M%S"),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "target": target,
        "summary": {
            "assertions_total": len(findings) + len(passed),
            "tests_passed": len(passed),
            "vulnerabilities_found": len(findings),
            "overall_risk": overall,
            "severity_counts": counts,
        },
        "passed_controls": sorted(passed),
        "findings": findings,
    }


def main():
    if not os.path.exists(RESULTS_PATH):
        raise SystemExit(
            f"No Newman report at {RESULTS_PATH}. Run the collection first:\n"
            "  npx newman run postman/APICipher-Security-Tests.json "
            "-e postman/APICipher-Local.postman_environment.json "
            "--reporters cli,json --reporter-json-export reports/newman-results.json"
        )

    result = scan()

    with open(FINDINGS_PATH, "w") as handle:
        json.dump(result, handle, indent=2)

    summary = result["summary"]
    counts = summary["severity_counts"]

    print(f"\n  APICipher scan {result['scan_id']}")
    print(f"  {'-' * 46}")
    print(f"  Overall risk        : {summary['overall_risk']}")
    print(f"  Vulnerabilities     : {summary['vulnerabilities_found']}")
    print(f"  Controls passed     : {summary['tests_passed']}")
    print(
        f"  Critical {counts['CRITICAL']}   High {counts['HIGH']}   "
        f"Medium {counts['MEDIUM']}   Low {counts['LOW']}"
    )
    print(f"  {'-' * 46}")

    for finding in result["findings"]:
        print(
            f"  {finding['id']}  {finding['risk_score']:>4}  "
            f"{finding['severity']:<8}  {finding['vulnerability']}"
        )

    print(f"\n  Written to {FINDINGS_PATH}\n")


if __name__ == "__main__":
    main()
