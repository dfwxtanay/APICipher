"""Risk scoring. Pure functions only - no I/O, so this stays easy to unit test."""

MAX_PRODUCT = 125  # 5 * 5 * 5

CRITICAL_THRESHOLD = 9.0
HIGH_THRESHOLD = 7.0
MEDIUM_THRESHOLD = 4.0

SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}


def calculate_risk(likelihood: int, impact: int, exposure: int) -> float:
    """Normalise Likelihood x Impact x Exposure onto a 0-10 scale.

    Multiplying rather than averaging is deliberate: a vulnerability that is
    unreachable (exposure 1) should collapse toward zero no matter how severe it
    would otherwise be, and averaging would keep it artificially high.
    """
    for name, value in (("likelihood", likelihood), ("impact", impact), ("exposure", exposure)):
        if not 1 <= value <= 5:
            raise ValueError(f"{name} must be between 1 and 5, got {value}")

    score = (likelihood * impact * exposure) / MAX_PRODUCT * 10
    return round(score, 1)


def severity_band(score: float) -> str:
    if score >= CRITICAL_THRESHOLD:
        return "CRITICAL"
    if score >= HIGH_THRESHOLD:
        return "HIGH"
    if score >= MEDIUM_THRESHOLD:
        return "MEDIUM"
    return "LOW"


def sort_key(finding: dict):
    """Rank findings most-urgent first: severity band, then score, then id."""
    return (
        SEVERITY_ORDER.get(finding["severity"], 99),
        -finding["risk_score"],
        finding["id"],
    )
