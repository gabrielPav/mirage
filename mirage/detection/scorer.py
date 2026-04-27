"""
scorer.py — Aggregates heuristic scores into a risk assessment per Config rule.
"""

RISK_LEVELS = [
    (70, "CRITICAL"),
    (40, "HIGH"),
    (20, "MEDIUM"),
    (5,  "LOW"),
    (0,  "INFO"),
]


def score_rule(findings: list) -> dict:
    """
    findings: list of (score, reason) tuples from heuristics.
    Returns a dict with total_score, risk_level, and reasons list.
    """
    total = sum(s for s, _ in findings)
    reasons = [r for _, r in findings if r]

    risk_level = "INFO"
    for threshold, level in RISK_LEVELS:
        if total >= threshold:
            risk_level = level
            break

    return {
        "total_score": total,
        "risk_level": risk_level,
        "reasons": reasons,
    }


def format_finding(rule_name: str, score_result: dict, verbose: bool = False) -> str:
    level = score_result["risk_level"]
    score = score_result["total_score"]
    reasons = score_result["reasons"]

    color = {
        "CRITICAL": "\033[91m",  # red
        "HIGH":     "\033[93m",  # yellow
        "MEDIUM":   "\033[33m",  # orange
        "LOW":      "\033[94m",  # blue
        "INFO":     "\033[37m",  # grey
    }.get(level, "")
    reset = "\033[0m"

    lines = [f"{color}[{level}]{reset} {rule_name}  (score: {score})"]
    if verbose or level in ("CRITICAL", "HIGH"):
        for r in reasons:
            lines.append(f"    → {r}")
    return "\n".join(lines)
