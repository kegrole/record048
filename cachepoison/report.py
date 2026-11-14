"""Report assembly and summary statistics."""

from .detector import VERDICT_RISK


def summarize(results):
    """Build the summary block for a list of report entries."""
    distribution = {}
    risk_count = 0
    for entry in results:
        if entry["verdict"] != VERDICT_RISK:
            continue
        risk_count += 1
        for risk_type in entry["risk_types"]:
            distribution[risk_type] = distribution.get(risk_type, 0) + 1
    return {
        "cases": len(results),
        "risks": risk_count,
        "safe": len(results) - risk_count,
        "risk_type_distribution": distribution,
    }


def build_report(results):
    """Assemble the full JSON-serializable report."""
    return {"summary": summarize(results), "results": results}


def summary_line(report):
    """One-line human-readable summary for stdout."""
    summary = report["summary"]
    distribution = summary["risk_type_distribution"]
    dist_text = ", ".join(
        "%s=%d" % (name, distribution[name]) for name in sorted(distribution)
    ) or "none"
    return "cases=%d risks=%d safe=%d risk_types: %s" % (
        summary["cases"], summary["risks"], summary["safe"], dist_text,
    )
