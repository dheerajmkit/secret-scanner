"""Markdown reporting for scan findings."""
from collections import Counter

SEVERITY_ORDER = ("critical", "high", "medium", "low")


def _cell(value):
    return str(value).replace("|", "\\|").replace("\n", " ")


def to_markdown(findings):
    """Render ``findings`` as a Markdown report string."""
    counts = Counter(f["severity"] for f in findings)
    lines = ["# Secret scan report", "",
             f"**Findings:** {len(findings)}", ""]
    if counts:
        lines += ["## Counts by severity", ""]
        for sev in SEVERITY_ORDER:
            if counts.get(sev):
                lines.append(f"- {sev}: {counts[sev]}")
        lines.append("")
    if findings:
        lines += ["## Findings", "",
                  "| File | Line | Type | Severity | Snippet |",
                  "| ---- | ---- | ---- | -------- | ------- |"]
        for f in sorted(findings, key=lambda x: (x["file"], x["line"])):
            lines.append("| {} | {} | {} | {} | {} |".format(
                _cell(f["file"]), f["line"], _cell(f["type"]),
                _cell(f["severity"]), _cell(f["snippet"])))
    else:
        lines.append("No hardcoded secrets detected.")
    return "\n".join(lines) + "\n"
