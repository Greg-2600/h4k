"""One-click assessment PDF (Backlog #14).

Renders the session report dict as a client-ready PDF with reportlab
(headings, tables, footer). Passwords are masked like the loot vault —
the PDF is a handoff artifact, and the plaintext stays behind
`fmt=json|md`. Raises RuntimeError when reportlab is not installed so a
bare environment fails loudly instead of shipping an empty file.
"""

from __future__ import annotations

from io import BytesIO
from typing import Any


def build_session_pdf(report: dict[str, Any]) -> bytes:
    """Render the session-report dict to PDF bytes."""
    try:
        from reportlab.lib.pagesizes import A4
        from reportlab.lib.styles import getSampleStyleSheet
        from reportlab.lib.units import cm
        from reportlab.platypus import (
            Paragraph,
            SimpleDocTemplate,
            Spacer,
            Table,
            TableStyle,
        )
    except ImportError as exc:
        raise RuntimeError("reportlab is not installed") from exc
    from reportlab.lib import colors

    buf = BytesIO()
    doc = SimpleDocTemplate(
        buf,
        pagesize=A4,
        leftMargin=1.5 * cm,
        rightMargin=1.5 * cm,
        title=f"h4k assessment — {report.get('session_id', '')}",
        author="h4k",
    )
    styles = getSampleStyleSheet()
    story: list[Any] = []
    story.append(Paragraph("h4k assessment report", styles["Title"]))
    meta = f"generated {report.get('generated', '')}"
    scope = report.get("scope") or {}
    if scope.get("engagement_id"):
        meta += f" · scope {scope.get('name')} ({', '.join(scope.get('scope') or [])})"
    story.append(Paragraph(meta, styles["Normal"]))
    story.append(Spacer(1, 0.4 * cm))

    def section(title: str) -> None:
        story.append(Paragraph(title, styles["Heading2"]))

    def table(rows: list[list[str]]) -> None:
        if not rows:
            return
        t = Table(rows, repeatRows=1)
        t.setStyle(
            TableStyle(
                [
                    ("BACKGROUND", (0, 0), (-1, 0), colors.HexColor("#1f2937")),
                    ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
                    ("FONTSIZE", (0, 0), (-1, -1), 8),
                    ("GRID", (0, 0), (-1, -1), 0.5, colors.grey),
                ]
            )
        )
        story.append(t)
        story.append(Spacer(1, 0.3 * cm))

    section("Hosts discovered")
    table(
        [["Host", "Vendor", "Hostname", "OS"]]
        + [
            [
                h.get("ip", ""),
                h.get("vendor") or "",
                h.get("hostname") or "",
                h.get("os") or "",
            ]
            for h in report.get("hosts", [])
        ]
        or [["—", "no hosts discovered", "", ""]]
    )
    section("Open services")
    table(
        [["Host", "Port", "Service", "Product", "Version"]]
        + [
            [
                s.get("ip", ""),
                str(s.get("port", "")),
                s.get("service") or "?",
                s.get("product") or "",
                s.get("version") or "",
            ]
            for s in report.get("services", [])
        ]
        or [["—", "", "no services", "", ""]]
    )
    section("Likely vulnerable")
    table(
        [["Finding", "Where", "Severity", "Detail"]]
        + [
            [
                v.get("vid", ""),
                f"{v.get('ip')}:{v.get('port')}",
                str(v.get("severity") or ""),
                (v.get("detail") or "")[:160],
            ]
            for v in report.get("vulns", [])
        ]
        or [["—", "", "", "no findings"]]
    )
    section("Credentials verified (passwords masked)")
    table(
        [["Host", "Service", "User", "Password"]]
        + [
            [
                f"{c.get('host')}:{c.get('port')}",
                c.get("service") or "",
                c.get("user") or "",
                "•" * 8,
            ]
            for c in report.get("credentials", [])
        ]
        or [["—", "", "", "none"]]
    )
    section("Sessions opened")
    table(
        [["Host", "Module", "Session"]]
        + [
            [
                s.get("host") or "",
                s.get("module") or "",
                str(s.get("msf_session_id") or ""),
            ]
            for s in report.get("sessions", [])
        ]
        or [["—", "none", ""]]
    )
    story.append(
        Paragraph(
            "Generated for authorized lab use — verify every target was owned before citing it. "
            "Passwords masked; use the JSON/MD export for full detail.",
            styles["Italic"] if "Italic" in styles else styles["Normal"],
        )
    )
    doc.build(story)
    return buf.getvalue()
