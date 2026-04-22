"""Reporting stage. Jinja2 + Plotly → two HTML files.

Contract:
    render(scan, out_dir) -> (technical_path, executive_path)

Both reports render from the same Pydantic Scan model so the two outputs
can never disagree about the underlying data.
"""

from __future__ import annotations

from pathlib import Path

import plotly.graph_objects as go
from jinja2 import Environment, FileSystemLoader, select_autoescape

from . import config, risk
from .diff import DiffResult
from .models import Scan, Severity


def _risk_gauge_figure(score: float) -> go.Figure:
    colour = "#28a745"  # green
    if score >= 75:
        colour = "#dc3545"  # red
    elif score >= 50:
        colour = "#fd7e14"  # orange
    elif score >= 25:
        colour = "#ffc107"  # yellow

    fig = go.Figure(
        go.Indicator(
            mode="gauge+number",
            value=score,
            number={"suffix": " / 100"},
            title={"text": "Overall Risk Score"},
            gauge={
                "axis": {"range": [0, 100]},
                "bar": {"color": colour},
                "steps": [
                    {"range": [0, 25], "color": "#e9f5ea"},
                    {"range": [25, 50], "color": "#fff8e1"},
                    {"range": [50, 75], "color": "#ffe8d6"},
                    {"range": [75, 100], "color": "#f8d7da"},
                ],
            },
        )
    )
    fig.update_layout(margin={"t": 40, "b": 20, "l": 20, "r": 20}, height=300)
    return fig


def _severity_bar_figure(breakdown: dict[str, int]) -> go.Figure:
    severity_order = [s.value for s in Severity if s != Severity.NONE]
    x = severity_order
    y = [breakdown.get(s, 0) for s in x]
    colours = {
        "Critical": "#dc3545",
        "High": "#fd7e14",
        "Medium": "#ffc107",
        "Low": "#17a2b8",
    }
    fig = go.Figure(
        go.Bar(
            x=x,
            y=y,
            marker_color=[colours.get(s, "#6c757d") for s in x],
        )
    )
    fig.update_layout(
        title="Findings by Severity",
        margin={"t": 40, "b": 20, "l": 40, "r": 20},
        height=300,
    )
    return fig


def _top_hosts_bar_figure(top_hosts: list[tuple[str, float]]) -> go.Figure:
    if not top_hosts:
        fig = go.Figure()
        fig.update_layout(
            title="Top Risk Hosts",
            annotations=[
                {
                    "text": "No host-level risk data",
                    "xref": "paper",
                    "yref": "paper",
                    "showarrow": False,
                    "font": {"size": 16},
                }
            ],
            height=300,
        )
        return fig

    fig = go.Figure(
        go.Bar(
            x=[h[0] for h in top_hosts],
            y=[h[1] for h in top_hosts],
            marker_color="#fd7e14",
        )
    )
    fig.update_layout(
        title="Top Risk Hosts",
        margin={"t": 40, "b": 20, "l": 40, "r": 20},
        height=300,
    )
    return fig


def render(scan: Scan, out_dir: Path) -> tuple[Path, Path]:
    """Render technical.html and executive.html for `scan` into `out_dir`."""
    out_dir.mkdir(parents=True, exist_ok=True)

    env = Environment(
        loader=FileSystemLoader(config.TEMPLATES_DIR),
        autoescape=select_autoescape(["html", "xml"]),
    )

    # ------------------------------------------------------------------
    # Compute risk metrics
    # ------------------------------------------------------------------
    risk_score = risk.risk_score(scan.findings)
    severity_breakdown = risk.severity_breakdown(scan.findings)
    top_hosts = risk.top_risk_hosts(scan.findings)
    kev_count = sum(1 for f in scan.findings if f.in_kev)
    exploit_count = sum(1 for f in scan.findings if f.exploit_refs)
    epss_values = [f.epss_score for f in scan.findings if f.epss_score is not None]
    avg_epss = sum(epss_values) / len(epss_values) if epss_values else 0.0

    plotly_figures = {
        "risk_gauge": _risk_gauge_figure(risk_score).to_json(),
        "severity_bar": _severity_bar_figure(severity_breakdown).to_json(),
        "top_hosts_bar": _top_hosts_bar_figure(top_hosts).to_json(),
    }

    # ------------------------------------------------------------------
    # Technical report
    # ------------------------------------------------------------------
    tech_template = env.get_template("technical.html")
    tech_path = out_dir / "technical.html"
    tech_path.write_text(
        tech_template.render(
            scan=scan,
            findings=scan.findings,
            hosts=scan.hosts,
            scan_json=scan.model_dump_json(),
        ),
        encoding="utf-8",
    )

    # ------------------------------------------------------------------
    # Executive report
    # ------------------------------------------------------------------
    exec_template = env.get_template("executive.html")
    exec_path = out_dir / "executive.html"
    exec_path.write_text(
        exec_template.render(
            scan=scan,
            risk_score=risk_score,
            severity_breakdown=severity_breakdown,
            top_hosts=top_hosts,
            plotly_figures=plotly_figures,
            kev_count=kev_count,
            exploit_count=exploit_count,
            avg_epss=avg_epss,
        ),
        encoding="utf-8",
    )

    return tech_path, exec_path


def render_diff(result: DiffResult, out_dir: Path) -> Path:
    """Render diff.html for a comparison between two scans."""
    out_dir.mkdir(parents=True, exist_ok=True)
    env = Environment(
        loader=FileSystemLoader(config.TEMPLATES_DIR),
        autoescape=select_autoescape(["html", "xml"]),
    )
    template = env.get_template("diff.html")
    path = out_dir / "diff.html"
    path.write_text(
        template.render(
            result=result,
            risk=risk,
        ),
        encoding="utf-8",
    )
    return path
