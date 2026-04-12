"""Backward-compatible wrapper for the unified PDF report generator."""

from report_generator import generate_basic_report


def generate_pdf_report(df, alvo):
    """Generate the legacy basic PDF while delegating to the unified report engine."""
    return generate_basic_report(df, alvo)
