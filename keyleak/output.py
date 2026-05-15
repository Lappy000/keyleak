"""Rich output formatters for keyleak results.

Provides both table (terminal) and JSON output modes.
Uses the rich library for beautiful terminal output.
"""

from __future__ import annotations

import json
import sys
from typing import TextIO

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

from keyleak.validators import KeyStatus, ValidationResult


def _status_style(status: KeyStatus) -> str:
    """Map status to rich style string."""
    styles = {
        KeyStatus.VALID: "bold green",
        KeyStatus.INVALID: "bold red",
        KeyStatus.EXPIRED: "bold yellow",
        KeyStatus.RATE_LIMITED: "bold cyan",
        KeyStatus.ERROR: "bold magenta",
        KeyStatus.UNKNOWN: "dim",
    }
    return styles.get(status, "dim")


def _mask_key(key: str, visible: int = 8) -> str:
    """Mask a key for safe display."""
    if len(key) <= visible:
        return key
    return key[:visible] + "*" * min(16, len(key) - visible)


def render_table(
    results: list[ValidationResult],
    console: Console | None = None,
    show_full_keys: bool = False,
) -> None:
    """Render validation results as a rich table.

    Args:
        results: List of ValidationResult objects.
        console: Optional Rich console (creates one if not provided).
        show_full_keys: If True, show full key values (dangerous!).
    """
    if console is None:
        console = Console()

    if not results:
        console.print("[dim]No keys to display.[/dim]")
        return

    table = Table(
        title="🔑 KeyLeak Validation Results",
        show_header=True,
        header_style="bold blue",
        border_style="bright_black",
        show_lines=True,
    )

    table.add_column("#", style="dim", width=4, justify="right")
    table.add_column("Service", style="bold", width=14)
    table.add_column("Key", width=28, no_wrap=True)
    table.add_column("Status", width=14, justify="center")
    table.add_column("Message", width=50)
    table.add_column("Time", width=8, justify="right")

    for idx, result in enumerate(results, start=1):
        key_display = result.key_value if show_full_keys else _mask_key(result.key_value)
        status_text = Text(
            f"{result.status_emoji} {result.status.value}",
            style=_status_style(result.status),
        )
        time_str = f"{result.response_time_ms:.0f}ms" if result.response_time_ms else "—"

        table.add_row(
            str(idx),
            result.service,
            key_display,
            status_text,
            result.message,
            time_str,
        )

    console.print(table)

    # Summary
    valid_count = sum(1 for r in results if r.status == KeyStatus.VALID)
    invalid_count = sum(1 for r in results if r.status == KeyStatus.INVALID)
    error_count = sum(1 for r in results if r.status in (KeyStatus.ERROR, KeyStatus.UNKNOWN))
    total = len(results)

    summary = (
        f"[bold]Summary:[/bold] {total} key(s) checked — "
        f"[green]{valid_count} valid[/green], "
        f"[red]{invalid_count} invalid[/red], "
        f"[yellow]{error_count} errors/unknown[/yellow]"
    )
    console.print(Panel(summary, border_style="bright_black"))


def render_json(
    results: list[ValidationResult],
    output: TextIO | None = None,
    pretty: bool = True,
) -> str:
    """Render validation results as JSON.

    Args:
        results: List of ValidationResult objects.
        output: Optional file-like object to write to.
        pretty: If True, use indented formatting.

    Returns:
        The JSON string.
    """
    data = {
        "results": [r.to_dict() for r in results],
        "summary": {
            "total": len(results),
            "valid": sum(1 for r in results if r.status == KeyStatus.VALID),
            "invalid": sum(1 for r in results if r.status == KeyStatus.INVALID),
            "expired": sum(1 for r in results if r.status == KeyStatus.EXPIRED),
            "rate_limited": sum(1 for r in results if r.status == KeyStatus.RATE_LIMITED),
            "error": sum(1 for r in results if r.status == KeyStatus.ERROR),
            "unknown": sum(1 for r in results if r.status == KeyStatus.UNKNOWN),
        },
    }

    indent = 2 if pretty else None
    json_str = json.dumps(data, indent=indent, ensure_ascii=False)

    if output:
        output.write(json_str)
        output.write("\n")
    else:
        sys.stdout.write(json_str)
        sys.stdout.write("\n")

    return json_str


def render_compact(
    results: list[ValidationResult],
    console: Console | None = None,
) -> None:
    """Render results in compact one-line-per-key format.

    Args:
        results: List of ValidationResult objects.
        console: Optional Rich console.
    """
    if console is None:
        console = Console()

    for result in results:
        style = _status_style(result.status)
        key_short = _mask_key(result.key_value, visible=6)
        line = f"{result.status_emoji} [{style}]{result.status.value:12s}[/{style}] | {result.service:12s} | {key_short:24s} | {result.message}"
        console.print(line)


def render_details(
    result: ValidationResult,
    console: Console | None = None,
) -> None:
    """Render detailed info for a single validation result.

    Args:
        result: The ValidationResult to display.
        console: Optional Rich console.
    """
    if console is None:
        console = Console()

    style = _status_style(result.status)
    panel_content = []
    panel_content.append(f"[bold]Service:[/bold]  {result.service}")
    panel_content.append(f"[bold]Key:[/bold]      {_mask_key(result.key_value)}")
    panel_content.append(f"[bold]Status:[/bold]   [{style}]{result.status_emoji} {result.status.value}[/{style}]")
    panel_content.append(f"[bold]Message:[/bold]  {result.message}")

    if result.account_info:
        panel_content.append(f"[bold]Account:[/bold]  {result.account_info}")
    if result.permissions:
        panel_content.append(f"[bold]Perms:[/bold]    {result.permissions}")
    if result.http_status:
        panel_content.append(f"[bold]HTTP:[/bold]     {result.http_status}")
    if result.response_time_ms:
        panel_content.append(f"[bold]Time:[/bold]     {result.response_time_ms:.1f}ms")

    console.print(Panel(
        "\n".join(panel_content),
        title=f"[bold]{result.service}[/bold] validation",
        border_style=style.replace("bold ", ""),
    ))
