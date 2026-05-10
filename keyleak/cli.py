"""keyleak CLI — command-line interface for API key validation.

Usage:
    echo 'sk-xxx' | keyleak
    keyleak scan secrets.txt
    keyleak check 'ghp_xxxx'
    keyleak --json scan dump.txt
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import List, Optional

import click
from rich.console import Console

from keyleak import __version__
from keyleak.detector import DetectedKey, KeyDetector
from keyleak.output import render_compact, render_details, render_json, render_table
from keyleak.validators import ValidationResult, validate_key

console = Console()


def _read_stdin() -> str:
    """Read all input from stdin if available."""
    if not sys.stdin.isatty():
        return sys.stdin.read()
    return ""


def _validate_detected_keys(
    detected_keys: List[DetectedKey],
    verbose: bool = False,
) -> List[ValidationResult]:
    """Validate a list of detected keys and return results.

    Args:
        detected_keys: Keys detected by the detector.
        verbose: If True, show progress for each key.

    Returns:
        List of ValidationResult objects.
    """
    results: List[ValidationResult] = []

    for idx, dk in enumerate(detected_keys, start=1):
        if verbose:
            console.print(
                f"[dim]({idx}/{len(detected_keys)}) Validating {dk.service}: {dk.masked()}...[/dim]"
            )

        result = validate_key(dk.service, dk.raw_value)
        results.append(result)

    return results


@click.group(invoke_without_command=True)
@click.option("--json", "use_json", is_flag=True, help="Output results as JSON.")
@click.option("--compact", is_flag=True, help="Use compact one-line output format.")
@click.option("--verbose", "-v", is_flag=True, help="Show verbose progress info.")
@click.option("--version", is_flag=True, help="Show version and exit.")
@click.option(
    "--services",
    "-s",
    multiple=True,
    help="Only check specific services (can repeat).",
)
@click.pass_context
def main(
    ctx: click.Context,
    use_json: bool,
    compact: bool,
    verbose: bool,
    version: bool,
    services: tuple,
) -> None:
    """🔑 keyleak — API key leak validator.

    Detect and validate leaked API keys from stdin, files, or direct input.

    \b
    Quick start:
        echo 'sk-abc123...' | keyleak
        keyleak scan secrets.txt
        keyleak check 'ghp_...'
    """
    if version:
        click.echo(f"keyleak v{__version__}")
        sys.exit(0)

    ctx.ensure_object(dict)
    ctx.obj["use_json"] = use_json
    ctx.obj["compact"] = compact
    ctx.obj["verbose"] = verbose
    ctx.obj["services"] = list(services) if services else None

    # If no subcommand, try reading from stdin
    if ctx.invoked_subcommand is None:
        stdin_text = _read_stdin()
        if stdin_text.strip():
            _process_text(
                text=stdin_text,
                use_json=use_json,
                compact=compact,
                verbose=verbose,
                services=ctx.obj["services"],
            )
        else:
            click.echo(ctx.get_help())


@main.command()
@click.argument("files", nargs=-1, required=True, type=click.Path(exists=True))
@click.pass_context
def scan(ctx: click.Context, files: tuple) -> None:
    """Scan one or more files for API keys and validate them.

    \b
    Examples:
        keyleak scan secrets.txt
        keyleak scan *.env config/*.yml
        keyleak --json scan dump.txt > results.json
    """
    use_json = ctx.obj["use_json"]
    compact = ctx.obj["compact"]
    verbose = ctx.obj["verbose"]
    services = ctx.obj["services"]

    all_detected: List[DetectedKey] = []
    detector = KeyDetector(services=services)

    for filepath in files:
        path = Path(filepath)
        if verbose:
            console.print(f"[dim]Scanning: {path}[/dim]")

        try:
            detected = detector.detect_in_file(str(path))
            all_detected.extend(detected)
            if verbose:
                console.print(f"[dim]  Found {len(detected)} potential key(s)[/dim]")
        except (FileNotFoundError, PermissionError) as exc:
            console.print(f"[red]Error reading {path}: {exc}[/red]")
            continue

    if not all_detected:
        if use_json:
            render_json([], output=sys.stdout)
        else:
            console.print("[yellow]No API keys detected in the provided files.[/yellow]")
        return

    if verbose:
        console.print(f"\n[bold]Found {len(all_detected)} key(s). Starting validation...[/bold]\n")

    results = _validate_detected_keys(all_detected, verbose=verbose)
    _output_results(results, use_json=use_json, compact=compact)


@main.command()
@click.argument("key")
@click.option("--service", "-s", help="Force a specific service type.")
@click.pass_context
def check(ctx: click.Context, key: str, service: Optional[str]) -> None:
    """Validate a single API key directly.

    \b
    Examples:
        keyleak check 'sk-abc123...'
        keyleak check --service github 'ghp_xxxx'
        keyleak --json check 'sk_live_xxxx'
    """
    use_json = ctx.obj["use_json"]
    compact = ctx.obj["compact"]
    verbose = ctx.obj["verbose"]

    detector = KeyDetector()

    if service:
        # Force specific service
        if verbose:
            console.print(f"[dim]Validating as {service}...[/dim]")
        result = validate_key(service, key)
        results = [result]
    else:
        # Auto-detect
        detected = detector.detect_single(key)
        if detected is None:
            console.print("[red]Could not identify the key type. Use --service to specify.[/red]")
            sys.exit(1)

        if verbose:
            console.print(f"[dim]Detected as: {detected.service} ({detected.pattern_name})[/dim]")

        result = validate_key(detected.service, detected.raw_value)
        results = [result]

    _output_results(results, use_json=use_json, compact=compact, detail=True)


@main.command()
@click.pass_context
def services(ctx: click.Context) -> None:
    """List all supported services and their key patterns.

    \b
    Example:
        keyleak services
    """
    from keyleak.detector import get_all_patterns

    patterns = get_all_patterns()
    use_json = ctx.obj["use_json"]

    if use_json:
        import json

        data = [
            {
                "service": p.service,
                "description": p.description,
                "prefix": p.prefix_hint,
                "min_length": p.min_length,
                "max_length": p.max_length,
            }
            for p in patterns
        ]
        click.echo(json.dumps(data, indent=2))
    else:
        from rich.table import Table

        table = Table(title="🔑 Supported Services", show_lines=True)
        table.add_column("Service", style="bold cyan")
        table.add_column("Description", style="white")
        table.add_column("Prefix", style="green")
        table.add_column("Key Length", justify="center")

        for p in patterns:
            length_str = str(p.min_length) if p.min_length == p.max_length else f"{p.min_length}–{p.max_length}"
            table.add_row(p.service, p.description, p.prefix_hint, length_str)

        console.print(table)


@main.command()
@click.pass_context
def batch(ctx: click.Context) -> None:
    """Read keys from stdin (one per line) and validate in batch.

    \b
    Examples:
        cat keys.txt | keyleak batch
        keyleak batch < collected_keys.txt
        keyleak --json batch < keys.txt > results.json
    """
    use_json = ctx.obj["use_json"]
    compact = ctx.obj["compact"]
    verbose = ctx.obj["verbose"]
    services_filter = ctx.obj["services"]

    stdin_text = _read_stdin()
    if not stdin_text.strip():
        console.print("[red]No input received. Pipe keys via stdin.[/red]")
        sys.exit(1)

    lines = [line.strip() for line in stdin_text.splitlines() if line.strip()]
    detector = KeyDetector(services=services_filter)

    detected_keys = detector.detect_batch(lines)

    if not detected_keys:
        if use_json:
            render_json([], output=sys.stdout)
        else:
            console.print("[yellow]No recognized API keys in input.[/yellow]")
        return

    if verbose:
        console.print(f"[bold]Recognized {len(detected_keys)} key(s) from {len(lines)} lines.[/bold]\n")

    results = _validate_detected_keys(detected_keys, verbose=verbose)
    _output_results(results, use_json=use_json, compact=compact)


def _process_text(
    text: str,
    use_json: bool,
    compact: bool,
    verbose: bool,
    services: Optional[List[str]],
) -> None:
    """Process text input (from stdin pipe) for keys."""
    detector = KeyDetector(services=services)
    detected_keys = detector.detect_in_text(text)

    if not detected_keys:
        if use_json:
            render_json([], output=sys.stdout)
        else:
            console.print("[yellow]No API keys detected in input.[/yellow]")
        return

    if verbose:
        console.print(f"[bold]Detected {len(detected_keys)} key(s). Validating...[/bold]\n")

    results = _validate_detected_keys(detected_keys, verbose=verbose)
    _output_results(results, use_json=use_json, compact=compact)


def _output_results(
    results: List[ValidationResult],
    use_json: bool = False,
    compact: bool = False,
    detail: bool = False,
) -> None:
    """Route results to the appropriate output renderer."""
    if use_json:
        render_json(results, output=sys.stdout)
    elif compact:
        render_compact(results, console=console)
    elif detail and len(results) == 1:
        render_details(results[0], console=console)
    else:
        render_table(results, console=console)

    # Exit with non-zero if any valid (leaked) keys found
    valid_count = sum(1 for r in results if r.is_active)
    if valid_count > 0:
        sys.exit(2)  # Signal: active leaked keys detected


if __name__ == "__main__":
    main()
