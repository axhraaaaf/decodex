"""CLI wrapper for the framework."""

import argparse
import dataclasses
import json
from pathlib import Path

from decodeX.core.analyze_tools import (
    DEFAULT_MIN_STRING_LENGTH,
    DEFAULT_STRING_LIMIT,
    analyze_file,
    build_structured_report,
    print_analysis,
)
from decodeX.framework.engine import Engine
from decodeX.framework.plugin_manager import PluginManager
from decodeX.utils import print_error, print_info


def register_framework_commands(subparsers: argparse._SubParsersAction) -> None:
    """Register framework CLI commands."""
    # 1. plugins list
    plugins_parser = subparsers.add_parser("decodeX.plugins", help="Manage plugins.")
    plugins_subparsers = plugins_parser.add_subparsers(dest="plugin_cmd")
    
    list_parser = plugins_subparsers.add_parser("list", help="List all enabled plugins.")
    list_parser.set_defaults(handler=handle_plugins_list)
    
    # 2. plugin <name> <target>
    plugin_parser = subparsers.add_parser("plugin", help="Run a specific plugin.")
    plugin_parser.add_argument("name", help="Name of the plugin to run.")
    plugin_parser.add_argument("target", help="Target file to analyze.")
    plugin_parser.set_defaults(handler=handle_plugin_run)
    
    analyze_parser = subparsers.add_parser(
        "analyze",
        help="Run structured PE/static triage and emit analyst-ready JSON.",
    )
    analyze_parser.add_argument("target", help="Target file to analyze.")
    analyze_parser.add_argument(
        "--min-string",
        type=int,
        default=DEFAULT_MIN_STRING_LENGTH,
        help=f"Minimum printable string length (default: {DEFAULT_MIN_STRING_LENGTH}).",
    )
    analyze_parser.add_argument(
        "-s",
        "--strings",
        type=int,
        default=DEFAULT_STRING_LIMIT,
        help=f"Maximum extracted strings to display (default: {DEFAULT_STRING_LIMIT}).",
    )
    analyze_parser.add_argument(
        "--json-stdout",
        action="store_true",
        help="Print the full JSON report to stdout instead of a compact summary.",
    )
    analyze_parser.add_argument(
        "-o",
        "--output",
        help="Path to save the JSON report. Defaults to <target>.report.json",
    )
    analyze_parser.set_defaults(handler=handle_analyze_all)

    risk_parser = subparsers.add_parser(
        "risk",
        help="Run high-level risk assessment on a file.",
    )
    risk_parser.add_argument("target", help="Target file to assess.")
    risk_parser.add_argument(
        "--json",
        action="store_true",
        help="Output the result as JSON.",
    )
    risk_parser.set_defaults(handler=handle_risk_assessment)

    auto_parser = subparsers.add_parser(
        "auto",
        help="Full automatic detection and recursive decoding suite.",
    )
    auto_parser.add_argument("input", help="The string to decode automatically.")
    auto_parser.add_argument(
        "--json",
        action="store_true",
        help="Output the result as JSON.",
    )
    auto_parser.set_defaults(handler=handle_auto_decode)

    triage_parser = subparsers.add_parser(
        "triage",
        help="Coordinated malware deobfuscation and IOC extraction.",
    )
    triage_parser.add_argument("target", help="Target file or payload to triage.")
    triage_parser.add_argument(
        "--json",
        action="store_true",
        help="Output the result as JSON.",
    )
    triage_parser.set_defaults(handler=handle_triage)


def handle_triage(args: argparse.Namespace) -> int:
    """Handle coordinated malware triage using SmartDecodePlugin."""
    try:
        from decodeX.plugins.smart_decode_plugin import SmartDecodePlugin
        plugin = SmartDecodePlugin()
        result = plugin.analyze(args.target)
        
        if getattr(args, "json", False):
            print(json.dumps(result, indent=2, default=str))
            return 0

        print_info(f"Analyzing: [bold cyan]{args.target}[/bold cyan]")
        
        from rich.panel import Panel
        from rich.table import Table
        from decodeX.utils.console import console
        
        # Summary Panel
        summary_table = Table.grid(padding=(0, 2))
        summary_table.add_row("Malware Score:", f"[bold red]{result.get('malware_score', 0)}/100[/bold red]")
        summary_table.add_row("Confidence:", f"{int(result.get('confidence', 0) * 100)}%")
        summary_table.add_row("Entropy:", f"{result.get('entropy', 'N/A')}")
        
        console.print(Panel(summary_table, title="[bold red]Malware Triage Summary[/bold red]", border_style="red"))

        if result.get("malware_indicators"):
            ind_table = Table(title="Malware Indicators", show_header=False, border_style="red")
            for ind in result["malware_indicators"]:
                ind_table.add_row(f"[bold red][!] {ind}[/bold red]")
            console.print(ind_table)
                
        if result.get("iocs"):
            ioc_table = Table(title="Extracted IOCs", border_style="yellow")
            ioc_table.add_column("Category", style="cyan")
            ioc_table.add_column("Value", style="white")
            for category, items in result["iocs"].items():
                for item in items:
                    ioc_table.add_row(category.upper(), item)
            console.print(ioc_table)
                    
        console.print(Panel(result.get("tree_view", "  (No transformations)"), title="[bold cyan]Transformation Path[/bold cyan]", border_style="cyan"))
        
        preview = result.get("final_output", "N/A")
        console.print(Panel(preview[:2000], title="[bold green]Final Decoded Payload[/bold green]", border_style="green"))

        return 0
    except Exception as e:
        print_error(f"Triage error: {e}")
        return 1


def handle_risk_assessment(args: argparse.Namespace) -> int:
    """Handle independent risk assessment."""
    from decodeX.core.risk_engine import calculate_risk
    try:
        analysis = analyze_file(args.target, string_limit=10)
        results = calculate_risk(build_structured_report(analysis))
        
        if getattr(args, "json", False):
            print(json.dumps(results, indent=2))
        else:
            print_info(f"Risk Assessment for: {args.target}")
            print(f"Score: {results['risk_score']}/100")
            print(f"Verdict: {results['verdict']}")
            print("\nBreakdown:")
            for item in results.get("breakdown", []):
                print(f"  - [{item['score']}] {item['component']}: {item['description']}")
                
        return 0
    except Exception as e:
        print_error(f"Risk assessment error: {e}")
        return 1


def handle_plugins_list(args: argparse.Namespace) -> int:
    manager = PluginManager()
    plugins = manager.load_plugins()
    if not plugins:
        print_info("No plugins found.")
        return 0
        
    print_info(f"Loaded {len(plugins)} plugins:")
    rows = []
    for p in plugins:
        rows.append((p.name, p.version, p.description))
        
    # We can use print_key_value_table or just print
    for name, version, desc in rows:
        print(f"  - {name} (v{version}): {desc}")
        
    return 0


def handle_plugin_run(args: argparse.Namespace) -> int:
    engine = Engine(PluginManager())
    # Retrieve plugin using PluginManager instead of Engine, because Engine no longer has get_plugin
    manager = engine.plugin_manager
    plugin = manager.get_plugin(args.name)
    if not plugin:
        print_error(f"Plugin '{args.name}' not found.")
        return 1
        
    try:
        result = plugin.analyze(args.target)
        print(json.dumps({args.name: result}, indent=2, default=str))
        return 0
    except Exception as e:
        print_error(f"Error running plugin '{args.name}': {e}")
        return 1



def _inject_pe_findings(results: dict, plugin_results: list) -> None:
    """Surface high-fidelity PE fields from PEPlugin into the structured report.

    Injects into results["analysis"]["high_value_findings"] and
    results["file_summary"] without altering their structure.
    """
    pe_result = None
    for entry in plugin_results:
        if entry.get("plugin") == "pe":
            pe_result = entry.get("result", {})
            break

    if not pe_result or pe_result.get("error"):
        return

    hvf = results.setdefault("analysis", {}).setdefault("high_value_findings", [])

    # 1. Imphash — high analyst value for malware family clustering
    imphash = pe_result.get("imphash")
    if imphash:
        results["file_summary"]["imphash"] = imphash
        hvf.append({
            "finding": "import hash (imphash)",
            "evidence": imphash,
            "priority": "medium",
        })

    # 2. Suspicious imports with category labels from pefile-level IAT walk
    suspicious_imports = pe_result.get("suspicious_imports", [])
    if suspicious_imports:
        hvf.append({
            "finding": "high-risk API imports (verified IAT)",
            "evidence": "; ".join(suspicious_imports[:6])
                        + (f" (+{len(suspicious_imports) - 6} more)" if len(suspicious_imports) > 6 else ""),
            "priority": "high",
        })

    # 3. RWX / W+X sections — strong packing / shellcode indicator
    rwx_sections = [
        s["name"] for s in pe_result.get("sections", [])
        if "Executable and Writable" in " ".join(pe_result.get("findings", []))
        and s["name"] in " ".join(pe_result.get("findings", []))
    ]
    # Simpler: scan findings for the flag text
    rwx_findings = [f for f in pe_result.get("findings", []) if "Executable and Writable" in f]
    if rwx_findings:
        hvf.append({
            "finding": "writable+executable section (RWX)",
            "evidence": "; ".join(rwx_findings),
            "priority": "high",
        })

    # 4. Overlay data — common in droppers / self-extractors
    overlay_size = pe_result.get("overlay_size", 0)
    if overlay_size > 1024:
        hvf.append({
            "finding": "overlay data appended to PE",
            "evidence": f"{overlay_size:,} bytes of data past the last section",
            "priority": "high",
        })

    # 5. Expose architecture in file_summary for convenience
    if pe_result.get("architecture") and pe_result["architecture"] != "Unknown":
        results["file_summary"]["architecture"] = pe_result["architecture"]


def handle_analyze_all(args: argparse.Namespace) -> int:
    try:
        Target = Path(args.target)
        output_path = Path(args.output) if args.output else Target.with_name(f"{Target.name}.report.json")
        
        analysis = analyze_file(
            args.target,
            string_limit=None,
            min_string_length=args.min_string,
        )
        
        results = build_structured_report(analysis)
        
        # Integrate plugin system results
        try:
            engine = Engine(PluginManager())
    
            plugin_results = engine.analyze(args.target)
            results["decodeX.plugins"] = plugin_results
            
            # Surface high-fidelity PE findings from PEPlugin into the report
            _inject_pe_findings(results, plugin_results)

            # Re-calculate risk score based on plugin findings
            from decodeX.core.risk_engine import calculate_risk
            risk_update = calculate_risk(results)
            
            # Use safe update to ensure we don't crash if something is missing
            results["file_summary"].update({
                "risk_score": risk_update.get("risk_score", results["file_summary"].get("risk_score", 0)),
                "verdict": risk_update.get("verdict", results["file_summary"].get("verdict", "Unknown")),
                "risk_level": f"{risk_update.get('verdict', 'Unknown')} ({risk_update.get('risk_score_10', 0)}/10)"
            })
        except Exception as e:
            results["plugins_error"] = str(e)
            
        output_path.write_text(json.dumps(results, indent=2))
        
        if args.json_stdout:
            print(json.dumps(results, indent=2))
        else:
            limited_strings = analysis.strings[:args.strings]
            compact_analysis = dataclasses.replace(analysis, strings=limited_strings)
            print_analysis(
                compact_analysis,
                risk_score=results["file_summary"]["risk_score"],
                verdict=results["file_summary"]["verdict"],
                categorized_strings=results.get("strings"),
            )
            print_info(f"\nFull JSON report saved to: {output_path}")
            
        return 0
    except Exception as e:
        print_error(f"Error running structured analysis: {e}")
        return 1


def handle_auto_decode(args: argparse.Namespace) -> int:
    """Handle automatic decoding of a string using the next-gen SmartDecodePlugin."""
    try:
        from rich.panel import Panel
        from rich.table import Table
        from decodeX.utils.console import console, print_info
        
        from decodeX.plugins.smart_decode_plugin import SmartDecodePlugin
        plugin = SmartDecodePlugin()
        result = plugin.analyze(args.input)
        
        if getattr(args, "json", False):
            print(json.dumps(result, indent=2, default=str))
            return 0

        print_info(f"Input: [bold yellow]{args.input}[/bold yellow]")
        
        # Stats Table
        stats = Table.grid(padding=(0, 2))
        stats.add_row("Readability:", f"[bold green]{result.get('readability_score', 0):.4f}[/bold green]")
        stats.add_row("Confidence:", f"[bold cyan]{int(result.get('confidence', 0) * 100)}%[/bold cyan]")
        stats.add_row("Entropy:", f"{result.get('entropy', 'N/A')}")
        
        console.print(Panel(stats, title="[bold cyan]Analysis Metrics[/bold cyan]", border_style="cyan", expand=False))
        
        # Tree View
        console.print(Panel(result.get("tree_view", "  (No transformations detected)"), title="[bold magenta]Decoding Path[/bold magenta]", border_style="magenta"))
        
        # Findings
        if result.get("findings"):
            f_table = Table(show_header=False, border_style="yellow", box=None)
            for f in result["findings"]:
                f_table.add_row(f"[yellow][{f['severity']}][/yellow]", f"[bold]{f['title']}[/bold]", f"[dim]{f['evidence']}[/dim]")
            console.print(Panel(f_table, title="[bold yellow]Heuristic Findings[/bold yellow]", border_style="yellow"))

        # Final Result
        console.print(Panel(result.get("final_output", "N/A"), title="[bold green]Final Result[/bold green]", border_style="green"))

        return 0
    except Exception as e:
        print_error(f"Auto-decode error: {e}")
        return 1
