"""
WinShield+ Collector.

Portable Windows patch inventory collector for authorised hosts.

This collector preserves the original WinShield+ scan JSON contract so the
generated scan files can be fed directly into the main WinShield+ pipeline.
"""

import argparse
import json
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any


# ------------------------------------------------------------
# SCRIPT NAMES
# ------------------------------------------------------------

BASELINE_SCRIPT = "winshield_baseline.ps1"
INVENTORY_SCRIPT = "winshield_inventory.ps1"
ADAPTER_SCRIPT = "winshield_adapter.ps1"


# ------------------------------------------------------------
# PATH RESOLUTION
# ------------------------------------------------------------

def get_root_dir() -> Path:
    """
    Return the project root directory.

    Expected layout:

        WINSHIELD_COLLECTOR/
        ├── winshield_collector.bat
        ├── src/
        │   ├── core/
        │   │   ├── winshield_collector.py
        │   │   └── winshield_collector.exe
        │   └── powershell/
        │       ├── winshield_baseline.ps1
        │       ├── winshield_inventory.ps1
        │       └── winshield_adapter.ps1
        └── output/

    Source mode:
        src/core/winshield_collector.py

    EXE mode:
        src/core/winshield_collector.exe

    In both cases, the project root is two levels above the file.
    """

    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parents[2]

    return Path(__file__).resolve().parents[2]


ROOT_DIR = get_root_dir()
POWERSHELL_DIR = ROOT_DIR / "src" / "powershell"
OUTPUT_DIR = ROOT_DIR / "output"


# ------------------------------------------------------------
# BASIC HELPERS
# ------------------------------------------------------------

def relative_path(path: Path) -> str:
    """Return a project-relative path for cleaner console output."""

    try:
        return str(path.relative_to(ROOT_DIR))
    except ValueError:
        return str(path)


def ensure_required_files() -> None:
    """Validate that the required PowerShell collector scripts are present."""

    required_scripts = [
        BASELINE_SCRIPT,
        INVENTORY_SCRIPT,
        ADAPTER_SCRIPT,
    ]

    missing_scripts = [
        script_name
        for script_name in required_scripts
        if not (POWERSHELL_DIR / script_name).exists()
    ]

    if missing_scripts:
        missing = ", ".join(missing_scripts)
        raise RuntimeError(f"Missing PowerShell collector script(s): {missing}")


# ------------------------------------------------------------
# POWERSHELL EXECUTION
# ------------------------------------------------------------

def run_powershell_script(
    script_name: str,
    extra_args: list[str] | None = None,
) -> dict[str, Any]:
    """Execute a PowerShell script and return parsed JSON output."""

    script_path = POWERSHELL_DIR / script_name
    args = extra_args or []

    command = [
        "powershell.exe",
        "-NoProfile",
        "-ExecutionPolicy",
        "Bypass",
        "-File",
        str(script_path),
        *args,
    ]

    result = subprocess.run(
        command,
        capture_output=True,
        text=True,
        check=False,
    )

    if result.returncode != 0:
        error_output = result.stderr.strip() or result.stdout.strip()

        if error_output:
            raise RuntimeError(f"{script_name} failed: {error_output}")

        raise RuntimeError(f"{script_name} failed with exit code {result.returncode}")

    stdout = result.stdout.strip()

    if not stdout:
        raise RuntimeError(f"{script_name} returned no output")

    try:
        return json.loads(stdout)
    except json.JSONDecodeError as exc:
        raise RuntimeError(f"{script_name} returned invalid JSON") from exc


# ------------------------------------------------------------
# MONTH RANGE HANDLING
# ------------------------------------------------------------

def build_month_ids_from_lcu(
    baseline: dict[str, Any],
    max_months: int = 48,
) -> list[str]:
    """Build a MonthId range from installed LCU month to latest MSRC month."""

    if not baseline.get("IsAdmin"):
        raise RuntimeError("Baseline collected without administrative privileges")

    start_id = baseline.get("LcuMonthId")
    if not start_id:
        raise RuntimeError("Baseline did not provide LcuMonthId")

    end_id = baseline.get("MsrcLatestMonthId")

    end_date = (
        datetime.strptime(end_id, "%Y-%b").replace(day=1, tzinfo=UTC)
        if end_id
        else datetime.now(UTC).replace(day=1)
    )

    start_date = datetime.strptime(start_id, "%Y-%b").replace(day=1, tzinfo=UTC)

    if start_date > end_date:
        start_date = end_date

    month_ids: list[str] = []
    year = start_date.year
    month = start_date.month

    while True:
        current_date = datetime(year, month, 1, tzinfo=UTC)

        if current_date > end_date or len(month_ids) >= max_months:
            break

        month_ids.append(current_date.strftime("%Y-%b"))

        if current_date == end_date:
            break

        month += 1

        if month == 13:
            month = 1
            year += 1

    return month_ids


def chunk_list(items: list[str], size: int) -> list[list[str]]:
    """Split a list into fixed-size chunks."""

    return [items[index:index + size] for index in range(0, len(items), size)]


# ------------------------------------------------------------
# KB ENTRY MERGING
# ------------------------------------------------------------

def merge_kb_entries(
    existing: dict[str, dict[str, Any]],
    incoming: list[dict[str, Any]],
) -> None:
    """Merge MSRC adapter KB entries into an indexed KB map."""

    for entry in incoming:
        kb_id = entry.get("KB")

        if not kb_id:
            continue

        target = existing.setdefault(
            kb_id,
            {
                "KB": kb_id,
                "Months": [],
                "Cves": [],
                "Supersedes": [],
            },
        )

        for field in ("Months", "Cves", "Supersedes"):
            for value in entry.get(field) or []:
                if value and value not in target[field]:
                    target[field].append(value)


# ------------------------------------------------------------
# SUPERSEDENCE RESOLUTION
# ------------------------------------------------------------

def compute_supersedence(
    kb_entries: list[dict[str, Any]],
    installed_kbs: set[str],
) -> set[str]:
    """
    Expand logical KB presence using supersedence relationships.

    This is used only to determine MissingKbs while preserving the original
    scan JSON output structure.
    """

    supersedes_map: dict[str, set[str]] = {}

    for entry in kb_entries:
        kb_id = entry.get("KB")

        if not kb_id:
            continue

        for superseded_kb in entry.get("Supersedes") or []:
            supersedes_map.setdefault(kb_id, set()).add(superseded_kb)

    logical_present_kbs = set(installed_kbs)

    for root_kb in installed_kbs:
        stack = [root_kb]
        seen = {root_kb}

        while stack:
            current_kb = stack.pop()

            for superseded_kb in supersedes_map.get(current_kb, set()):
                logical_present_kbs.add(superseded_kb)

                if superseded_kb not in seen:
                    seen.add(superseded_kb)
                    stack.append(superseded_kb)

    return logical_present_kbs


# ------------------------------------------------------------
# SCAN COLLECTION
# ------------------------------------------------------------

def collect_scan(max_months: int = 48) -> dict[str, Any]:
    """
    Collect baseline, inventory, and MSRC KB data.

    The returned object intentionally matches the original WinShield+ scan
    schema used by the downstream pipeline:

        Baseline
        InstalledKbs
        MonthsRequested
        KbEntries
        MissingKbs
    """

    baseline = run_powershell_script(BASELINE_SCRIPT)

    product_name_hint = baseline.get("ProductNameHint")
    if not product_name_hint:
        raise RuntimeError("ProductNameHint could not be resolved")

    inventory = run_powershell_script(INVENTORY_SCRIPT)
    installed_kbs = set(inventory.get("AllInstalledKbs") or [])

    month_ids = build_month_ids_from_lcu(
        baseline=baseline,
        max_months=max_months,
    )

    merged_entries: dict[str, dict[str, Any]] = {}

    for month_chunk in chunk_list(month_ids, 3):
        msrc_data = run_powershell_script(
            ADAPTER_SCRIPT,
            extra_args=[
                "-MonthIds",
                ",".join(month_chunk),
                "-ProductNameHint",
                product_name_hint,
            ],
        )

        entries = msrc_data.get("KbEntries") or []
        merge_kb_entries(merged_entries, entries)

    kb_entries = list(merged_entries.values())

    for entry in kb_entries:
        entry["Months"] = sorted(set(entry.get("Months") or []))
        entry["Cves"] = sorted(set(entry.get("Cves") or []))
        entry["Supersedes"] = sorted(set(entry.get("Supersedes") or []))

    logical_present_kbs = compute_supersedence(
        kb_entries=kb_entries,
        installed_kbs=installed_kbs,
    )

    expected_kbs = {
        entry["KB"]
        for entry in kb_entries
        if entry.get("KB")
    }

    missing_kbs = sorted(expected_kbs - logical_present_kbs)

    scan_result = {
        "Baseline": baseline,
        "InstalledKbs": sorted(installed_kbs),
        "MonthsRequested": month_ids,
        "KbEntries": sorted(kb_entries, key=lambda item: item["KB"]),
        "MissingKbs": missing_kbs,
    }

    return scan_result


# ------------------------------------------------------------
# EXPORT
# ------------------------------------------------------------

def export_scan(scan_result: dict[str, Any]) -> Path:
    """Write the collected scan using the original WinShield+ filename format."""

    OUTPUT_DIR.mkdir(parents=True, exist_ok=True)

    timestamp = datetime.now(UTC).strftime("%Y%m%d_%H%M%S")
    output_path = OUTPUT_DIR / f"scan_{timestamp}.json"

    with output_path.open("w", encoding="utf-8") as file:
        json.dump(scan_result, file, indent=2)

    return output_path


# ------------------------------------------------------------
# COMMAND LINE
# ------------------------------------------------------------

def parse_args() -> argparse.Namespace:
    """Parse command-line arguments."""

    parser = argparse.ArgumentParser(
        description="Collect Windows patch inventory data and export WinShield+ scan JSON.",
    )

    parser.add_argument(
        "--max-months",
        type=int,
        default=48,
        help="Maximum number of MSRC months to query from the LCU month onward.",
    )

    parser.add_argument(
        "--quiet",
        action="store_true",
        help="Suppress success output. Errors are still printed to stderr.",
    )

    return parser.parse_args()


# ------------------------------------------------------------
# MAIN WORKFLOW
# ------------------------------------------------------------

def main() -> int:
    """Run the WinShield+ Collector workflow."""

    args = parse_args()

    try:
        ensure_required_files()

        scan_result = collect_scan(max_months=args.max_months)
        output_path = export_scan(scan_result)

        if not args.quiet:
            print(f"Scan completed: {relative_path(output_path)}")

        return 0

    except Exception as exc:
        print(f"Collector failed: {exc}", file=sys.stderr)
        return 1


# ------------------------------------------------------------
# ENTRY POINT
# ------------------------------------------------------------

if __name__ == "__main__":
    raise SystemExit(main())