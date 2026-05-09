"""
windows_task_scanner.py — Detect scheduled task privilege escalation vectors.

Checks:
  - Scheduled tasks running as SYSTEM with writable binaries
  - Scheduled tasks running as SYSTEM with writable script paths
  - Tasks with writable directories in their action paths
  - Tasks using missing/deleted executables
"""

import subprocess
import os


def _run_powershell(script: str, timeout: int = 30) -> str:
    try:
        r = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command", script],
            capture_output=True, text=True, timeout=timeout,
            encoding="utf-8", errors="replace",
        )
        return r.stdout.strip()
    except Exception:
        return ""


def _is_writable(path: str) -> bool:
    try:
        return os.path.exists(path) and os.access(path, os.W_OK)
    except Exception:
        return False


def _get_scheduled_tasks() -> list[dict]:
    """Retrieve scheduled tasks with their action paths and run-as accounts."""
    script = """
Get-ScheduledTask | ForEach-Object {
    $task = $_
    foreach ($action in $task.Actions) {
        [PSCustomObject]@{
            TaskName    = $task.TaskName
            TaskPath    = $task.TaskPath
            RunAs       = ($task.Principal.UserId)
            RunLevel    = ($task.Principal.RunLevel)
            Execute     = $action.Execute
            Arguments   = $action.Arguments
            State       = $task.State
        }
    }
} | ConvertTo-Json -Depth 2
"""
    raw = _run_powershell(script)
    if not raw:
        return []

    import json
    try:
        tasks = json.loads(raw)
        if isinstance(tasks, dict):
            tasks = [tasks]
        return tasks if isinstance(tasks, list) else []
    except json.JSONDecodeError:
        return []


def _resolve_exe(execute: str) -> str:
    """Resolve execute path, expanding environment variables."""
    if not execute:
        return ""
    try:
        expanded = os.path.expandvars(execute)
        return expanded.strip().strip('"')
    except Exception:
        return execute


def run(verbose: bool = False) -> list[dict]:
    """Entry point — returns list of scheduled task privilege escalation findings."""
    if verbose:
        print("[*] Scanning scheduled tasks for privilege escalation vectors...")

    findings: list[dict] = []
    tasks = _get_scheduled_tasks()

    if verbose:
        print(f"    Retrieved {len(tasks)} scheduled task action(s).")

    checked_exes: set = set()

    for task in tasks:
        name     = str(task.get("TaskName", "") or "")
        path     = str(task.get("TaskPath", "") or "")
        # RunAs / RunLevel / State may be int enums when deserialised from ConvertTo-Json
        run_as    = str(task.get("RunAs",    "") or "")
        run_level = str(task.get("RunLevel", "") or "")
        execute   = str(task.get("Execute",  "") or "")
        state     = str(task.get("State",    "") or "")

        # Only care about tasks running with elevated context
        # RunLevel 1 == "Highest" in the Task Scheduler enum
        is_privileged = (
            "system" in run_as.lower()
            or "administrator" in run_as.lower()
            or run_level.lower() == "highest"
            or run_level == "1"
        )
        if not is_privileged:
            continue

        exe = _resolve_exe(execute)
        if not exe or exe in checked_exes:
            continue
        checked_exes.add(exe)

        # Check 1: Executable is writable
        if os.path.isfile(exe) and _is_writable(exe):
            findings.append({
                "category": "Windows Scheduled Tasks",
                "type": "Writable Task Executable",
                "severity": "CRITICAL",
                "description": (
                    f"Scheduled task '{name}' runs as '{run_as}' and its executable "
                    f"'{exe}' is writable by the current user. Overwriting this binary "
                    "will execute arbitrary code at the next task trigger."
                ),
                "mitigation": (
                    f"Fix permissions on '{exe}': "
                    f'icacls "{exe}" /inheritance:d /grant:r "Administrators:(F)" /remove "Users"'
                ),
                "details": {
                    "task_name": name,
                    "task_path": path,
                    "run_as": run_as,
                    "executable": exe,
                    "state": state,
                },
            })

        # Check 2: Executable's directory is writable (DLL hijacking opportunity)
        exe_dir = os.path.dirname(exe)
        if exe_dir and os.path.isdir(exe_dir) and _is_writable(exe_dir):
            if not any(s.lower() in exe_dir.lower() for s in ["system32", r"c:\windows"]):
                findings.append({
                    "category": "Windows Scheduled Tasks",
                    "type": "Writable Task Binary Directory",
                    "severity": "HIGH",
                    "description": (
                        f"Scheduled task '{name}' runs as '{run_as}'. Its binary "
                        f"directory '{exe_dir}' is writable. A malicious DLL can be "
                        "planted here to hijack the task's DLL search order."
                    ),
                    "mitigation": (
                        f"Restrict write access to '{exe_dir}' for non-admin users."
                    ),
                    "details": {
                        "task_name": name,
                        "run_as": run_as,
                        "directory": exe_dir,
                    },
                })

        # Check 3: Executable path does not exist
        if not os.path.exists(exe) and exe and not exe.startswith("%"):
            findings.append({
                "category": "Windows Scheduled Tasks",
                "type": "Missing Task Executable",
                "severity": "HIGH",
                "description": (
                    f"Scheduled task '{name}' runs as '{run_as}' but its executable "
                    f"'{exe}' does not exist. If the directory is writable, a malicious "
                    "binary can be planted at that path."
                ),
                "mitigation": (
                    f"Remove or update the scheduled task '{name}' to point to a valid "
                    "executable, or disable the task if it is no longer needed."
                ),
                "details": {
                    "task_name": name,
                    "task_path": path,
                    "run_as":    run_as,
                    "executable": exe,
                    "state":     state,
                },
            })

    return findings
