"""Exit code translation and signal mapping."""

EXIT_CODE_MAP = {
    0: ("Success", "Container exited normally."),
    1: ("Error", "Generic application error."),
    2: ("Misuse", "Shell built-in misuse (e.g., missing command)."),
    126: ("NotExecutable", "Command found but not executable."),
    127: ("NotFound", "Command not found."),
    128: ("InvalidExit", "Invalid exit argument."),
    130: ("SIGINT (128+2)", "Container interrupted (Ctrl+C or kill -2)."),
    134: ("SIGABRT (128+6)", "Process aborted — assertion failure or Environment.FailFast()."),
    137: ("SIGKILL (128+9)", "External kill — OOMKill, kubectl delete, rollout, or liveness probe timeout."),
    139: ("SIGSEGV (128+11)", "Segmentation fault — invalid memory access in native code."),
    143: ("SIGTERM (128+15)", "Graceful termination requested (preStop hook, pod deletion)."),
    255: ("ExitOutOfRange", "Exit code out of range or unknown error."),
}


def translate_exit_code(code: int) -> dict:
    """Translate a container exit code to human-readable explanation."""
    if code in EXIT_CODE_MAP:
        signal_name, description = EXIT_CODE_MAP[code]
        return {
            "exit_code": code,
            "signal": signal_name,
            "description": description,
            "is_crash": code not in (0, 143),
            "is_oom_possible": code == 137,
            "is_segfault": code == 139,
        }

    # Handle unknown signal-based exit codes (128 + signal)
    if 128 < code < 165:
        signal_num = code - 128
        return {
            "exit_code": code,
            "signal": f"Signal {signal_num} (128+{signal_num})",
            "description": f"Container killed by signal {signal_num}.",
            "is_crash": True,
            "is_oom_possible": False,
            "is_segfault": False,
        }

    return {
        "exit_code": code,
        "signal": "Unknown",
        "description": f"Non-standard exit code {code}.",
        "is_crash": code != 0,
        "is_oom_possible": False,
        "is_segfault": False,
    }


def determine_kill_actor(event: dict) -> str:
    """Determine who/what killed the container based on audit log event."""
    username = event.get("user", {}).get("username", "")

    if "replicaset-controller" in username:
        return "replicaset-controller (deployment rollout or scale-down)"
    elif "deployment-controller" in username:
        return "deployment-controller (rollout)"
    elif "job-controller" in username:
        return "job-controller (job completion)"
    elif "system:node:" in username:
        return "kubelet (container crash, liveness probe failure, or OOMKill)"
    elif "system:serviceaccount:" in username:
        return f"service account: {username}"
    else:
        return f"user: {username}"
