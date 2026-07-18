"""Parse raw audit log JSON into structured pod lifecycle events."""

import json
from datetime import datetime


def parse_container_status(container_status: dict) -> dict:
    """Extract meaningful info from a containerStatus object."""
    result = {
        "name": container_status.get("name"),
        "image": container_status.get("image"),
        "restart_count": container_status.get("restartCount", 0),
        "ready": container_status.get("ready"),
        "started": container_status.get("started"),
        "container_id": container_status.get("containerID"),
    }

    # Current state
    state = container_status.get("state", {})
    if "running" in state:
        result["state"] = "running"
        result["started_at"] = state["running"].get("startedAt")
    elif "terminated" in state:
        result["state"] = "terminated"
        result["exit_code"] = state["terminated"].get("exitCode")
        result["reason"] = state["terminated"].get("reason")
        result["started_at"] = state["terminated"].get("startedAt")
        result["finished_at"] = state["terminated"].get("finishedAt")
    elif "waiting" in state:
        result["state"] = "waiting"
        result["reason"] = state["waiting"].get("reason")

    # Previous state
    last_state = container_status.get("lastState", {})
    if "terminated" in last_state:
        result["last_exit_code"] = last_state["terminated"].get("exitCode")
        result["last_reason"] = last_state["terminated"].get("reason")
        result["last_started_at"] = last_state["terminated"].get("startedAt")
        result["last_finished_at"] = last_state["terminated"].get("finishedAt")

    return result


def parse_audit_event(raw_message: str) -> dict:
    """Parse a raw audit log message into a structured event."""
    try:
        event = json.loads(raw_message)
    except json.JSONDecodeError:
        return {"error": "Failed to parse JSON", "raw": raw_message[:200]}

    parsed = {
        "timestamp": event.get("requestReceivedTimestamp"),
        "verb": event.get("verb"),
        "actor": event.get("user", {}).get("username", "unknown"),
        "resource": event.get("objectRef", {}).get("resource"),
        "pod_name": event.get("objectRef", {}).get("name"),
        "namespace": event.get("objectRef", {}).get("namespace"),
        "response_code": event.get("responseStatus", {}).get("code"),
    }

    # Extract container statuses from the request object (for patch events)
    request_obj = event.get("requestObject", {})
    status = request_obj.get("status", {})
    container_statuses = status.get("containerStatuses", [])

    if container_statuses:
        parsed["containers"] = [
            parse_container_status(cs) for cs in container_statuses
        ]

    # Extract phase
    if "phase" in status:
        parsed["phase"] = status["phase"]

    # Extract conditions
    conditions = status.get("conditions", [])
    if conditions:
        parsed["conditions"] = [
            {
                "type": c.get("type"),
                "status": c.get("status"),
                "reason": c.get("reason"),
                "message": c.get("message"),
            }
            for c in conditions
        ]

    return parsed


def calculate_runtime(started_at: str, finished_at: str) -> str:
    """Calculate human-readable runtime duration."""
    try:
        start = datetime.fromisoformat(started_at.replace("Z", "+00:00"))
        end = datetime.fromisoformat(finished_at.replace("Z", "+00:00"))
        delta = end - start
        hours, remainder = divmod(int(delta.total_seconds()), 3600)
        minutes, seconds = divmod(remainder, 60)

        if hours > 24:
            days = hours // 24
            hours = hours % 24
            return f"{days}d {hours}h {minutes}m"
        elif hours > 0:
            return f"{hours}h {minutes}m {seconds}s"
        elif minutes > 0:
            return f"{minutes}m {seconds}s"
        else:
            return f"{seconds}s"
    except (ValueError, TypeError):
        return "unknown"
