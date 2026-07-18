"""CloudWatch Logs Insights query builder for EKS audit logs."""

from datetime import datetime, timedelta


def build_pod_lifecycle_query(pod_name: str, exact: bool = False) -> str:
    """Build a query to get the full lifecycle of a specific pod.
    If exact=False, uses 'like' for partial matching (e.g., 'orderservice' matches all pods).
    """
    if exact:
        return f"""fields @timestamp, @message
| filter objectRef.name = "{pod_name}"
| sort @timestamp asc"""
    return f"""fields @timestamp, @message
| filter objectRef.name like /{pod_name}/
| sort @timestamp asc"""


def build_pod_termination_query(pod_name: str, exact: bool = False) -> str:
    """Build a query to find termination events for a pod.
    If exact=False, uses 'like' for partial matching.
    Uses @message string matching since CW Logs Insights can't filter nested JSON fields directly.
    """
    if exact:
        return f"""fields @timestamp, @message
| filter @message like /"{pod_name}"/ and @message like /"terminated"/
| sort @timestamp asc"""
    return f"""fields @timestamp, @message
| filter @message like /{pod_name}/ and @message like /"terminated"/
| sort @timestamp asc"""


def build_crash_scan_query(exit_code: int = 139) -> str:
    """Build a query to find all containers that exited with a specific code."""
    return f"""fields @timestamp, @message
| filter @message like /"exitCode":{exit_code}/
| parse @message /objectRef.*?"name":"(?<pod_name>[^"]+)"/
| parse @message /finishedAt":"(?<finished_at>[^"]+)"/
| parse @message /"startedAt":"(?<started_at>[^"]+)"/
| sort @timestamp desc
| limit 100"""


def build_all_crashes_query(service_name: str = None) -> str:
    """Build a query to find all non-zero exit codes, optionally filtered by service."""
    base = """fields @timestamp, @message
| filter @message like /"terminated"/ and @message like /"exitCode"/"""

    if service_name:
        base += f' and @message like /{service_name}/'

    base += """
| parse @message /objectRef.*?"name":"(?<pod_name>[^"]+)"/
| parse @message /"exitCode":(?<exit_code>\\d+)/
| parse @message /finishedAt":"(?<finished_at>[^"]+)"/
| sort @timestamp desc
| limit 200"""
    return base


def build_restart_events_query(pod_name: str, time_start: str, time_end: str) -> str:
    """Build a query to find restart-related events in a specific time window."""
    return f"""fields @timestamp, @message
| filter objectRef.name = "{pod_name}" and verb = "patch"
  and @timestamp >= "{time_start}" and @timestamp <= "{time_end}"
| sort @timestamp asc"""


def get_log_group_name(cluster_name: str) -> str:
    """Get the CloudWatch log group name for an EKS cluster."""
    return f"/aws/eks/{cluster_name}/cluster"


def calculate_time_range(hours_back: int = 24) -> tuple[int, int]:
    """Calculate start/end timestamps in epoch milliseconds."""
    end = datetime.utcnow()
    start = end - timedelta(hours=hours_back)
    return int(start.timestamp() * 1000), int(end.timestamp() * 1000)
