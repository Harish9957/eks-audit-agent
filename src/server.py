"""EKS Audit Agent — MCP Server for CloudWatch audit log analysis."""

import asyncio
import json
import logging
import re
from datetime import datetime, timedelta, timezone

import boto3
from botocore.exceptions import ClientError, BotoCoreError
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent

from .parsers.exit_codes import translate_exit_code, determine_kill_actor
from .parsers.queries import (
    build_pod_termination_query,
    build_crash_scan_query,
    build_all_crashes_query,
    get_log_group_name,
)
from .parsers.audit_log import parse_audit_event, parse_container_status, calculate_runtime

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("eks-audit-agent")

server = Server("eks-audit-agent")

# Input validation
SAFE_NAME_PATTERN = re.compile(r'^[a-zA-Z0-9][a-zA-Z0-9._-]{0,252}$')
MAX_HOURS_BACK = 720  # 30 days


def validate_name(value: str, field: str) -> str:
    """Validate that input contains only safe characters."""
    if not SAFE_NAME_PATTERN.match(value):
        raise ValueError(f"Invalid {field}: must be alphanumeric with hyphens/dots/underscores, max 253 chars.")
    return value


async def run_insights_query(cluster: str, query: str, hours_back: int = 24, region: str = "us-east-1") -> list[dict]:
    """Execute a CloudWatch Logs Insights query and return results."""
    hours_back = min(hours_back, MAX_HOURS_BACK)

    try:
        client = boto3.client("logs", region_name=region)
        log_group = get_log_group_name(cluster)

        end_time = int(datetime.now(timezone.utc).timestamp())
        start_time = int((datetime.now(timezone.utc) - timedelta(hours=hours_back)).timestamp())

        response = client.start_query(
            logGroupName=log_group,
            startTime=start_time,
            endTime=end_time,
            queryString=query,
            limit=100,
        )

        query_id = response["queryId"]

        # Poll for results with timeout (max 60s)
        max_polls = 60
        for _ in range(max_polls):
            result = client.get_query_results(queryId=query_id)
            if result["status"] in ("Complete", "Failed", "Cancelled"):
                break
            await asyncio.sleep(1)
        else:
            logger.warning(f"Query timed out after {max_polls}s for cluster={cluster}")
            return []

        if result["status"] != "Complete":
            logger.warning(f"Query failed with status: {result['status']}")
            return []

        return result.get("results", [])

    except ClientError as e:
        error_code = e.response["Error"]["Code"]
        if error_code == "ResourceNotFoundException":
            logger.error(f"Log group not found for cluster '{cluster}'. Ensure audit logging is enabled.")
        elif error_code == "LimitExceededException":
            logger.error("CloudWatch concurrent query limit reached. Try again shortly.")
        else:
            logger.error(f"AWS error: {e}")
        return []
    except (BotoCoreError, Exception) as e:
        logger.error(f"Failed to query CloudWatch: {e}")
        return []


@server.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="diagnose_restart",
            description="Diagnose why a pod restarted. Accepts either a full pod name (podA-xxxx-xxxx) or just the service name (orderservice) — both work. Queries EKS CloudWatch audit logs to find the exit code, termination reason, actor, and provides a human-readable explanation.",
            inputSchema={
                "type": "object",
                "properties": {
                    "pod_name": {"type": "string", "description": "Pod name or service name (e.g., 'orderservice' or 'podA-xxxx-xxxx')"},
                    "cluster": {"type": "string", "description": "EKS cluster name (e.g., PRODUCTION)"},
                    "region": {"type": "string", "description": "AWS region (e.g., us-east-1)", "default": "us-east-1"},
                    "hours_back": {"type": "integer", "description": "How many hours back to search", "default": 168},
                },
                "required": ["pod_name", "cluster"],
            },
        ),
        Tool(
            name="find_crashes",
            description="Find all container crashes (non-zero exit codes) in a cluster. Optionally filter by service name or specific exit code.",
            inputSchema={
                "type": "object",
                "properties": {
                    "cluster": {"type": "string", "description": "EKS cluster name (e.g., PRODUCTION)"},
                    "region": {"type": "string", "description": "AWS region", "default": "us-east-1"},
                    "service_name": {"type": "string", "description": "Filter by service name (e.g., orderservice)"},
                    "exit_code": {"type": "integer", "description": "Filter by specific exit code (e.g., 139 for SIGSEGV)"},
                    "hours_back": {"type": "integer", "description": "How many hours back to search", "default": 168},
                },
                "required": ["cluster"],
            },
        ),
        Tool(
            name="get_pod_lifecycle",
            description="Get the full lifecycle timeline of a pod from creation to deletion, showing all state transitions.",
            inputSchema={
                "type": "object",
                "properties": {
                    "pod_name": {"type": "string", "description": "The pod name"},
                    "cluster": {"type": "string", "description": "EKS cluster name"},
                    "region": {"type": "string", "description": "AWS region", "default": "us-east-1"},
                    "hours_back": {"type": "integer", "description": "How many hours back to search", "default": 168},
                },
                "required": ["pod_name", "cluster"],
            },
        ),
        Tool(
            name="explain_exit_code",
            description="Translate a container exit code into a human-readable explanation with diagnosis guidance.",
            inputSchema={
                "type": "object",
                "properties": {
                    "exit_code": {"type": "integer", "description": "The container exit code (e.g., 139)"},
                },
                "required": ["exit_code"],
            },
        ),
    ]


@server.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:
    try:
        if name == "explain_exit_code":
            code = arguments["exit_code"]
            result = translate_exit_code(code)
            output = f"""Exit Code: {code}
Signal: {result['signal']}
Description: {result['description']}
Is Crash: {result['is_crash']}
OOM Possible: {result['is_oom_possible']}
Segfault: {result['is_segfault']}"""
            return [TextContent(type="text", text=output)]

        elif name == "diagnose_restart":
            pod_name = validate_name(arguments["pod_name"], "pod_name")
            cluster = validate_name(arguments["cluster"], "cluster")
            region = arguments.get("region", "us-east-1")
            hours_back = arguments.get("hours_back", 168)

            # Use exact match if input looks like a full pod name (contains hash pattern)
            exact = bool(re.search(r'-[a-f0-9]{8,10}-[a-z0-9]{5}$', pod_name))
            query = build_pod_termination_query(pod_name, exact=exact)
            results = await run_insights_query(cluster, query, hours_back, region)

            if not results:
                return [TextContent(type="text", text=f"No audit log events found for pod '{pod_name}' in cluster '{cluster}' (last {hours_back}h).")]

            # Parse events and find termination
            events = []
            for row in results:
                message_field = next((f["value"] for f in row if f["field"] == "@message"), None)
                if message_field:
                    parsed = parse_audit_event(message_field)
                    events.append(parsed)

            # Find termination events
            terminations = []
            for event in events:
                for container in event.get("containers", []):
                    if container.get("state") == "terminated":
                        terminations.append({
                            "pod_name": event.get("pod_name", "unknown"),
                            "namespace": event.get("namespace", "unknown"),
                            "timestamp": event["timestamp"],
                            "actor": event["actor"],
                            "exit_code": container.get("exit_code"),
                            "reason": container.get("reason"),
                            "started_at": container.get("started_at"),
                            "finished_at": container.get("finished_at"),
                            "restart_count": container.get("restart_count", 0),
                        })

            if not terminations:
                return [TextContent(type="text", text=f"Pod '{pod_name}' found in audit logs but no termination events detected.")]

            # Build diagnosis
            # Deduplicate pod names found
            pod_names_found = list(dict.fromkeys(t["pod_name"] for t in terminations if t["pod_name"] != "unknown"))
            pods_display = ", ".join(pod_names_found) if pod_names_found else pod_name
            namespace_display = terminations[0].get("namespace", "unknown") if terminations else "unknown"

            output_lines = [f"# Restart Diagnosis: {pod_name}", f"Cluster: {cluster} ({region})", f"Namespace: {namespace_display}", f"Pod(s): {pods_display}", ""]

            for i, term in enumerate(terminations, 1):
                code_info = translate_exit_code(term["exit_code"]) if term["exit_code"] is not None else None
                runtime = calculate_runtime(term["started_at"], term["finished_at"]) if term.get("started_at") and term.get("finished_at") else "unknown"
                actor = determine_kill_actor({"user": {"username": term["actor"]}})

                output_lines.append(f"## Termination Event {i}")
                output_lines.append(f"- Pod: {term['pod_name']}")
                output_lines.append(f"- Timestamp: {term['finished_at']}")
                output_lines.append(f"- Exit Code: {term['exit_code']} ({code_info['signal'] if code_info else 'unknown'})")
                output_lines.append(f"- Description: {code_info['description'] if code_info else 'unknown'}")
                output_lines.append(f"- Runtime: {runtime}")
                output_lines.append(f"- Actor: {actor}")
                output_lines.append(f"- Restart Count After: {term['restart_count']}")
                output_lines.append("")

                # Recommendations
                if code_info and code_info["is_segfault"]:
                    output_lines.append("### Recommendation")
                    output_lines.append("- SIGSEGV = native code crash. Not infra-related.")
                    output_lines.append("- Enable crash dumps: COMPlus_DbgEnableMiniDump=1")
                    output_lines.append("- Check native libraries (gRPC core, OpenSSL, P/Invoke)")
                    output_lines.append("")
                elif code_info and code_info["is_oom_possible"]:
                    output_lines.append("### Recommendation")
                    output_lines.append("- Exit 137 can be OOMKill OR external SIGKILL (rollout/liveness).")
                    output_lines.append("- Check if replicaset-controller issued a delete (= rollout, expected).")
                    output_lines.append("- If kubelet-only: check container memory limit vs usage.")
                    output_lines.append("")

            return [TextContent(type="text", text="\n".join(output_lines))]

        elif name == "find_crashes":
            cluster = validate_name(arguments["cluster"], "cluster")
            region = arguments.get("region", "us-east-1")
            hours_back = arguments.get("hours_back", 168)
            service_name = arguments.get("service_name")
            exit_code = arguments.get("exit_code")
            if service_name:
                validate_name(service_name, "service_name")

            if exit_code:
                query = build_crash_scan_query(exit_code)
            else:
                query = build_all_crashes_query(service_name)

            results = await run_insights_query(cluster, query, hours_back, region)

            if not results:
                return [TextContent(type="text", text=f"No crashes found in cluster '{cluster}' (last {hours_back}h).")]

            output_lines = [f"# Crash Report: {cluster}", f"Filter: exit_code={exit_code or 'any'}, service={service_name or 'all'}", f"Time range: last {hours_back}h", ""]
            output_lines.append("| Pod | Exit Code | Signal | Finished At |")
            output_lines.append("|-----|-----------|--------|-------------|")

            for row in results:
                pod = next((f["value"] for f in row if f["field"] == "pod_name"), "unknown")
                code = next((f["value"] for f in row if f["field"] == "exit_code"), "?")
                finished = next((f["value"] for f in row if f["field"] == "finished_at"), "?")

                try:
                    code_int = int(code)
                    signal = translate_exit_code(code_int)["signal"]
                except (ValueError, TypeError):
                    signal = "unknown"

                output_lines.append(f"| {pod} | {code} | {signal} | {finished} |")

            return [TextContent(type="text", text="\n".join(output_lines))]

        elif name == "get_pod_lifecycle":
            pod_name = validate_name(arguments["pod_name"], "pod_name")
            cluster = validate_name(arguments["cluster"], "cluster")
            region = arguments.get("region", "us-east-1"
            hours_back = arguments.get("hours_back", 168)

            exact = bool(re.search(r'-[a-f0-9]{8,10}-[a-z0-9]{5}$', pod_name))
            if exact:
                query = f"""fields @timestamp, @message
| filter objectRef.name = "{pod_name}"
| sort @timestamp asc"""
            else:
                query = f"""fields @timestamp, @message
| filter objectRef.name like /{pod_name}/
| sort @timestamp asc"""

            results = await run_insights_query(cluster, query, hours_back, region)

            if not results:
                return [TextContent(type="text", text=f"No events found for pod '{pod_name}'.")]

            output_lines = [f"# Pod Lifecycle: {pod_name}", f"Cluster: {cluster}", ""]
            output_lines.append("| Timestamp | Verb | Actor | Summary |")
            output_lines.append("|-----------|------|-------|---------|")

            for row in results:
                ts = next((f["value"] for f in row if f["field"] == "@timestamp"), "?")
                message = next((f["value"] for f in row if f["field"] == "@message"), None)

                if message:
                    parsed = parse_audit_event(message)
                    verb = parsed.get("verb", "?")
                    actor = parsed.get("actor", "?").split(":")[-1]  # short actor name

                    # Summarize
                    summary = verb
                    for container in parsed.get("containers", []):
                        if container.get("state") == "terminated":
                            summary = f"terminated (exit {container.get('exit_code')})"
                        elif container.get("state") == "running":
                            summary = f"running (restart #{container.get('restart_count', 0)})"
                        elif container.get("state") == "waiting":
                            summary = f"waiting ({container.get('reason', '?')})"

                    output_lines.append(f"| {ts} | {verb} | {actor} | {summary} |")

            return [TextContent(type="text", text="\n".join(output_lines))]

        else:
            return [TextContent(type="text", text=f"Unknown tool: {name}")]

    except ValueError as e:
        return [TextContent(type="text", text=f"Validation error: {e}")]
    except Exception as e:
        logger.error(f"Unexpected error in tool '{name}': {e}")
        return [TextContent(type="text", text=f"Error: {e}")]


async def main():
    """Run the MCP server."""
    async with stdio_server() as (read_stream, write_stream):
        await server.run(read_stream, write_stream, server.create_initialization_options())


if __name__ == "__main__":
    import asyncio
    asyncio.run(main())
