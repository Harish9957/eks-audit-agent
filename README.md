# EKS Audit Agent — MCP Server

A Model Context Protocol server that queries EKS CloudWatch control plane audit logs to diagnose container restarts, crashes, and lifecycle events — turning raw JSON into actionable RCA.

## Why?

- OTel/observability platforms only see what the **app emits**. Dead apps emit nothing.
- EKS audit logs (CloudWatch) record **everything** the kubelet reports — including exit codes, termination reasons, and actor identity.
- But audit logs are massive, deeply nested JSON that nobody wants to read manually.
- This agent bridges the gap: ask a question, get an answer.

## Capabilities

| Tool | What it does |
|------|-------------|
| `diagnose_restart` | Given a service name (e.g., `orderservice`) or full pod name + cluster, explains why it restarted |
| `get_pod_lifecycle` | Full timeline: create → schedule → run → terminate → restart |
| `find_crashes` | Scan cluster for non-zero exit codes (139=SIGSEGV, 137=OOM/SIGKILL, etc.) |
| `pattern_detection` | Detect recurring crashes for a service over a time range |

## Example usage (from VS Code Copilot)

```
User: Has orderservice crashed on PRODUCTION in the last 7 days?

Agent: Found 1 crash for orderservice on PRODUCTION:

       Pod: orderservice
       Terminated: 2026-01-23 14:59:08 UTC
       Exit code: 139 (SIGSEGV — segmentation fault)
       Runtime before crash: 6h 1m
       Actor: kubelet (container self-terminated, no external kill)
       
       This is NOT OOM (memory at 4%), NOT liveness probe (app was healthy).
       Root cause: Native code crash in .NET process.
       Recommendation: Enable crash dumps (COMPlus_DbgEnableMiniDump=1)
```

```
User: Any pod crashes on PRODUCTION this week?

Agent: Found 3 terminations:
       | Pod | Exit Code | Signal | Time |
       | POD-A | 139 | SIGSEGV | Jan 23 14:59 |
       | POD-B  | 137 | SIGKILL | Feb 06 17:58 |
       | POD-C   | 137 | SIGKILL | Mar 07 09:50 |
       
       The 137s on Jul 7 were rollout-related (replicaset-controller deleted them).
       The 139 on Jun 23 was a native code crash — needs dev team attention.
```

```
User: What killed orderservice on staging?

Agent: Pod orderA terminated twice:
       1. Jan 23 17:58 — Exit 137 (SIGKILL by kubelet, likely liveness probe)
       2. Mar 07 09:50 — Exit 137 (SIGKILL by replicaset-controller = rollout)
       
       The Jul 6 kill was NOT a rollout. With 1 CPU / 2Gi limit, investigate
       if liveness probe timed out or if container hit memory ceiling.
```

## Setup

```bash
pip install -e .
```

## Configuration

Set AWS credentials with access to CloudWatch Logs for your EKS clusters:

```bash
export AWS_PROFILE=your-profile
# or
export AWS_ACCESS_KEY_ID=...
export AWS_SECRET_ACCESS_KEY=...
```

## Architecture

```
VS Code / Copilot Chat
        │
        ▼
┌────────────────────┐
│  EKS Audit Agent   │  (MCP Server - stdio transport)
│  (Python)          │
└────────┬───────────┘
         │
         ▼
┌────────────────────┐
│ CloudWatch Logs    │  /aws/eks/<cluster>/cluster
│ Insights API       │
└────────────────────┘
```
