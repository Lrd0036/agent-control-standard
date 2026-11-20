"""Emit a tool result and its Guardian allow as two OCSF 1.9.0 JSON lines."""

import json
from datetime import datetime, timedelta, timezone


def epoch_ms(timestamp):
    epoch = datetime(1970, 1, 1, tzinfo=timezone.utc)
    return (datetime.fromisoformat(timestamp) - epoch) // timedelta(milliseconds=1)


def event_metadata(producer, session_id, request_id):
    return {
        "version": "1.9.0",
        "product": {"name": producer, "vendor_name": "Example Corp"},
        "correlation_uid": f"{session_id}:{request_id}",
    }


def process_exit_event(params, process, device, exit_code):
    """Map a tool result whose subprocess exited on its own."""
    session_id = params["metadata"]["session_id"]
    payload = params["payload"]
    acs = {
        "method": "steps/toolCallResult",
        "request_id": params["request_id"],
        "session_id": session_id,
        "agent_id": params["metadata"]["agent_id"],
        "tool": payload["tool"],
        "exit_status": payload["exit_status"],
        "outputs": payload["outputs"],
    }
    for name in ("request_id_ref", "operation", "duration_ms"):
        if name in payload:
            acs[name] = payload[name]
    return {
        "class_uid": 1007, "class_name": "Process Activity",
        "category_uid": 1, "category_name": "System Activity",
        "activity_id": 2, "activity_name": "Terminate",
        "type_uid": 100702, "severity_id": 1,
        "time": process["terminated_time"],
        "metadata": event_metadata("ACS trace example", session_id, params["request_id"]),
        "actor": {"process": process},
        "process": process,
        "device": device,
        "exit_code": exit_code,
        "unmapped": {"acs": acs},
    }


def allow_event(params, result, application, decided_at):
    """Map an on-time Guardian allow for the gated tool result."""
    if result["decision"] != "allow" or result["request_id"] != params["request_id"]:
        raise ValueError("Expected an allow for this tool result")
    session_id = params["metadata"]["session_id"]
    acs = {
        "request_id": result["request_id"], "session_id": session_id, "decision": result["decision"],
    }
    for name in (
        "reasoning", "reason_codes", "policy_references", "cited_provenance_ids",
        "chain_hash", "metadata",
    ):
        if name in result and result[name] != []:
            acs[name] = result[name]
    return {
        "class_uid": 6002, "class_name": "Application Lifecycle",
        "category_uid": 6, "category_name": "Application Activity",
        "activity_id": 99, "activity_name": "Allow tool result",
        "type_uid": 600299, "severity_id": 1,
        "time": epoch_ms(decided_at),
        "metadata": event_metadata("Example Guardian", session_id, result["request_id"]),
        "application": application,
        "unmapped": {"acs": acs},
    }


def main():
    # Selected fields from the toolCallResult request's params.
    params = {
        "request_id": "1287ce09-fcda-4588-a5e9-3fa83bfe5291",
        "metadata": {
            "agent_id": "agent_456",
            "session_id": "7673ad6b-b5b3-4eec-8f46-66c83eef0b52",
        },
        "payload": {
            "tool": {"name": "run_command"},
            "exit_status": "success",
            "request_id_ref": "e1572c78-689e-4bdb-91d4-6e019b416849",
            "outputs": [{"value": "hello"}],
        },
    }
    # The host observed this process exit on its own.
    process = {
        "pid": 4243,
        "name": "printf",
        "cmd_line": "/usr/bin/printf hello",
        "parent_process": {"pid": 4242, "name": "python", "cmd_line": "python agent.py"},
        "terminated_time": epoch_ms("2026-10-09T12:00:00Z"),
    }
    device = {
        "uid": "host_001", "hostname": "agent-host.example", "type_id": 1, "type": "Server",
    }
    step = process_exit_event(params, process, device, exit_code=0)

    # Selected fields from the Guardian response's result, including a sample chain head.
    result = {
        "request_id": params["request_id"],
        "decision": "allow",
        "metadata": {"evaluator": "deterministic"},
        "chain_hash": "0123456789abcdef" * 4,
    }
    decision = allow_event(
        params, result, application={"name": "Example agent runtime"},
        decided_at="2026-10-09T12:00:00.025Z",
    )
    for event in (step, decision):
        print(json.dumps(event))


if __name__ == "__main__":
    main()
