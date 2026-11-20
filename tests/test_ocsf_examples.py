"""Keep the OCSF walkthrough, runnable producer, and SIEM queries in agreement.

The OCSF tab previously used an invented class, a seconds timestamp, and the
agent's identity as an identity provider. MkDocs and the link guards accepted
it. Read the published JSON itself so those mistakes cannot return unnoticed.

These are focused documentation checks, not a complete OCSF validator. The
required process context follows OCSF 1.9.0's Process Activity, System Activity,
Process, and Device definitions at schema commit
856d462bd20dc46cc1ffed2dfffe3b91ef0fbeba. Upstream event validation is a separate
check before publication.
"""

import json
import re
import shlex
import subprocess
import sys
from copy import deepcopy
from datetime import datetime
from html import unescape
from pathlib import Path
from runpy import run_path

import pytest
from jsonschema import Draft202012Validator, FormatChecker, ValidationError
from referencing import Registry, Resource
from referencing.jsonschema import DRAFT202012

ROOT = Path(__file__).resolve().parent.parent
SPEC = ROOT / "specification" / "v0.1.0"
PRODUCER = Path("assets/examples/ocsf_tool_result.py")


def walkthrough_tab():
    source = (ROOT / "docs" / "acs.md").read_text(encoding="utf-8")
    return source.partition('    === "OCSF"\n')[2].partition("\n    === ")[0]


def walkthrough_event():
    blocks = re.findall(r"```json\n(.*?)```", walkthrough_tab(), re.DOTALL)
    assert len(blocks) == 1, "The OCSF tab must contain one complete event example"
    return json.loads(blocks[0])


@pytest.fixture(scope="module")
def published_blocks(built_docs):
    page = built_docs / "spec/trace/OCSF/implementation_examples/index.html"
    # The highlighter wraps code in spans and escapes literal markup.
    blocks = re.findall(r"<pre\b[^>]*>(.*?)</pre>", page.read_text(encoding="utf-8"), re.DOTALL)
    return [unescape(re.sub(r"<[^>]+>", "", block)) for block in blocks]


@pytest.fixture(scope="module")
def produced_events(built_docs, published_blocks, tmp_path_factory):
    source = ROOT / "docs" / PRODUCER
    assert (built_docs / PRODUCER).read_bytes() == source.read_bytes()
    assert source.read_text(encoding="utf-8") in published_blocks
    run = subprocess.run(
        [sys.executable, "-I", "-S", source],
        cwd=tmp_path_factory.mktemp("ocsf"),
        capture_output=True, text=True, check=True, timeout=10,
    )
    step, decision = (json.loads(line) for line in run.stdout.splitlines())
    return step, decision


@pytest.fixture(scope="module", params=["walkthrough", "producer"])
def step_event(request, produced_events):
    return walkthrough_event() if request.param == "walkthrough" else produced_events[0]


def field_at(event, path):
    for name in path.split("."):
        event = event[name]
    return event


def declared_objects_only(schema):
    """Reject invented wrapper fields in this example, leaving output values opaque.

    The wire schemas remain extensible. This constraint applies only to the
    documentation's claim to copy existing ACS fields.
    """
    if isinstance(schema, list):
        return [declared_objects_only(item) for item in schema]
    if not isinstance(schema, dict):
        return schema
    result = {key: declared_objects_only(value) for key, value in schema.items()}
    if schema.get("type") == "object" and "properties" in schema:
        result["additionalProperties"] = False
    return result


def validate_copied_acs_fields(acs):
    envelope = json.loads((SPEC / "request-envelope.json").read_text(encoding="utf-8"))
    hook = json.loads((SPEC / "hooks" / "tool-call-result.json").read_text(encoding="utf-8"))
    metadata = envelope["$defs"]["Metadata"]
    payload_fields = hook["properties"]
    metadata_fields = metadata["properties"]
    allowed = set(payload_fields) | set(metadata_fields) | {"method", "request_id"}
    assert not set(acs) - allowed, f"Undeclared ACS fields: {set(acs) - allowed}"

    resources = []
    for path in sorted(SPEC.rglob("*.json")):
        schema = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(schema, dict) and "$id" in schema:
            resources.append((schema["$id"], Resource.from_contents(schema, default_specification=DRAFT202012)))
    registry = Registry().with_resources(resources)

    for schema, value in (
        (metadata, {key: value for key, value in acs.items() if key in metadata_fields}),
        (hook, {key: value for key, value in acs.items() if key in payload_fields}),
        (envelope["properties"]["method"], acs["method"]),
        (envelope["$defs"]["AcsParams"]["properties"]["request_id"], acs["request_id"]),
    ):
        Draft202012Validator(
            declared_objects_only(schema), registry=registry, format_checker=FormatChecker()
        ).validate(value)

    assert acs["method"] == "steps/toolCallResult"
    assert acs["request_id"] != acs["request_id_ref"]


def test_step_uses_the_mapped_process_class(step_event):
    event = step_event
    method = event["unmapped"]["acs"].get("method")
    assert method == "steps/toolCallResult"
    mapping = json.loads(
        (SPEC / "trace" / "ocsf-mapping.json")
        .read_text(encoding="utf-8")
    )["properties"]["step_to_class"]["default"][method]

    assert event["class_uid"] == mapping["class_uid"]
    assert event["class_name"] == mapping["class_name"]
    assert event["category_uid"] == 1  # System Activity
    assert event["category_name"] == "System Activity"
    assert event["activity_id"] == 2  # A subprocess exiting on its own
    assert event["activity_name"] == "Terminate"
    assert event["type_uid"] == event["class_uid"] * 100 + event["activity_id"]
    assert event["metadata"]["version"] == "1.9.0"
    assert event["metadata"]["product"]["name"]
    assert "ocsf" not in event["metadata"]


def test_step_represents_a_reflexive_process_exit(step_event):
    event = step_event
    assert "process" in event["actor"], "The actor must identify the exiting process"
    assert "device" in event, "Process Activity requires the actual host device"
    assert "process" in event, "The tool's subprocess must be identified"
    assert event["actor"]["process"] == event["process"], (
        "A self-exit's actor and target must both identify the exiting process"
    )
    assert type(event["process"]["pid"]) is int
    assert event["process"]["pid"] > 0
    parent = event["process"]["parent_process"]
    assert type(parent["pid"]) is int and parent["pid"] > 0
    assert parent["pid"] != event["process"]["pid"]
    assert type(event["device"]["type_id"]) is int
    assert "idp" not in event["actor"]

    acs = event["unmapped"]["acs"]
    assert event["device"]["uid"] != acs["agent_id"]
    assert type(event["exit_code"]) is int
    assert event["exit_code"] == 0 and acs["exit_status"] == "success"
    assert "acs_extensions" not in event
    assert "asop" not in event["unmapped"]


def test_step_copies_declared_acs_fields(step_event):
    validate_copied_acs_fields(step_event["unmapped"]["acs"])


def check_correlation_uid(event):
    """The step and decision both identify the gated request within its session."""
    acs = event["unmapped"]["acs"]
    assert event["metadata"].get("correlation_uid") == f"{acs['session_id']}:{acs['request_id']}", (
        "metadata.correlation_uid must be the step's <session_id>:<request_id>"
    )


def test_step_sets_its_correlation_uid(step_event):
    check_correlation_uid(step_event)


@pytest.mark.parametrize("make", [
    None,
    lambda acs: f"{acs['request_id']}:{acs['session_id']}",
    lambda acs: f"{acs['session_id']}:{acs['request_id_ref']}",
    lambda acs: f"{acs['session_id']}/{acs['request_id']}",
], ids=["dropped", "reversed", "gated_request", "separator"])
def test_correlation_uid_rejects_a_dropped_or_wrong_pair(make):
    event = walkthrough_event()
    check_correlation_uid(event)
    if make is None:
        del event["metadata"]["correlation_uid"]
    else:
        event["metadata"]["correlation_uid"] = make(event["unmapped"]["acs"])
    with pytest.raises(AssertionError):
        check_correlation_uid(event)


@pytest.mark.parametrize("path,value", [
    (("tool", "id"), "run_command"),
    (("tool", "execution_id"), "exec_123"),
    (("step",), {"id": "step_result_1", "type": "toolCallResult"}),
    (("session_id",), "sess_123"),
    (("request_id",), "step_result_1"),
    (("request_id_ref",), "exec_123"),
])
def test_copied_acs_fields_reject_old_aliases_and_non_uuid_ids(path, value):
    acs = deepcopy(walkthrough_event()["unmapped"]["acs"])
    validate_copied_acs_fields(acs)
    target = acs
    for key in path[:-1]:
        target = target[key]
    target[path[-1]] = value
    with pytest.raises((AssertionError, ValidationError)):
        validate_copied_acs_fields(acs)


def test_step_timestamps_match_the_documented_exit(step_event):
    event = step_event
    timestamp = re.search(r"at `([^`]+Z)`", walkthrough_tab())
    assert timestamp, "The scenario must state its occurrence time in UTC"
    exited_at = datetime.fromisoformat(timestamp[1])
    expected_ms = int(exited_at.timestamp() * 1000)
    assert event["time"] == expected_ms, "OCSF occurrence time uses milliseconds"
    assert event["process"]["terminated_time"] == expected_ms
    assert event["actor"]["process"]["terminated_time"] == expected_ms


def test_producer_joins_the_guardian_allow_to_the_result(produced_events):
    step, decision = produced_events
    mapping = json.loads((SPEC / "trace" / "ocsf-mapping.json").read_text(encoding="utf-8"))["properties"]
    decision_rules = mapping["decision_class"]["properties"]
    allow = decision_rules["allow_class"]["properties"]
    for path in allow["required_fields"]["default"]:
        assert field_at(decision, path) is not None, path
    assert decision["class_uid"] == allow["class_uid"]["const"]
    assert decision["class_name"] == allow["class_name"]["const"]
    assert (decision["category_uid"], decision["category_name"]) == (6, "Application Activity")
    assert (decision["activity_id"], decision["activity_name"]) == (99, "Allow tool result")
    assert decision["type_uid"] == decision["class_uid"] * 100 + decision["activity_id"]
    assert decision["application"]["name"]
    assert decision["metadata"]["version"] == "1.9.0"
    assert decision["metadata"]["product"]["name"]
    assert decision["time"] == step["time"] + 25

    acs = decision["unmapped"]["acs"]
    assert acs["decision"] == "allow"
    assert decision["severity_id"] == mapping["severity_mapping"]["default"][acs["decision"]]
    for name in decision_rules["join_fields"]["default"]:
        assert acs[name] == step["unmapped"]["acs"][name]
    check_correlation_uid(decision)
    assert decision["metadata"]["correlation_uid"] == step["metadata"]["correlation_uid"]

    response_fields = set(acs) - {"session_id"}
    assert response_fields <= set(decision_rules["acs_fields"]["default"])
    assert acs["metadata"]["evaluator"] == "deterministic"
    assert acs["chain_hash"]
    response_schema = json.loads((SPEC / "response-envelope.json").read_text(encoding="utf-8"))
    properties = response_schema["$defs"]["AcsResult"]["properties"]
    for name in response_fields:
        Draft202012Validator(properties[name], format_checker=FormatChecker()).validate(acs[name])


@pytest.mark.parametrize(("verdict", "id_field"), [("deny", "request_id"), ("allow", "request_id_ref")])
def test_allow_builder_rejects_a_deny_or_another_request(produced_events, verdict, id_field):
    acs = produced_events[0]["unmapped"]["acs"]
    params = {"request_id": acs["request_id"], "metadata": {"session_id": acs["session_id"]}}
    result = {"request_id": acs[id_field], "decision": verdict}
    allow_event = run_path(str(ROOT / "docs" / PRODUCER))["allow_event"]
    with pytest.raises(ValueError, match="allow for this tool result"):
        allow_event(
            params, result, application={"name": "Example agent runtime"},
            decided_at="2026-10-09T12:00:00.025Z",
        )


def test_queries_filter_and_group_on_produced_fields(produced_events, published_blocks):
    step, decision = produced_events
    [spl] = [block for block in published_blocks if block.startswith("index=")]
    base, extract, search, stats = spl.splitlines()
    assert {term.split("=", 1)[0] for term in shlex.split(base)} == {"index", "sourcetype"}
    assert extract == "| spath"
    assert search.startswith("| search ") and stats.startswith("| stats count BY ")
    filters = dict(term.split("=", 1) for term in shlex.split(search.removeprefix("| search ")))
    groups = stats.removeprefix("| stats count BY ").split()
    assert filters == {"class_uid": str(step["class_uid"]), "unmapped.acs.method": "steps/toolCallResult"}
    assert all(str(field_at(step, path)) == value for path, value in filters.items())
    assert str(decision["class_uid"]) != filters["class_uid"]
    assert [field_at(step, path) for path in groups] == ["agent_456", "run_command"]

    [elastic] = [json.loads(block) for block in published_blocks if block.startswith("{")]
    # Elasticsearch applies the same filters and groups using its keyword subfields.
    assert elastic == {
        "size": 0,
        "query": {"bool": {"filter": [
            {"term": {"class_uid": step["class_uid"]}},
            {"term": {"unmapped.acs.method.keyword": filters["unmapped.acs.method"]}},
        ]}},
        "aggs": {"by_agent_and_tool": {"multi_terms": {
            "terms": [{"field": f"{path}.keyword"} for path in groups],
        }}},
    }
