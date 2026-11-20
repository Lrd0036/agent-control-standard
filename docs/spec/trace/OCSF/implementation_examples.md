# OCSF Implementation Examples

Trace a tool result and the Guardian’s decision about releasing it to the agent. This example emits two OCSF 1.9.0 events for the `run_command` scenario in the [ACS walkthrough](../../../acs.md#traceable).

## Emit the result and its decision

The tool runs `/usr/bin/printf hello`. The host observes `printf` exit on its own with code `0` at `2026-10-09T12:00:00Z`. The Guardian issues its verdict 25 milliseconds later. The producer uses synthetic observations and selected fields from the ACS exchange.

| Event | What it records | Where the data comes from |
| --- | --- | --- |
| Process Activity (`1007`) | The subprocess exited. Both `actor.process` and `process` identify `printf` for the reflexive Terminate activity. | The host supplies the process, parent, device, exit code and occurrence time. The `steps/toolCallResult` request supplies the agent, session, tool and output. |
| Application Lifecycle (`6002`) | The Guardian issued an `allow` for this result. | The response supplies the decision, request ID, evaluator and chain head. The gated request supplies the session ID. |

ACS assigns the allow class and severity. It leaves the `6002` activity ID open. This producer uses OCSF’s `99` (Other) with the source-specific label `Allow tool result`. The `application` field names the agent runtime that requested the decision. See the [ACS class mapping](../events.md#ocsf-event-classes).

Run the [Python producer](../../../assets/examples/ocsf_tool_result.py) with Python 3.11 or later. It uses the standard library and writes one JSON event per line. To adapt it, pass the hook’s `params` and host observations to `process_exit_event`. Pass the same `params` and the Guardian’s `result` to `allow_event`, along with the application and decision time.

```sh
python3 ocsf_tool_result.py > events.ndjson
```

```python
--8<-- "docs/assets/examples/ocsf_tool_result.py"
```

Join the two records on `metadata.correlation_uid`. Both contain `<session_id>:<request_id>` for the **result** request. The step’s `unmapped.acs.request_id_ref` points back to the earlier tool-call request. For a Guardian deny, see the [Detection Finding (`2004`) example](../extend_ocsf.md#example-deny-decision-as-detection-finding-2004).

## Count tool results by agent and tool

Index each line of `events.ndjson` as one JSON event. Filter on the method as well as the class because tool-call requests also use `1007`. With the two sample records, both searches return one result for `agent_456` and `run_command`.

### Splunk

Use your index and sourcetype, and select a time range that includes the sample. `spath` extracts the JSON fields from the raw event.

```spl
index=security sourcetype=ocsf
| spath
| search class_uid=1007 unmapped.acs.method="steps/toolCallResult"
| stats count BY unmapped.acs.agent_id unmapped.acs.tool.name
```

### Elasticsearch

Send this body to `GET /ocsf-events/_search` for an index named `ocsf-events`. The query assumes a numeric `class_uid` and indexed ACS strings with `.keyword` subfields. If your index maps those strings directly as `keyword`, use their field names without the suffix.

```json
{
  "size": 0,
  "query": {
    "bool": {
      "filter": [
        { "term": { "class_uid": 1007 } },
        { "term": { "unmapped.acs.method.keyword": "steps/toolCallResult" } }
      ]
    }
  },
  "aggs": {
    "by_agent_and_tool": {
      "multi_terms": {
        "terms": [
          { "field": "unmapped.acs.agent_id.keyword" },
          { "field": "unmapped.acs.tool.name.keyword" }
        ]
      }
    }
  }
}
```

The sample produces one `by_agent_and_tool` bucket with `key` equal to `["agent_456", "run_command"]` and `doc_count` equal to `1`.
