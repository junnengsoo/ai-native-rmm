import asyncio
import ast
import hashlib
import json
from types import SimpleNamespace

import httpx
import pytest
from agents import Model, ModelResponse, RunContextWrapper
from agents.usage import InputTokensDetails, OutputTokensDetails, Usage
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText

from control_plane.openai_driver import (
    ControlPlaneClient,
    DiagnosticContext,
    DriverError,
    _inspect_output,
    _submit_script,
    _wait_for_execution,
    build_agent,
    drive_diagnostic,
    inert_text,
    render_result,
)


class FakeControlPlane:
    def __init__(self, *, close_ok=True):
        self.closed = False
        self.close_ok = close_ok
        self.close_raises = False
        self.submitted = []
        self.waits = []
        self.inspections = []
        self.next_execution = 1
        self.wait_counts = {}
        self.fail_submit = False

    async def open_session(self, device_id, *, timeout_seconds):
        assert device_id == "device-1"
        assert timeout_seconds > 0
        return {"session_id": "session-1", "status": "active"}

    async def close_session(self, session_id, *, timeout_seconds):
        assert session_id == "session-1"
        assert timeout_seconds >= 31
        if self.close_raises:
            raise httpx.ReadTimeout("close stuck")
        self.closed = self.close_ok
        return (self.close_ok, None if self.close_ok else "session_close_unconfirmed")

    async def submit_execution(self, session_id, script, *, timeout_seconds):
        assert session_id == "session-1"
        if self.fail_submit:
            raise httpx.ReadTimeout("submit response lost")
        execution_id = f"exec-{self.next_execution}"
        self.next_execution += 1
        self.submitted.append((execution_id, script))
        return {
            "execution_id": execution_id,
            "status": "queued",
            "script_sha256": hashlib.sha256(script.encode()).hexdigest(),
        }

    async def wait_execution(self, execution_id, timeout_seconds):
        self.waits.append((execution_id, timeout_seconds))
        self.wait_counts[execution_id] = self.wait_counts.get(execution_id, 0) + 1
        if execution_id == "exec-1" and self.wait_counts[execution_id] == 1:
            return {
                "execution_id": execution_id,
                "status": "running",
                "terminal": False,
                "wait_timed_out": True,
            }
        if execution_id == "exec-1":
            return {
                "execution_id": execution_id,
                "status": "completed",
                "terminal": True,
                "wait_timed_out": False,
                "invocation_outcome": "completed_normally",
                "exit_code": 0,
                "duration_ms": 12.0,
                "capture": {"loss_detected": False},
                "output_preview": {
                    "stdout": {"text": "DNS resolves to 10.0.0.5\n", "shortened": False},
                    "stderr": {"text": "", "shortened": False},
                },
            }
        return {
            "execution_id": execution_id,
            "status": "completed",
            "terminal": True,
            "wait_timed_out": False,
            "invocation_outcome": "completed_normally",
            "exit_code": 0,
            "duration_ms": 42.0,
            "capture": {"loss_detected": False},
            "output_preview": {
                "stdout": {"text": "TcpTestSucceeded: False\n", "shortened": True},
                "stderr": {"text": "", "shortened": False},
            },
        }

    async def inspect_output(self, execution_id, stream, mode, params, *, timeout_seconds):
        self.inspections.append((execution_id, stream, mode, params))
        if mode == "search":
            return {
                "stream": stream,
                "query": params["query"],
                "case_sensitive": params["case_sensitive"],
                "matches": [{
                    "text": "TcpTestSucceeded: False",
                    "context": {"before": "ComputerName: rmm-test-fileserver\n", "after": ""},
                    "range": {"start_byte": 31, "end_byte": 54},
                    "line_range": {"start_line": 2, "end_line": 2},
                }],
                "match_count": 1,
                "limit_reached": False,
                "next_after_byte": None,
                "partial": False,
                "capture_lost": False,
                "gap": {"detected": False, "reason": None},
            }
        if mode == "tail":
            return {"stream": stream, "text": "stderr tail", "line_range": {"start_line": 1, "end_line": 1},
                    "range": {"start_byte": 0, "end_byte": 11}, "partial": False,
                    "capture_lost": False, "gap": {"detected": False, "reason": None}}
        return {"stream": stream, "text": "TcpTestSucceeded: False",
                "range": {"start_byte": params["start_byte"], "end_byte": params["end_byte"]},
                "requested_range": {"start_byte": params["start_byte"], "end_byte": params["end_byte"]},
                "partial": False, "capture_lost": False, "gap": {"detected": False, "reason": None}}


def test_agent_exposes_exactly_three_script_execution_tools():
    agent = build_agent("gpt-5-nano")

    assert agent.model == "gpt-5-nano"
    assert [tool.name for tool in agent.tools] == ["submit_script", "wait_for_execution", "inspect_output"]
    assert "run_diagnostic" not in {tool.name for tool in agent.tools}
    assert agent.model_settings.parallel_tool_calls is False
    assert agent.model_settings.max_tokens == 600

    schemas = {tool.name: tool.params_json_schema["properties"] for tool in agent.tools}
    assert set(schemas["submit_script"]) == {"script"}
    assert schemas["submit_script"]["script"]["maxLength"] == 32768
    assert set(schemas["wait_for_execution"]) == {"execution_id", "timeout_seconds"}
    assert schemas["wait_for_execution"]["timeout_seconds"]["maximum"] == 60
    assert set(schemas["inspect_output"]) == {
        "execution_id", "stream", "mode", "query", "case_sensitive", "context_lines",
        "limit_matches", "after_byte", "lines", "start_byte", "end_byte",
    }


def context(max_steps=2):
    return DiagnosticContext(FakeControlPlane(), "session-1", 9999999999.0, max_steps)


def tool_context(ctx):
    return RunContextWrapper(ctx, usage=SimpleNamespace())


def test_real_agents_sdk_submit_tool_invokes_bound_session_and_schema():
    submit_tool = build_agent("gpt-5-nano").tools[0]
    ctx = context()

    payload = asyncio.run(submit_tool.on_invoke_tool(
        tool_context(ctx),
        json.dumps({"script": "Resolve-DnsName rmm-test-fileserver"}),
    ))

    assert payload["execution_id"] == "exec-1"
    assert payload["status"] == "queued"
    assert payload["script_sha256"]
    assert ctx.owned_execution_ids == {"exec-1"}
    assert ctx.control_plane.submitted == [("exec-1", "Resolve-DnsName rmm-test-fileserver")]


def test_wait_and_inspect_reject_unknown_execution_ids():
    ctx = context()

    with pytest.raises(DriverError, match="unknown_execution_id"):
        asyncio.run(_wait_for_execution(ctx, "not-created-here", 1))
    with pytest.raises(DriverError, match="unknown_execution_id"):
        asyncio.run(_inspect_output(ctx, "not-created-here", "stdout", "search", query="Tcp"))


def test_submit_enforces_driver_owned_script_budget():
    ctx = context(max_steps=1)

    first = asyncio.run(_submit_script(ctx, "Get-NetIPConfiguration"))
    assert first["execution_id"] == "exec-1"
    with pytest.raises(DriverError, match="script_step_budget_exhausted"):
        asyncio.run(_submit_script(ctx, "Test-NetConnection rmm-test-fileserver -Port 445"))


def test_submit_consumes_budget_before_ambiguous_post_result():
    ctx = context(max_steps=1)
    ctx.control_plane.fail_submit = True

    with pytest.raises(httpx.ReadTimeout):
        asyncio.run(_submit_script(ctx, "Get-NetIPConfiguration"))
    assert ctx.scripts_submitted == 1
    assert ctx.owned_execution_ids == set()
    with pytest.raises(DriverError, match="script_step_budget_exhausted"):
        asyncio.run(_submit_script(ctx, "Resolve-DnsName rmm-test-fileserver"))


def test_three_tools_handle_repeated_wait_and_retained_output_inspection():
    ctx = context(max_steps=2)
    first = asyncio.run(_submit_script(ctx, "Resolve-DnsName rmm-test-fileserver"))
    running = asyncio.run(_wait_for_execution(ctx, first["execution_id"], 0.1))
    complete = asyncio.run(_wait_for_execution(ctx, first["execution_id"], 5))
    second = asyncio.run(_submit_script(ctx, "Test-NetConnection rmm-test-fileserver -Port 445"))
    tcp = asyncio.run(_wait_for_execution(ctx, second["execution_id"], 5))
    search = asyncio.run(_inspect_output(ctx, second["execution_id"], "stdout", "search",
                                         query="TcpTestSucceeded", context_lines=1, limit_matches=5))
    tail = asyncio.run(_inspect_output(ctx, second["execution_id"], "stderr", "tail", lines=5))
    expanded = asyncio.run(_inspect_output(ctx, second["execution_id"], "stdout", "range",
                                           start_byte=31, end_byte=54))

    assert running == {
        "execution_id": "exec-1",
        "status": "running",
        "terminal": False,
        "wait_timed_out": True,
        "invocation_outcome": None,
        "exit_code": None,
        "duration_ms": None,
        "capture": None,
        "output_preview": None,
    }
    assert complete["output_preview"]["stdout"]["text"] == "DNS resolves to 10.0.0.5\n"
    assert tcp["output_preview"]["stdout"]["more_available"] is True
    assert search["matches"][0]["text"]["text"] == "TcpTestSucceeded: False"
    assert search["matches"][0]["context"]["before"]["text"] == "ComputerName: rmm-test-fileserver\n"
    assert tail["text"]["text"] == "stderr tail"
    assert expanded["text"]["text"] == "TcpTestSucceeded: False"
    assert [step.tool for step in ctx.steps] == [
        "submit_script",
        "wait_for_execution",
        "wait_for_execution",
        "submit_script",
        "wait_for_execution",
        "inspect_output:search:stdout",
        "inspect_output:tail:stderr",
        "inspect_output:range:stdout",
    ]


def sdk_usage():
    return Usage(
        requests=1,
        input_tokens=1,
        output_tokens=1,
        total_tokens=2,
        input_tokens_details=InputTokensDetails(cached_tokens=0),
        output_tokens_details=OutputTokensDetails(reasoning_tokens=0),
    )


class ScriptedModel(Model):
    def __init__(self):
        self.calls = 0
        self.tool_outputs = {}

    def remember_tool_outputs(self, input_items):
        for item in input_items:
            if item.get("type") == "function_call_output" and item["call_id"] not in self.tool_outputs:
                self.tool_outputs[item["call_id"]] = ast.literal_eval(item["output"])

    async def get_response(self, system_instructions, input, *args, **kwargs):
        self.remember_tool_outputs(input)
        self.calls += 1
        if self.calls == 1:
            output = [ResponseFunctionToolCall(
                type="function_call",
                call_id="call-1",
                name="submit_script",
                arguments=json.dumps({"script": "Resolve-DnsName rmm-test-fileserver"}),
            )]
        elif self.calls == 2:
            first_execution = self.tool_outputs["call-1"]["execution_id"]
            output = [ResponseFunctionToolCall(
                type="function_call",
                call_id="call-2",
                name="wait_for_execution",
                arguments=json.dumps({"execution_id": first_execution, "timeout_seconds": 0.1}),
            )]
        elif self.calls == 3:
            first_execution = self.tool_outputs["call-1"]["execution_id"]
            assert self.tool_outputs["call-2"]["terminal"] is False
            output = [ResponseFunctionToolCall(
                type="function_call",
                call_id="call-3",
                name="wait_for_execution",
                arguments=json.dumps({"execution_id": first_execution, "timeout_seconds": 5}),
            )]
        elif self.calls == 4:
            first_result = self.tool_outputs["call-3"]["output_preview"]["stdout"]["text"]
            assert "DNS resolves" in first_result
            output = [ResponseFunctionToolCall(
                type="function_call",
                call_id="call-4",
                name="submit_script",
                arguments=json.dumps({"script": "Test-NetConnection rmm-test-fileserver -Port 445"}),
            )]
        elif self.calls == 5:
            second_execution = self.tool_outputs["call-4"]["execution_id"]
            output = [ResponseFunctionToolCall(
                type="function_call",
                call_id="call-5",
                name="wait_for_execution",
                arguments=json.dumps({"execution_id": second_execution, "timeout_seconds": 5}),
            )]
        elif self.calls == 6:
            second_execution = self.tool_outputs["call-4"]["execution_id"]
            assert self.tool_outputs["call-5"]["output_preview"]["stdout"]["more_available"] is True
            output = [ResponseFunctionToolCall(
                type="function_call",
                call_id="call-6",
                name="inspect_output",
                arguments=json.dumps({
                    "execution_id": second_execution,
                    "stream": "stdout",
                    "mode": "search",
                    "query": "TcpTestSucceeded",
                    "context_lines": 1,
                    "limit_matches": 5,
                }),
            )]
        else:
            assert self.tool_outputs["call-6"]["matches"][0]["text"]["text"] == "TcpTestSucceeded: False"
            output = [ResponseOutputMessage(
                id="msg-1",
                type="message",
                role="assistant",
                status="completed",
                content=[ResponseOutputText(type="output_text", text="DNS resolves, but SMB TCP 445 is unreachable.", annotations=[])],
            )]
        return ModelResponse(output=output, usage=sdk_usage(), response_id="resp-" + str(self.calls))

    def stream_response(self, *args, **kwargs):
        raise NotImplementedError


def test_real_agents_sdk_runner_loop_submit_wait_read_dependent_script_and_reports():
    model = ScriptedModel()
    control_plane = FakeControlPlane()
    result = asyncio.run(drive_diagnostic(
        problem="Why can Windows not reach the test share?",
        device_id="device-1",
        control_plane=control_plane,
        model=model,
        max_steps=2,
        max_seconds=60,
    ))

    assert model.calls == 7
    assert result.completed is True
    assert result.final_report == "DNS resolves, but SMB TCP 445 is unreachable."
    assert [script for _, script in control_plane.submitted] == [
        "Resolve-DnsName rmm-test-fileserver",
        "Test-NetConnection rmm-test-fileserver -Port 445",
    ]
    assert control_plane.waits == [("exec-1", 0.1), ("exec-1", 5.0), ("exec-2", 5.0)]
    assert control_plane.inspections == [("exec-2", "stdout", "search", {
        "query": "TcpTestSucceeded",
        "case_sensitive": False,
        "context_lines": 1,
        "limit_matches": 5,
        "after_byte": 0,
    })]
    assert [step.tool for step in result.steps] == [
        "submit_script",
        "wait_for_execution",
        "wait_for_execution",
        "submit_script",
        "wait_for_execution",
        "inspect_output:search:stdout",
    ]


def test_drive_diagnostic_delegates_loop_to_runner_and_closes_session():
    async def fake_runner(agent, prompt, *, context, max_turns, hooks, run_config):
        assert [tool.name for tool in agent.tools] == ["submit_script", "wait_for_execution", "inspect_output"]
        assert "Budget: at most 2 submitted PowerShell scripts" in prompt
        assert "only one active script" in prompt
        assert "policy, not sandbox enforcement" in prompt
        assert max_turns == 11
        assert run_config.tracing_disabled is True
        await hooks.on_llm_start(None, agent, None, [])
        await hooks.on_llm_end(None, agent, None)
        first = await _submit_script(context.context, "Resolve-DnsName rmm-test-fileserver")
        await _wait_for_execution(context.context, first["execution_id"], 0.1)
        await _wait_for_execution(context.context, first["execution_id"], 5)
        second = await _submit_script(context.context, "Test-NetConnection rmm-test-fileserver -Port 445")
        await _wait_for_execution(context.context, second["execution_id"], 5)
        return SimpleNamespace(
            final_output="Likely file-server TCP 445 is unreachable.",
            raw_responses=[SimpleNamespace(usage=SimpleNamespace(requests=1, input_tokens=10, output_tokens=20, total_tokens=30))],
        )

    control_plane = FakeControlPlane()
    result = asyncio.run(drive_diagnostic(
        problem="Why can Windows not reach the test share?",
        device_id="device-1",
        control_plane=control_plane,
        max_steps=2,
        max_seconds=60,
        runner=fake_runner,
    ))

    assert result.completed is True
    assert result.closed is True
    assert control_plane.closed is True
    assert len([step for step in result.steps if step.tool == "submit_script"]) == 2
    assert result.usage == {"requests": 1, "input_tokens": 10, "output_tokens": 20, "total_tokens": 30}
    assert result.model_latency_ms >= 0
    rendered = render_result(result)
    assert "Likely file-server TCP 445 is unreachable." in rendered
    assert "Model latency ms:" in rendered


def test_drive_diagnostic_does_not_complete_without_diagnostics():
    async def fake_runner(*args, **kwargs):
        return SimpleNamespace(final_output="No commands needed.", raw_responses=[])

    result = asyncio.run(drive_diagnostic(
        problem="Diagnose",
        device_id="device-1",
        control_plane=FakeControlPlane(),
        max_steps=2,
        max_seconds=60,
        runner=fake_runner,
    ))

    assert result.completed is False
    assert "terminal evidence" in result.final_report


def test_drive_diagnostic_does_not_complete_with_submit_only_run():
    async def fake_runner(agent, prompt, *, context, max_turns, hooks, run_config):
        await _submit_script(context.context, "Resolve-DnsName rmm-test-fileserver")
        return SimpleNamespace(final_output="Submitted, but did not wait.", raw_responses=[])

    result = asyncio.run(drive_diagnostic(
        problem="Diagnose",
        device_id="device-1",
        control_plane=FakeControlPlane(),
        max_steps=1,
        max_seconds=60,
        runner=fake_runner,
    ))

    assert result.completed is False
    assert "terminal evidence" in result.final_report
    assert result.closed is True


def test_drive_diagnostic_does_not_complete_after_ambiguous_submit_even_if_runner_continues():
    async def fake_runner(agent, prompt, *, context, max_turns, hooks, run_config):
        context.context.control_plane.fail_submit = True
        with pytest.raises(httpx.ReadTimeout):
            await _submit_script(context.context, "Resolve-DnsName rmm-test-fileserver")
        return SimpleNamespace(final_output="Submit outcome unknown.", raw_responses=[])

    result = asyncio.run(drive_diagnostic(
        problem="Diagnose",
        device_id="device-1",
        control_plane=FakeControlPlane(),
        max_steps=1,
        max_seconds=60,
        runner=fake_runner,
    ))

    assert result.completed is False
    assert "terminal evidence" in result.final_report
    assert result.closed is True


def test_drive_diagnostic_does_not_complete_with_only_nonterminal_wait_and_preserves_cleanup():
    async def fake_runner(agent, prompt, *, context, max_turns, hooks, run_config):
        submitted = await _submit_script(context.context, "Resolve-DnsName rmm-test-fileserver")
        waited = await _wait_for_execution(context.context, submitted["execution_id"], 0.1)
        assert waited["terminal"] is False
        return SimpleNamespace(final_output="Still running.", raw_responses=[])

    result = asyncio.run(drive_diagnostic(
        problem="Diagnose",
        device_id="device-1",
        control_plane=FakeControlPlane(close_ok=False),
        max_steps=1,
        max_seconds=60,
        runner=fake_runner,
    ))

    assert result.completed is False
    assert "terminal evidence" in result.final_report
    assert "closure_unconfirmed" in result.final_report
    assert result.closed is False


def test_drive_diagnostic_surfaces_time_budget_and_still_closes():
    async def slow_runner(*args, **kwargs):
        await asyncio.sleep(0.2)

    result = asyncio.run(drive_diagnostic(
        problem="Diagnose",
        device_id="device-1",
        control_plane=FakeControlPlane(),
        max_steps=1,
        max_seconds=0.1,
        runner=slow_runner,
    ))

    assert result.final_report == "Stopped because the configured diagnostic time budget was exhausted."
    assert result.closed is True


def test_unconfirmed_session_close_is_reported():
    async def fake_runner(*args, **kwargs):
        return SimpleNamespace(final_output="No issue found.", raw_responses=[])

    result = asyncio.run(drive_diagnostic(
        problem="Diagnose",
        device_id="device-1",
        control_plane=FakeControlPlane(close_ok=False),
        max_steps=1,
        max_seconds=60,
        runner=fake_runner,
    ))

    assert result.closed is False
    assert "closure_unconfirmed" in result.final_report


def test_close_transport_failure_preserves_primary_outcome():
    async def fake_runner(agent, prompt, *, context, max_turns, hooks, run_config):
        first = await _submit_script(context.context, "Resolve-DnsName rmm-test-fileserver")
        await _wait_for_execution(context.context, first["execution_id"], 0.1)
        await _wait_for_execution(context.context, first["execution_id"], 5)
        second = await _submit_script(context.context, "Test-NetConnection rmm-test-fileserver -Port 445")
        await _wait_for_execution(context.context, second["execution_id"], 5)
        return SimpleNamespace(final_output="Primary finding.", raw_responses=[])

    control_plane = FakeControlPlane()
    control_plane.close_raises = True
    result = asyncio.run(drive_diagnostic(
        problem="Diagnose",
        device_id="device-1",
        control_plane=control_plane,
        max_steps=2,
        max_seconds=60,
        runner=fake_runner,
    ))

    assert result.completed is True
    assert result.closed is False
    assert result.close_error == "transport:ReadTimeout"
    assert result.final_report.startswith("Primary finding.")


def test_control_plane_client_authenticates_public_api_without_openai_key():
    requests = []

    def handler(request):
        requests.append(request)
        assert request.headers["Authorization"] == "Bearer operator-secret"
        assert "openai-secret" not in str(request.headers)
        if request.url.path.endswith("/executions"):
            assert request.headers["Idempotency-Key"].startswith("openai-driver-")
            return httpx.Response(202, json={"execution_id": "exec-1", "status": "queued"})
        if request.url.path == "/executions/exec-1/wait":
            return httpx.Response(200, json={"execution_id": "exec-1", "status": "completed", "terminal": True, "wait_timed_out": False})
        if request.url.path == "/executions/exec-1/output/stdout/search":
            assert request.url.params["query"] == "Tcp"
            assert request.url.params["after_byte"] == "0"
            return httpx.Response(200, json={
                "matches": [{"text": "TcpTestSucceeded: False", "context": {"before": "", "after": ""}}],
                "match_count": 1,
                "limit_reached": False,
                "next_after_byte": None,
                "partial": False,
                "capture_lost": False,
                "gap": {"detected": False, "reason": None},
            })
        raise AssertionError(request.url.path)

    client = ControlPlaneClient("http://control-plane.test", "operator-secret")
    client.client = httpx.AsyncClient(
        base_url="http://control-plane.test",
        headers={"Authorization": "Bearer operator-secret"},
        transport=httpx.MockTransport(handler),
    )

    assert asyncio.run(client.submit_execution("session-1", "Get-Date", timeout_seconds=1))["execution_id"] == "exec-1"
    assert asyncio.run(client.wait_execution("exec-1", 1))["terminal"] is True
    inspected = asyncio.run(client.inspect_output(
        "exec-1", "stdout", "search", {"query": "Tcp", "after_byte": 0}, timeout_seconds=1,
    ))
    assert inspected["matches"][0]["text"] == "TcpTestSucceeded: False"
    assert len(requests) == 3


def test_terminal_rendering_escapes_untrusted_control_sequences():
    result = SimpleNamespace(
        final_report="ok\x1b]0;pwned\x07\rbad",
        steps=[],
        model_latency_ms=0,
        total_ms=1,
        usage={},
        completed=True,
        closed=False,
        close_error="close\x1b[31m",
    )

    rendered = render_result(result)

    assert "\x1b" not in rendered
    assert "\r" not in rendered
    assert "\\x1b]0;pwned\\x07\\x0dbad" in rendered
    assert inert_text("a\x1b\rb") == "a\\x1b\\x0db"
