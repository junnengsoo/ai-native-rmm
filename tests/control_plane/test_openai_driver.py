import asyncio
import json
from types import SimpleNamespace

import httpx
import pytest
from agents import Model, ModelResponse, RunContextWrapper
from agents.usage import InputTokensDetails, OutputTokensDetails, Usage
from openai.types.responses import ResponseFunctionToolCall, ResponseOutputMessage, ResponseOutputText

from control_plane.openai_driver import (
    DEFAULT_PAGE_LIMIT_BYTES,
    DIAGNOSTIC_SCRIPTS,
    ControlPlaneClient,
    DiagnosticContext,
    DriverError,
    _run_diagnostic,
    build_agent,
    build_script,
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
        self.events_seen = []
        self.pages = []

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

    async def submit_execution(self, session_id, script, timeout_ms, *, timeout_seconds):
        assert session_id == "session-1"
        assert "Remove-Item" not in script
        assert any(command in script for command in ("Test-NetConnection", "Resolve-DnsName"))
        assert 100 <= timeout_ms <= 20_000
        self.submitted.append((script, timeout_ms))
        return {"execution_id": "exec-1", "status": "queued"}

    async def output_events(self, execution_id, stream, *, after, wait_ms, timeout_seconds):
        assert execution_id == "exec-1"
        self.events_seen.append((stream, after, wait_ms))
        if stream == "stdout" and after == "0":
            return {
                "events": [{"cursor": "1", "text": "event text", "byte_count": 10, "created_at": "now"}],
                "next_cursor": "1",
                "terminal": True,
                "more_available": False,
            }
        return {"events": [], "next_cursor": after, "terminal": True, "more_available": False}

    async def get_execution(self, execution_id, *, timeout_seconds):
        assert execution_id == "exec-1"
        return {
            "status": "completed",
            "invocation_outcome": "completed_normally",
            "exit_code": 0,
            "duration_ms": 42.0,
            "capture": {"loss_detected": False},
            "output_preview": {
                "stdout": {"text": "TcpTestSucceeded: False\n", "shortened": True},
                "stderr": {"text": "", "shortened": False},
            },
        }

    async def output_page(self, execution_id, stream, after, *, timeout_seconds):
        self.pages.append((execution_id, stream, after))
        if after == "0":
            return {
                "text": "first page",
                "next_cursor": "2",
                "more_available": True,
                "capture_lost": False,
                "gap": {"detected": False, "reason": None},
            }
        return {
            "text": "second page",
            "next_cursor": "3",
            "more_available": False,
            "capture_lost": False,
            "gap": {"detected": False, "reason": None},
        }


def test_agent_uses_agents_sdk_tools_without_raw_powershell():
    agent = build_agent("gpt-5-nano")

    assert agent.model == "gpt-5-nano"
    assert [tool.name for tool in agent.tools] == ["run_diagnostic"]
    assert "run_powershell" not in {tool.name for tool in agent.tools}
    assert agent.model_settings.parallel_tool_calls is False
    assert agent.model_settings.max_tokens == 600
    schema = agent.tools[0].params_json_schema["properties"]
    assert set(schema) == {"operation", "timeout_ms"}
    assert schema["timeout_ms"]["minimum"] == 100
    assert schema["timeout_ms"]["maximum"] == 60000


def test_fixed_templates_are_read_only_and_quote_inputs():
    assert set(DIAGNOSTIC_SCRIPTS) == {"network_config", "default_gateway_ping", "dns_resolution", "target_ping", "tcp_port"}
    script = build_script("tcp_port", "rmm-test-fileserver", 445)

    assert "Test-NetConnection" in script
    assert "$TargetHost = 'rmm-test-fileserver'" in script
    assert "$Port = 445" in script
    for operation in DIAGNOSTIC_SCRIPTS:
        template = build_script(operation, "server-1", 445)
        assert "Remove-Item" not in template
        assert "Set-" not in template
        assert "New-" not in template


def test_invalid_target_or_port_never_builds_script():
    with pytest.raises(DriverError):
        build_script("tcp_port", "server; Remove-Item C:\\important", 445)
    with pytest.raises(DriverError):
        build_script("tcp_port", "server", 0)


def test_run_diagnostic_uses_public_api_long_poll_pages_with_continuation_and_tracks_timing_outside_tool_output():
    progress = []
    control_plane = FakeControlPlane()
    ctx = DiagnosticContext(control_plane, "session-1", 9999999999.0, 2, progress_callback=progress.append)

    output = asyncio.run(_run_diagnostic(ctx, "tcp_port", 5000))

    assert output["execution_id"] == "exec-1"
    assert output["stdout"]["text"] == "TcpTestSucceeded: False\n"
    assert output["stdout_more_available"] is True
    assert [page["after"] for page in output["stdout_pages"]] == ["0", "2"]
    assert [page["page"]["text"] for page in output["stdout_pages"]] == ["first page", "second page"]
    assert control_plane.pages == [("exec-1", "stdout", "0"), ("exec-1", "stdout", "2")]
    assert "api_round_trip_ms" not in output
    assert [step.tool for step in ctx.steps] == ["run_diagnostic:tcp_port", "output_page:stdout", "output_page:stdout"]
    assert ctx.steps[0].execution_ms == 42.0
    assert ctx.diagnostics_run == 1
    assert progress[0]["text"]["text"] == "event text"


def test_real_agents_sdk_function_tool_invokes_bound_context_and_schema():
    tool = build_agent("gpt-5-nano").tools[0]
    control_plane = FakeControlPlane()
    ctx = DiagnosticContext(control_plane, "session-1", 9999999999.0, 2)
    tool_context = RunContextWrapper(ctx, usage=SimpleNamespace())

    payload = asyncio.run(tool.on_invoke_tool(tool_context, json.dumps({"operation": "tcp_port", "timeout_ms": 5000})))

    assert payload["operation"] == "tcp_port"
    assert len(control_plane.submitted) == 1
    assert "rmm-test-fileserver" in control_plane.submitted[0][0]
    assert "$Port = 445" in control_plane.submitted[0][0]


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

    async def get_response(self, *args, **kwargs):
        self.calls += 1
        if self.calls == 1:
            output = [ResponseFunctionToolCall(
                type="function_call",
                call_id="call-1",
                name="run_diagnostic",
                arguments=json.dumps({"operation": "dns_resolution", "timeout_ms": 5000}),
            )]
        elif self.calls == 2:
            output = [ResponseFunctionToolCall(
                type="function_call",
                call_id="call-2",
                name="run_diagnostic",
                arguments=json.dumps({"operation": "tcp_port", "timeout_ms": 5000}),
            )]
        else:
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


def test_real_agents_sdk_runner_loop_makes_dependent_tool_calls_and_reports():
    model = ScriptedModel()
    result = asyncio.run(drive_diagnostic(
        problem="Why can Windows not reach the test share?",
        device_id="device-1",
        control_plane=FakeControlPlane(),
        model=model,
        max_steps=3,
        max_seconds=60,
    ))

    assert model.calls == 3
    assert result.completed is True
    assert result.final_report == "DNS resolves, but SMB TCP 445 is unreachable."
    assert [step.tool for step in result.steps if step.tool.startswith("run_diagnostic")] == [
        "run_diagnostic:dns_resolution",
        "run_diagnostic:tcp_port",
    ]


def test_drive_diagnostic_delegates_loop_to_runner_and_closes_session():
    async def fake_runner(agent, prompt, *, context, max_turns, hooks, run_config):
        assert [tool.name for tool in agent.tools] == ["run_diagnostic"]
        assert "Budget: at most 2 diagnostic tool calls" in prompt
        assert max_turns == 3
        assert run_config.tracing_disabled is True
        await hooks.on_llm_start(None, agent, None, [])
        await hooks.on_llm_end(None, agent, None)
        await _run_diagnostic(context.context, "dns_resolution", 5000)
        await _run_diagnostic(context.context, "tcp_port", 5000)
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
    assert len([step for step in result.steps if step.tool.startswith("run_diagnostic")]) == 2
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
    assert "required multi-step diagnostic depth" in result.final_report


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
        await _run_diagnostic(context.context, "dns_resolution", 5000)
        await _run_diagnostic(context.context, "tcp_port", 5000)
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
        if request.url.path == "/executions/exec-1/output/stdout/events":
            return httpx.Response(200, json={"events": [], "next_cursor": "0", "terminal": True})
        if request.url.path == "/executions/exec-1/output/stdout":
            assert request.url.params["limit_bytes"] == str(DEFAULT_PAGE_LIMIT_BYTES)
            return httpx.Response(200, json={
                "text": "page",
                "next_cursor": "1",
                "more_available": False,
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

    assert asyncio.run(client.submit_execution("session-1", "Get-Date", 1000, timeout_seconds=1))["execution_id"] == "exec-1"
    assert asyncio.run(client.output_events("exec-1", "stdout", after="0", wait_ms=50, timeout_seconds=1))["terminal"] is True
    assert asyncio.run(client.output_page("exec-1", "stdout", "0", timeout_seconds=1))["text"] == "page"
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
