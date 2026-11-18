"""Programmatic and interactive ADK Runner with persistent sessions and HITL resume loop."""

from __future__ import annotations

import argparse
import asyncio
import sys
import uuid
from typing import Any

from opsguardian.config import OpsGuardianConfig
from opsguardian.observability.logging import get_logger
from opsguardian.observability.tracing import get_tracer

logger = get_logger("runner")


def _write_ui(text: str) -> None:
    """Write interactive CLI output without using bare ``print()`` statements."""
    sys.stdout.write(text + "\n")
    sys.stdout.flush()


async def run_turn(
    *,
    runner: Any,
    user_id: str,
    session_id: str,
    prompt_text: str,
    auto_approve: bool | None = None,
) -> str:
    """Execute one user turn, handling ADK ``adk_request_confirmation`` HITL pauses."""
    from google.adk.tools.tool_confirmation import ToolConfirmation
    from google.genai import types

    tracer = get_tracer("opsguardian.runner")
    final_texts: list[str] = []

    with tracer.start_as_current_span(
        "opsguardian.invocation",
        attributes={"opsguardian.session_id": session_id, "opsguardian.user_id": user_id},
    ):
        message = types.Content(role="user", parts=[types.Part.from_text(text=prompt_text)])
        pending_confirmations: dict[str, Any] = {}

        async for event in runner.run_async(
            user_id=user_id,
            session_id=session_id,
            new_message=message,
        ):
            actions = getattr(event, "actions", None)
            if actions and getattr(actions, "requested_tool_confirmations", None):
                pending_confirmations.update(actions.requested_tool_confirmations)

            content = getattr(event, "content", None)
            if content and getattr(content, "parts", None):
                for part in content.parts:
                    if getattr(part, "text", None) and event.is_final_response():
                        final_texts.append(part.text)

        # Resume any paused high-stakes HITL confirmation requests
        for call_id, confirmation in pending_confirmations.items():
            hint = getattr(confirmation, "hint", "Approve pending high-stakes action?")
            _write_ui(f"\n[HITL APPROVAL GATE] {hint}")
            if auto_approve is None:
                answer = input("Approve execution? [y/N]: ").strip().lower()
                approved = answer in {"y", "yes"}
            else:
                approved = auto_approve

            decision_payload = ToolConfirmation(
                hint=hint,
                confirmed=approved,
                payload=getattr(confirmation, "payload", None),
            )
            resume_msg = types.Content(
                role="user",
                parts=[
                    types.Part(
                        function_response=types.FunctionResponse(
                            id=call_id,
                            name="adk_request_confirmation",
                            response=decision_payload.model_dump(by_alias=True),
                        )
                    )
                ],
            )
            async for resumed_event in runner.run_async(
                user_id=user_id,
                session_id=session_id,
                new_message=resume_msg,
            ):
                content = getattr(resumed_event, "content", None)
                if content and getattr(content, "parts", None):
                    for part in content.parts:
                        if getattr(part, "text", None) and resumed_event.is_final_response():
                            final_texts.append(part.text)

    return "\n".join(final_texts).strip()


async def run_interactive(session_id: str | None = None, user_id: str = "sre-oncall") -> None:
    """Start an interactive multi-turn incident triage session backed by persistent DB."""
    from google.adk.runners import Runner

    from opsguardian.agent import build_opsguardian_app
    from opsguardian.memory.session_factory import (
        create_memory_service,
        create_session_service,
    )

    config = OpsGuardianConfig.from_env()
    adk_app, consolidator = build_opsguardian_app(config)
    session_service = create_session_service(config)
    memory_service = create_memory_service(config)

    runner = Runner(
        app=adk_app,
        session_service=session_service,
        memory_service=memory_service,
    )

    sid = session_id or f"inc-{uuid.uuid4().hex[:8]}"
    existing = await session_service.get_session(
        app_name=config.app_name, user_id=user_id, session_id=sid
    )
    if existing is None:
        await session_service.create_session(
            app_name=config.app_name, user_id=user_id, session_id=sid
        )

    _write_ui("=" * 72)
    _write_ui(f"OpsGuardian Live Session | session_id={sid} | env={config.env}")
    _write_ui(f"Routing: fast={config.fast_model} | reasoning={config.reasoning_model}")
    _write_ui("Type 'exit' or 'quit' to end (background memory tasks flush automatically).")
    _write_ui("=" * 72)

    try:
        while True:
            user_input = input("\nsre> ").strip()
            if not user_input:
                continue
            if user_input.lower() in {"exit", "quit"}:
                break
            response = await run_turn(
                runner=runner,
                user_id=user_id,
                session_id=sid,
                prompt_text=user_input,
            )
            _write_ui(f"\n[OpsGuardian]\n{response}")
    finally:
        logger.log_event("runner.shutdown", "Flushing pending async memory tasks before exit.")
        await consolidator.flush(timeout=10.0)


def main() -> None:
    parser = argparse.ArgumentParser(description="Run OpsGuardian interactive ADK Runner.")
    parser.add_argument("--interactive", action="store_true", help="Start interactive REPL.")
    parser.add_argument("--session-id", default=None, help="Resume an existing session ID.")
    parser.add_argument("--user-id", default="sre-oncall", help="Operator user ID.")
    args = parser.parse_args()
    asyncio.run(run_interactive(session_id=args.session_id, user_id=args.user_id))


if __name__ == "__main__":
    main()
