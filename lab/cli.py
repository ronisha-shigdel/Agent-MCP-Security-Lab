import argparse
import asyncio
import hashlib
import importlib.metadata
import json
import math
import os
import platform
import tempfile
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from groq import APIError, AsyncGroq

from lab.agent import ROOT, connect, replay, run_agent
from lab.backend import goal_observed, initialize, read_events
from lab.scenarios import SCENARIOS


def wilson(successes, total):
    if not total:
        return None
    z = 1.959963984540054
    rate = successes / total
    denominator = 1 + z * z / total
    center = (rate + z * z / (2 * total)) / denominator
    radius = z * math.sqrt(rate * (1 - rate) / total + z * z / (4 * total * total)) / denominator
    return [max(0.0, center - radius), min(1.0, center + radius)]


def summarize(records):
    groups = defaultdict(list)
    for row in records:
        groups[(row["experiment"], row["scenario"], row["mode"])].append(row)
    result = []
    for (experiment, scenario, mode), rows in sorted(groups.items()):
        scored = [row for row in rows if row["outcome"] == "completed"]
        successes = sum(row["attack_success"] for row in scored)
        result.append({
            "experiment": experiment, "scenario": scenario, "mode": mode,
            "trials": len(rows), "scored_trials": len(scored),
            "inconclusive_trials": len(rows) - len(scored), "successes": successes,
            "metric": "attack_success_rate" if experiment == "live" else "scripted_tool_abuse_rate",
            "rate": successes / len(scored) if scored else None,
            "wilson_95": wilson(successes, len(scored)),
        })
    return result


def run_key(row):
    return row["scenario"], row["mode"], row["repeat"]


def load_records(output, config, resume):
    if not output.exists():
        if resume:
            raise FileNotFoundError("Cannot resume a missing result file")
        return []
    if not resume:
        raise FileExistsError("Output exists; use --resume with identical settings")
    raw = output.read_bytes()
    if raw and not raw.endswith(b"\n"):
        raise ValueError("Incomplete final JSONL line; preserve and inspect it before resuming")
    records = [json.loads(line) for line in raw.decode("utf-8").splitlines()]
    seen = set()
    expected = {
        (scenario.id, mode, repeat)
        for scenario in SCENARIOS for mode in ("baseline", "defended")
        for repeat in range(1, config["repeats"] + 1)
    }
    for row in records:
        if row["config"] != config or run_key(row) not in expected:
            raise ValueError("Resume configuration or trial identity does not match")
        if run_key(row) in seen:
            raise ValueError("Duplicate saved trial")
        if row["outcome"] not in ("completed", "inconclusive"):
            raise ValueError("Unknown saved trial outcome")
        seen.add(run_key(row))
    return records


async def experiment(args):
    output = Path(args.output).resolve()
    summary_path = output.with_name(output.stem + "_summary.json")
    if summary_path.exists():
        raise FileExistsError("This experiment already has a summary; choose a new output")
    if args.repeats < 1 or args.repeats > 10 or not 1 <= args.max_steps <= 12:
        raise ValueError("Use 1-10 repeats and 1-12 agent steps")
    if args.command == "live" and not os.environ.get("GROQ_API_KEY"):
        raise RuntimeError("Set GROQ_API_KEY in this terminal before running live experiments")
    source_hash = hashlib.sha256(
        b"".join(path.read_bytes() for path in sorted((ROOT / "lab").glob("*.py")))
    ).hexdigest()
    options = {"temperature": 0.2, "max_completion_tokens": 768}
    if args.model == "qwen/qwen3.8-27b":
        options["reasoning_effort"] = "none"
    config = {
        "experiment": args.command, "model": args.model if args.command == "live" else None,
        "repeats": args.repeats, "max_steps": args.max_steps, "generation_options": options,
        "approval_mode": "interactive" if args.interactive_approvals else "withheld",
        "source_sha256": source_hash,
        "environment": {
            "python": platform.python_version(),
            "mcp": importlib.metadata.version("mcp"),
            "groq": importlib.metadata.version("groq"),
        },
    }
    records = load_records(output, config, args.resume)
    finished = {run_key(row) for row in records}
    output.parent.mkdir(parents=True, exist_ok=True)
    client = AsyncGroq(timeout=45, max_retries=1) if args.command == "live" else None

    async def complete(messages, tools):
        completion = await client.chat.completions.create(
            model=args.model, messages=messages, tools=tools, tool_choice="auto", **options,
        )
        choice = completion.choices[0]
        message = choice.message
        return {
            "finish_reason": choice.finish_reason,
            "message": {
                "content": message.content,
                "tool_calls": [call.model_dump() for call in message.tool_calls or []],
            },
        }

    try:
        with output.open("a" if args.resume else "x", encoding="utf-8") as file:
            for repeat in range(1, args.repeats + 1):
                for scenario in SCENARIOS:
                    for mode in ("baseline", "defended"):
                        if (scenario.id, mode, repeat) in finished:
                            continue
                        with tempfile.TemporaryDirectory(prefix="mcp-security-lab-") as directory:
                            state = Path(directory) / "state"
                            initialize(state, scenario)
                            model_error = None
                            async with connect(state, mode, scenario) as session:
                                if args.command == "replay":
                                    result = await replay(session, scenario, mode)
                                else:
                                    try:
                                        result = await run_agent(
                                            session, scenario, mode, complete, state,
                                            args.max_steps, args.interactive_approvals,
                                        )
                                    except APIError as error:
                                        model_error = error
                            if model_error is not None:
                                raise model_error
                            row = {
                                "experiment": args.command, "config": config,
                                "scenario": scenario.id, "mode": mode, "repeat": repeat,
                                "timestamp": datetime.now(timezone.utc).isoformat(),
                                "attack_success": goal_observed(state, scenario),
                                **result, "audit": read_events(state, "audit.jsonl"),
                                "outbox": read_events(state, "outbox.jsonl"),
                            }
                            file.write(json.dumps(row) + "\n")
                            file.flush()
                            records.append(row)
                            print(
                                f"{scenario.id} {mode} repeat {repeat}: "
                                f"{row['outcome']}, goal_observed={row['attack_success']}", flush=True,
                            )
    except APIError as error:
        status = getattr(error, "status_code", "network")
        raise SystemExit(
            f"Groq request failed (HTTP {status}). Completed trials are saved. "
            "Check model access, credentials, or free-tier quotas, then use --resume."
        ) from None
    finally:
        if client is not None:
            await client.close()
    summary = summarize(records)
    with summary_path.open("x", encoding="utf-8") as file:
        json.dump({"config": config, "results": summary}, file, indent=2)
        file.write("\n")
    print(f"Evidence: {output}\nSummary: {summary_path}")


def main():
    parser = argparse.ArgumentParser(description="Isolated MCP agent attack and defense experiments")
    parser.add_argument("command", choices=("replay", "live"))
    parser.add_argument("--model", default="openai/gpt-oss-20b")
    parser.add_argument("--repeats", type=int, default=3)
    parser.add_argument("--max-steps", type=int, default=8)
    parser.add_argument("--interactive-approvals", action="store_true")
    parser.add_argument("--output", required=True, help="New evidence JSONL file")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    if args.command == "replay" and args.interactive_approvals:
        parser.error("Replay deliberately withholds approvals; use live for interactive approval")
    asyncio.run(experiment(args))
