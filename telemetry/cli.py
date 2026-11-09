import argparse
import json
import sys
import httpx
from telemetry.scenarios.catalog import (
    SCENARIO_DEFINITIONS,
    generate_attack_mode_telemetry,
    generate_full_simulation_suite,
    generate_normal_mode_telemetry,
    generate_scenario_events,
)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="ThreatLens Synthetic Security Telemetry Generator CLI (Supports NORMAL MODE and ATTACK SIMULATION MODE)"
    )
    parser.add_argument(
        "--mode",
        type=str,
        choices=["normal", "attack", "all"],
        default=None,
        help="Generator mode: 'normal' (NORMAL MODE), 'attack' (ATTACK SIMULATION MODE), or 'all'",
    )
    parser.add_argument(
        "--scenario",
        type=str,
        default="all",
        help="Scenario ID to generate (or 'normal_mode', 'attack_mode', 'all')",
    )
    parser.add_argument(
        "--volume",
        type=int,
        default=1,
        help="Volume multiplier (1-20)",
    )
    parser.add_argument(
        "--api-url",
        type=str,
        default="http://localhost:8000/api/events/bulk",
        help="ThreatLens bulk ingestion endpoint URL",
    )
    parser.add_argument(
        "--no-detections",
        action="store_true",
        help="Ingest events into PostgreSQL without running alert detections",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print generated events as JSON without sending to API",
    )
    args = parser.parse_args()

    effective_mode = (args.mode or args.scenario).lower()
    if effective_mode in ("normal", "normal_mode"):
        events = generate_normal_mode_telemetry(volume_multiplier=args.volume)
    elif effective_mode in ("attack", "attack_mode", "attack_simulation"):
        events = generate_attack_mode_telemetry(volume_multiplier=args.volume)
    elif effective_mode == "all":
        events = generate_full_simulation_suite()
    else:
        valid_ids = {s["id"] for s in SCENARIO_DEFINITIONS}
        if args.scenario not in valid_ids:
            print(f"Error: Unknown scenario '{args.scenario}'. Valid options: {sorted(valid_ids)}", file=sys.stderr)
            return 1
        events = generate_scenario_events(args.scenario, volume_multiplier=args.volume)

    if args.dry_run:
        print(
            json.dumps(
                {
                    "mode": args.mode or args.scenario,
                    "synthetic_labeled": all(e.get("is_synthetic") is True for e in events),
                    "count": len(events),
                    "events": events,
                },
                indent=2,
            )
        )
        return 0

    run_detections = not args.no_detections
    print(
        f"Sending {len(events)} synthetic telemetry events (mode={effective_mode}, run_detections={run_detections}) to {args.api_url} ..."
    )
    with httpx.Client(timeout=15.0) as client:
        resp = client.post(args.api_url, json={"events": events, "run_detections": run_detections})
        print(f"HTTP {resp.status_code}: {resp.text}")
        return 0 if resp.status_code < 400 else 1


if __name__ == "__main__":
    raise SystemExit(main())

