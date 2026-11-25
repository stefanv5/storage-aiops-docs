"""Replay a synthetic ENOSPC incident. No device or network access."""

import argparse
import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import datetime, timedelta
from pathlib import Path
from typing import Any


FIXTURE_PATH = Path(__file__).with_name("incident-chain.json")
APPLICATION_ID = 0x49434C42  # ICLB
SCHEMA_VERSION = 1
MOCK_JOB_ID = "mock-job-001"
MAX_CHECK_AGE_MINUTES = 5
LabRecord = dict[str, Any]


def parse_utc(value: str) -> datetime:
    if not value.endswith("Z"):
        raise ValueError("Fixture timestamps must end in Z.")
    return datetime.fromisoformat(value[:-1] + "+00:00")


def require_fields(record: Any, fields: dict[str, type], name: str) -> None:
    if not isinstance(record, dict):
        raise ValueError(f"{name} must be a JSON object.")
    for field, expected in fields.items():
        if type(record.get(field)) is not expected:
            raise ValueError(f"{name}.{field} must be {expected.__name__}.")


def load_fixture() -> LabRecord:
    fixture = json.loads(FIXTURE_PATH.read_text(encoding="utf-8"))
    require_fields(
        fixture,
        {
            "incident_id": str, "target": str, "clock_origin": str, "approver": str,
            "topology_revision": int, "volume_gib": int, "growth_gib": int,
            "pool_headroom_gib": int, "evidence": dict, "checks": dict,
        },
        "fixture",
    )
    parse_utc(fixture["clock_origin"])
    evidence_fields = {
        "application": {"error": str},
        "filesystem": {"size_gib": int, "free_gib": int, "free_inodes": int},
        "quota": {"remaining_gib": int},
        "pool": {"free_gib": int},
    }
    if fixture["evidence"].keys() != evidence_fields.keys():
        raise ValueError("Fixture evidence must include exactly the four incident records.")
    provenance = {"evidence_id": str, "source": str}
    times = {"observed_at": str, "available_at": str}
    for name, fields in evidence_fields.items():
        record = fixture["evidence"].get(name)
        require_fields(record, provenance | times | fields, f"evidence.{name}")
        parse_utc(record["observed_at"])
        parse_utc(record["available_at"])
    probe_fields = {"target": str, "observed_offset_minutes": int}
    business = {
        "filesystem_gib": int, "free_gib": int, "attempted_writes": int,
        "successful_writes": int, "readback_ok": bool,
    }
    protection = {"degraded_pgs": int, "pgs_not_active_clean": int, "scrub_errors": int}
    for name, fields in (
        ("business", business), ("protection", protection), ("stale-protection", protection),
    ):
        require_fields(fixture["checks"].get(name), provenance | probe_fields | fields, name)
    return fixture


def initialize(
    connection: sqlite3.Connection, fixture: LabRecord, scenario: str
) -> LabRecord:
    state = {
        "fixture": fixture,
        "scenario": scenario,
        "phase": "open",
        "clock_minute": 0,
        "topology_revision": fixture["topology_revision"],
        "volume_gib": fixture["volume_gib"],
        "quota_remaining_gib": fixture["evidence"]["quota"]["remaining_gib"],
        "pool_free_gib": fixture["evidence"]["pool"]["free_gib"],
    }
    connection.executescript(f"""
        BEGIN;
        PRAGMA application_id = {APPLICATION_ID};
        PRAGMA user_version = {SCHEMA_VERSION};
        CREATE TABLE incident_state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            payload TEXT NOT NULL
        );
        CREATE TABLE device_jobs (
            request_id TEXT PRIMARY KEY,
            job_id TEXT NOT NULL UNIQUE,
            target TEXT NOT NULL,
            size_gib INTEGER NOT NULL,
            completed INTEGER NOT NULL DEFAULT 0
        );
    """)
    with connection:
        connection.execute(
            "INSERT INTO incident_state VALUES (1, ?)", (json.dumps(state),)
        )
    return state


def read_state(connection: sqlite3.Connection) -> LabRecord:
    marker = connection.execute("PRAGMA application_id").fetchone()[0]
    if marker != APPLICATION_ID:
        raise sqlite3.DatabaseError("This file is not an incident chain database.")
    version = connection.execute("PRAGMA user_version").fetchone()[0]
    if version != SCHEMA_VERSION:
        raise sqlite3.DatabaseError("This incident chain database has an unsupported version.")
    tables = connection.execute(
        "SELECT name FROM sqlite_master "
        "WHERE type = 'table' AND name IN ('incident_state', 'device_jobs')"
    ).fetchall()
    if len(tables) != 2:
        raise sqlite3.DatabaseError("This incident chain database is missing required tables.")
    row = connection.execute("SELECT payload FROM incident_state WHERE id = 1").fetchone()
    if row is None:
        raise sqlite3.DatabaseError("This incident chain database has no state.")
    return json.loads(row[0])


def save_state(connection: sqlite3.Connection, state: LabRecord) -> None:
    connection.execute(
        "UPDATE incident_state SET payload = ? WHERE id = 1", (json.dumps(state),)
    )


def timestamp(state: LabRecord, minute: int) -> str:
    origin = parse_utc(state["fixture"]["clock_origin"])
    return (origin + timedelta(minutes=minute)).isoformat().replace("+00:00", "Z")


def diagnose(state: LabRecord) -> str:
    evidence = state["fixture"]["evidence"]
    cutoff = state["fixture"]["clock_origin"]
    cutoff_time = parse_utc(cutoff)
    if any(parse_utc(record["available_at"]) > cutoff_time for record in evidence.values()):
        return "insufficient_incident_evidence"
    filesystem = evidence["filesystem"]
    if not (
        evidence["application"]["error"] == "ENOSPC"
        and filesystem["size_gib"] == state["volume_gib"]
        and filesystem["free_gib"] == 0
        and filesystem["free_inodes"] > 0
        and evidence["quota"]["remaining_gib"] > 0
        and evidence["pool"]["free_gib"] > 0
    ):
        return "cause_unresolved"
    state["diagnosis"] = {
        "cause": "filesystem_full",
        "knowledge_cutoff": cutoff,
        "evidence_ids": [record["evidence_id"] for record in evidence.values()],
    }
    state["phase"] = "diagnosed"
    return "filesystem_full"


def plan_hash(plan: LabRecord) -> str:
    payload = json.dumps(plan, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return hashlib.sha256(payload).hexdigest()


def plan_expansion(state: LabRecord) -> str:
    fixture = state["fixture"]
    state["plan"] = {
        "incident_id": fixture["incident_id"],
        "target": fixture["target"],
        "action": "grow_volume_and_filesystem",
        "from_gib": state["volume_gib"],
        "to_gib": state["volume_gib"] + fixture["growth_gib"],
        "topology_revision": state["topology_revision"],
        "minimum_pool_headroom_gib": fixture["pool_headroom_gib"],
        "evidence_ids": state["diagnosis"]["evidence_ids"],
    }
    state["phase"] = "planned"
    return "plan_ready"


def approve(state: LabRecord, args: argparse.Namespace) -> str:
    plan = state["plan"]
    if args.approver != state["fixture"]["approver"]:
        return "approver_unauthorized"
    if args.target != plan["target"] or args.plan_hash != plan_hash(plan):
        return "approval_target_or_hash_mismatch"
    minute = state["clock_minute"]
    expiry = minute + args.valid_minutes
    state["approval"] = {
        "approver": args.approver,
        "target": args.target,
        "plan_hash": args.plan_hash,
        "approved_at": timestamp(state, minute),
        "expires_at": timestamp(state, expiry),
        "expires_minute": expiry,
    }
    state["phase"] = "approved"
    return "approved"


def preflight(state: LabRecord) -> str | None:
    plan = state["plan"]
    approval = state["approval"]
    if (
        approval["approver"] != state["fixture"]["approver"]
        or plan["target"] != state["fixture"]["target"]
        or approval["target"] != plan["target"]
        or approval["plan_hash"] != plan_hash(plan)
    ):
        return "approval_target_or_hash_mismatch"
    if state["clock_minute"] >= approval["expires_minute"]:
        return "approval_expired"
    if state["topology_revision"] != plan["topology_revision"]:
        return "topology_changed"
    if state["volume_gib"] != plan["from_gib"]:
        return "volume_size_changed"
    return None


def advance(connection: sqlite3.Connection, state: LabRecord) -> str:
    phase = state["phase"]
    if phase == "planned":
        return "approval_required"
    if phase == "approved":
        failure = preflight(state)
        if failure:
            state["phase"] = "needs_reapproval"
            return failure
        plan = state["plan"]
        growth = plan["to_gib"] - plan["from_gib"]
        if state["pool_free_gib"] - growth < plan["minimum_pool_headroom_gib"]:
            state["phase"] = "blocked"
            return "pool_headroom_insufficient"
        if state["quota_remaining_gib"] < growth:
            state["phase"] = "blocked"
            return "quota_headroom_insufficient"
        request_id = "expand-" + plan_hash(plan)
        state.update(phase="submission_unknown", request_id=request_id)
        save_state(connection, state)
        connection.commit()
        # The simulated device persists its receipt even though no response arrives.
        connection.execute(
            "INSERT INTO device_jobs (request_id, job_id, target, size_gib) VALUES (?, ?, ?, ?)",
            (request_id, MOCK_JOB_ID, plan["target"], plan["to_gib"]),
        )
        return "device_accepted_response_lost"
    if phase == "submission_unknown":
        job = connection.execute(
            "SELECT job_id, target, size_gib FROM device_jobs WHERE request_id = ?",
            (state["request_id"],),
        ).fetchone()
        plan = state["plan"]
        if job is None or (job[1], job[2]) != (plan["target"], plan["to_gib"]):
            state["phase"] = "needs_review"
            return "device_receipt_unconfirmed"
        state.update(phase="tracking", job_id=job[0])
        return "device_job_recovered"
    if phase == "tracking":
        plan = state["plan"]
        updated = connection.execute(
            "UPDATE device_jobs SET completed = 1 "
            "WHERE request_id = ? AND job_id = ? AND target = ? AND size_gib = ? "
            "AND completed = 0",
            (state["request_id"], state["job_id"], plan["target"], plan["to_gib"]),
        )
        if updated.rowcount != 1:
            state["phase"] = "needs_review"
            return "device_receipt_unconfirmed"
        growth = plan["to_gib"] - plan["from_gib"]
        state["pool_free_gib"] -= growth
        state["quota_remaining_gib"] -= growth
        state["volume_gib"] = plan["to_gib"]
        state["clock_minute"] += 1
        state["completed_minute"] = state["clock_minute"]
        state["phase"] = "verifying"
        return "device_job_completed"
    if phase == "verifying":
        return "awaiting_independent_checks"
    return "no_transition"


def assess_probe(state: LabRecord, check: str) -> LabRecord:
    if check == "protection" and state["scenario"] == "missing-protection":
        return {"status": "missing"}

    sample_name = check
    if check == "protection" and state["scenario"] == "stale-protection":
        sample_name = "stale-protection"
    sample = state["fixture"]["checks"][sample_name]
    observed = state["completed_minute"] + sample["observed_offset_minutes"]
    minute = state["clock_minute"]
    if sample["target"] != state["plan"]["target"]:
        status = "wrong_target"
    elif observed > minute:
        status = "not_yet_visible"
    elif observed <= state["completed_minute"] or minute - observed > MAX_CHECK_AGE_MINUTES:
        status = "stale"
    elif check == "business":
        passed = (
            sample["filesystem_gib"] == state["plan"]["to_gib"]
            and sample["free_gib"] > 0
            and 0 < sample["attempted_writes"] == sample["successful_writes"]
            and sample["readback_ok"]
        )
        status = "passed" if passed else "failed"
    else:
        passed = (
            sample["degraded_pgs"] == 0
            and sample["pgs_not_active_clean"] == 0
            and sample["scrub_errors"] == 0
        )
        status = "passed" if passed else "failed"
    return {
        **sample,
        "status": status,
        "observed_minute": observed,
        "observed_at": timestamp(state, observed),
    }


def verify(state: LabRecord, check: str) -> str:
    state[check] = assess_probe(state, check)
    results = (state.get("business"), state.get("protection"))
    # The second check may arrive well after the first one.
    minute = state["clock_minute"]
    for result in results:
        if (
            result
            and result["status"] == "passed"
            and minute - result["observed_minute"] > MAX_CHECK_AGE_MINUTES
        ):
            result["status"] = "stale"
    if all(result and result["status"] == "passed" for result in results):
        state["phase"] = "succeeded"
    return f"{check}_{state[check]['status']}"


def dispatch(connection: sqlite3.Connection, state: LabRecord, args: argparse.Namespace) -> str:
    action = args.action
    phase = state["phase"]
    if action == "diagnose" and phase == "open":
        return diagnose(state)
    if action == "plan" and phase == "diagnosed":
        return plan_expansion(state)
    if action == "approve" and phase == "planned":
        return approve(state, args)
    if action == "step":
        return advance(connection, state)
    if action == "advance-clock":
        state["clock_minute"] += args.minutes
        return "clock_advanced"
    if action == "drift-topology" and phase == "approved":
        state["topology_revision"] += 1
        return "topology_drift_injected"
    if action == "tighten-pool" and phase == "approved":
        state["pool_free_gib"] = state["plan"]["minimum_pool_headroom_gib"] + 2
        return "pool_pressure_injected"
    if action in {"verify-business", "verify-protection"} and phase == "verifying":
        return verify(state, action.removeprefix("verify-"))
    return "action_outside_current_phase"


def report(connection: sqlite3.Connection, state: LabRecord, message: str) -> LabRecord:
    fixture = state["fixture"]
    plan = state.get("plan")
    return {
        "incident_id": fixture["incident_id"],
        "target": fixture["target"],
        "phase": state["phase"],
        "message": message,
        "clock": timestamp(state, state["clock_minute"]),
        "scenario": state["scenario"],
        "topology_revision": state["topology_revision"],
        "volume_gib": state["volume_gib"],
        "pool_free_gib": state["pool_free_gib"],
        "diagnosis": state.get("diagnosis"),
        "plan": plan,
        "plan_hash": plan_hash(plan) if plan else None,
        "approval": state.get("approval"),
        "request_id": state.get("request_id"),
        "job_id": state.get("job_id"),
        "device_jobs": connection.execute("SELECT COUNT(*) FROM device_jobs").fetchone()[0],
        "business": state.get("business"),
        "protection": state.get("protection"),
    }


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path, help="dedicated SQLite file for this lab")
    actions = parser.add_subparsers(dest="action", required=True)
    init_parser = actions.add_parser("init")
    init_parser.add_argument(
        "--scenario",
        default="success",
        choices=("success", "missing-protection", "stale-protection"),
    )
    approval_parser = actions.add_parser("approve")
    approval_parser.add_argument("--approver", required=True)
    approval_parser.add_argument("--target", required=True)
    approval_parser.add_argument("--plan-hash", required=True)
    approval_parser.add_argument(
        "--valid-minutes", required=True, type=int, choices=range(1, 31)
    )
    clock_parser = actions.add_parser("advance-clock")
    clock_parser.add_argument("--minutes", required=True, type=int, choices=range(1, 61))
    for action in (
        "diagnose", "plan", "step", "status", "drift-topology", "tighten-pool",
        "verify-business", "verify-protection",
    ):
        actions.add_parser(action)
    args = parser.parse_args()

    exists = args.database.is_file()
    if not exists and args.action != "init":
        parser.error("Initialize a dedicated lab database first.")
    try:
        fixture = None if exists else load_fixture()
        with closing(sqlite3.connect(args.database)) as connection:
            if fixture is not None:
                state = initialize(connection, fixture, args.scenario)
                message = "initialized"
            else:
                state = read_state(connection)
                if args.action in {"init", "status"}:
                    message = "existing_state_preserved" if args.action == "init" else "status"
                else:
                    with connection:
                        message = dispatch(connection, state, args)
                        save_state(connection, state)
            print(json.dumps(report(connection, state, message)))
    except (OSError, sqlite3.Error, ValueError) as error:
        parser.exit(1, f"incident chain: {error}\n")


if __name__ == "__main__":
    main()
