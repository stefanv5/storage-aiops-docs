"""Replay a synthetic volume-expansion workflow using a local SQLite file."""

import argparse
import json
import sqlite3
from contextlib import closing
from pathlib import Path


REQUEST_ID = "expand-volume-01-v1"
DEVICE_JOB_ID = "mock-job-001"


def initialize(connection: sqlite3.Connection) -> None:
    """Seed an approved plan and a simulated device without resetting progress."""
    connection.executescript(
        """
        BEGIN;
        CREATE TABLE IF NOT EXISTS state (
            id INTEGER PRIMARY KEY CHECK (id = 1),
            phase TEXT NOT NULL,
            approved_revision INTEGER NOT NULL,
            topology_revision INTEGER NOT NULL,
            request_id TEXT NOT NULL UNIQUE,
            job_id TEXT,
            business_ok INTEGER NOT NULL,
            protection_ok INTEGER NOT NULL
        );
        CREATE TABLE IF NOT EXISTS device_jobs (
            request_id TEXT PRIMARY KEY,
            job_id TEXT NOT NULL UNIQUE,
            poll_count INTEGER NOT NULL DEFAULT 0
        );
        COMMIT;
        """
    )
    with connection:
        connection.execute(
            "INSERT OR IGNORE INTO state VALUES (1, 'approved', 7, 7, ?, NULL, 0, 0)",
            (REQUEST_ID,),
        )


def read_state(connection: sqlite3.Connection) -> sqlite3.Row:
    return connection.execute("SELECT * FROM state WHERE id = 1").fetchone()


def advance(connection: sqlite3.Connection) -> str:
    """Advance one step so every CLI invocation can start a fresh process."""
    state = read_state(connection)
    phase = state["phase"]

    if phase == "approved":
        with connection:
            if state["approved_revision"] != state["topology_revision"]:
                connection.execute("UPDATE state SET phase = 'needs_reapproval'")
                return "Topology changed after approval. Nothing was submitted."
            connection.execute("UPDATE state SET phase = 'submission_unknown'")
        # The simulated device commits independently before its response is lost.
        with connection:
            connection.execute(
                "INSERT INTO device_jobs (request_id, job_id) VALUES (?, ?)",
                (state["request_id"], DEVICE_JOB_ID),
            )
        return "The device accepted the request, but the worker lost the response."

    if phase == "submission_unknown":
        job = connection.execute(
            "SELECT job_id FROM device_jobs WHERE request_id = ?", (state["request_id"],)
        ).fetchone()
        with connection:
            if job is None:
                connection.execute("UPDATE state SET phase = 'needs_review'")
                return "The device did not confirm receipt. Hand off for reconciliation."
            connection.execute(
                "UPDATE state SET phase = 'tracking', job_id = ?", (job["job_id"],)
            )
        return "Recovered the existing device job without issuing another request."

    if phase == "tracking":
        with connection:
            poll = connection.execute(
                "UPDATE device_jobs SET poll_count = poll_count + 1 "
                "WHERE job_id = ? RETURNING poll_count",
                (state["job_id"],),
            ).fetchone()
            if poll["poll_count"] == 1:
                return "The device still reports the job as running."
            connection.execute("UPDATE state SET phase = 'verifying', business_ok = 1")
        return "Device job completed. Business checks passed, protection is still pending."

    if phase == "verifying":
        if not (state["business_ok"] and state["protection_ok"]):
            return "The workflow remains open until both verification signals pass."
        with connection:
            connection.execute("UPDATE state SET phase = 'succeeded'")
        return "Business and protection checks both passed."

    return "No additional state transition is available."


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("database", type=Path, help="SQLite file used only by this lab")
    parser.add_argument(
        "action", choices=["init", "status", "step", "drift-topology", "verify-protection"]
    )
    args = parser.parse_args()
    if args.action != "init" and not args.database.is_file():
        parser.error("Initialize a lab database before issuing this action.")

    with closing(sqlite3.connect(args.database)) as connection:
        connection.row_factory = sqlite3.Row
        message = "Status read from the local lab database."
        if args.action == "init":
            initialize(connection)
            message = "Local lab initialized. Existing progress is preserved."
        elif args.action == "step":
            message = advance(connection)
        elif args.action == "drift-topology":
            with connection:
                changed = connection.execute(
                    "UPDATE state SET topology_revision = topology_revision + 1 "
                    "WHERE phase = 'approved'"
                )
                if changed.rowcount == 0:
                    parser.error("Topology drift is injected before submission in this lab.")
            message = "Injected a topology change after approval."
        elif args.action == "verify-protection":
            with connection:
                changed = connection.execute(
                    "UPDATE state SET protection_ok = 1 WHERE phase = 'verifying'"
                )
                if changed.rowcount == 0:
                    parser.error("Protection verification follows device job completion.")
            message = "Injected an independent successful protection check."

        state = dict(read_state(connection))
        job_count = connection.execute("SELECT COUNT(*) FROM device_jobs").fetchone()[0]
        print(json.dumps({"message": message, "state": state, "device_jobs": job_count}))


if __name__ == "__main__":
    main()
