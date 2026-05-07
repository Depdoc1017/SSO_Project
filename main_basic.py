"""Secure System Observer CLI entry point."""

from __future__ import annotations

from pathlib import Path
from typing import Dict

from sso.logging_integrity import create_snapshot, delete_log_pair, list_logs, verify_log
from sso.monitor import enumerate_processes, format_memory_report
from sso.security import AccessDenied, AuthError, audit_event, prompt_login, require_role


def print_process_table(processes: list[dict[str, str]], restricted: bool = False) -> None:
    if not processes:
        print("No processes found or /proc is unavailable.")
        return

    if restricted:
        print(f"{'PID':<8} {'PPID':<8} {'STATE':<18} {'UID':<8} {'OWNER':<14} {'NAME':<22} CMDLINE")
        print("-" * 115)
        for p in processes:
            state = f"{p['state_code']} {p['state']}"
            cmd = p.get("cmdline", "")[:80]
            print(f"{p['pid']:<8} {p.get('ppid','?'):<8} {state:<18} {p.get('uid','?'):<8} {p.get('owner','?'):<14} {p['name']:<22} {cmd}")
    else:
        print(f"{'PID':<8} {'STATE':<18} NAME")
        print("-" * 55)
        for p in processes:
            state = f"{p['state_code']} {p['state']}"
            print(f"{p['pid']:<8} {state:<18} {p['name']}")


def choose_log() -> Path | None:
    logs = list_logs()
    if not logs:
        print("No snapshot logs found.")
        return None

    print("\nAvailable logs:")
    for i, path in enumerate(logs, start=1):
        print(f"{i}. {path.name}")

    choice = input("Choose log number: ").strip()
    if not choice.isdigit() or not (1 <= int(choice) <= len(logs)):
        print("Invalid selection.")
        return None
    return logs[int(choice) - 1]


def show_menu(user: Dict[str, str]) -> None:
    while True:
        print("\n=== Secure System Observer ===")
        print(f"Logged in as: {user['username']} ({user['role']})")
        print("1. View basic process stats")
        print("2. View restricted process details [Administrator only]")
        print("3. View memory metrics")
        print("4. Snapshot current system state to log")
        print("5. Verify log integrity")
        print("6. Delete a log file [Administrator only]")
        print("7. Exit")
        choice = input("Select option: ").strip()

        try:
            if choice == "1":
                processes = enumerate_processes(include_restricted_details=False, limit=30)
                print_process_table(processes, restricted=False)

            elif choice == "2":
                require_role(user, {"Administrator"}, "view restricted process details")
                processes = enumerate_processes(include_restricted_details=True, limit=30)
                print_process_table(processes, restricted=True)

            elif choice == "3":
                print("\n" + format_memory_report())

            elif choice == "4":
                include_restricted = user["role"] == "Administrator"
                path = create_snapshot(user, include_restricted_details=include_restricted)
                print(f"Snapshot saved: {path}")
                print(f"Hash saved: {path}.sha256")

            elif choice == "5":
                path = choose_log()
                if path:
                    ok = verify_log(path)
                    if ok:
                        print("Integrity check PASSED. Log has not been changed.")
                    else:
                        print("Integrity check FAILED. Log may have been altered.")
                        audit_event("SECURITY_ALERT", f"Integrity check failed for {path.name}", user["username"])

            elif choice == "6":
                require_role(user, {"Administrator"}, "delete log files")
                path = choose_log()
                if path:
                    delete_log_pair(path, user["username"])
                    print("Log and hash file deleted.")

            elif choice == "7":
                audit_event("LOGOUT", "User exited SSO", user["username"])
                print("Goodbye.")
                break

            else:
                print("Invalid option.")

        except AccessDenied as e:
            print(str(e))
        except FileNotFoundError as e:
            print(f"File error: {e}")
        except PermissionError as e:
            print(f"Permission error: {e}")
        except Exception as e:  # classroom-friendly error handling
            print(f"Unexpected error: {e}")
            audit_event("ERROR", str(e), user.get("username", "unknown"))


def main() -> None:
    print("Secure System Observer login required.")
    try:
        user = prompt_login()
    except AuthError as e:
        print(e)
        return
    show_menu(user)


if __name__ == "__main__":
    main()
