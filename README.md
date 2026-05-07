# Secure System Observer (SSO)

The Secure System Observer is a protected Linux terminal application for monitoring operating system health. It uses authentication, salted password hashing, role-based access control, process monitoring through `/proc`, secure log snapshots, and SHA-256 integrity checks.

This version includes a **Rich terminal interface** with a live moving dashboard for CPU, RAM, Swap, process counts, process states, and top processes.

## 1. Requirements

Use Ubuntu or another Linux system that has `/proc` available.

Install Python and Rich:

```bash
sudo apt update
sudo apt install -y python3 python3-pip
python3 -m pip install -r requirements.txt
```

## 2. Create the demo users

Run this once before launching the app:

```bash
python3 init_users.py
```

Demo accounts:

| Username | Password | Role |
|---|---|---|
| admin | AdminPass123! | Administrator |
| auditor | AuditPass123! | Auditor |

The passwords are not stored in plain text. They are stored as PBKDF2-HMAC-SHA256 hashes with a unique salt for each user.

## 3. Launch SSO

```bash
python3 main.py
```

The older plain text menu is still included as:

```bash
python3 main_basic.py
```

## 4. Rich interface features

The live dashboard shows:

- CPU usage percentage
- load average
- system uptime
- RAM used, available, and total
- Swap used, free, and total
- moving CPU/RAM/Swap charts
- moving process-count chart
- top processes by CPU and memory
- process state counts such as Running, Sleeping, Zombie, and Idle Kernel

Inside the live dashboard, press:

```text
q
```

to return to the menu.

## 5. Role-based access control

### Administrator

The Administrator can:

- view the safe live dashboard
- view the restricted live dashboard
- view process owner, UID, PPID, and command-line details
- create logs
- verify logs
- delete logs
- view the audit log

### Auditor

The Auditor can:

- view the safe live dashboard
- view basic process stats
- view memory metrics
- create basic snapshot logs
- verify logs
- view the audit log

The Auditor cannot:

- view restricted process details
- open the restricted live dashboard
- delete log files

If the Auditor tries a blocked action, the app denies it and records a `SECURITY_ALERT` in `data/audit.log`.

## 6. Recommended live demo steps

Use these steps for the project presentation.

1. Start the program with `python3 main.py`.
2. Attempt a bad login to show failed authentication.
3. Log in as `auditor` using `auditor / AuditPass123!`.
4. Open the live performance dashboard and show the moving CPU/RAM/Swap charts.
5. Press `q` to return to the menu.
6. Try the restricted dashboard as Auditor.
7. Show that access is denied and a `SECURITY_ALERT` is recorded.
8. Create a snapshot log.
9. Verify the log integrity and show that it passes.
10. Manually edit the log file in `data/snapshots/`.
11. Verify the same log again and show that the integrity check fails.
12. Log in as `admin` using `admin / AdminPass123!`.
13. Open the restricted dashboard and show the extra owner, UID, and command-line details.
14. Delete a log file as Admin to show Admin privileges.

## 7. How the OS data is collected

SSO reads Linux kernel-exposed runtime data from the `/proc` virtual file system.

Examples:

- `/proc/[pid]/stat` gives process state and CPU timing information.
- `/proc/[pid]/status` gives memory usage such as RSS and virtual memory size.
- `/proc/meminfo` gives RAM and Swap information.
- `/proc/stat` gives CPU counters used to calculate CPU usage.
- `/proc/loadavg` gives 1-minute, 5-minute, and 15-minute load averages.
- `/proc/uptime` gives system uptime.

## 8. Integrity checking

When a snapshot is created, SSO writes a `.log` file and immediately creates a matching `.sha256` file.

Later, when the user verifies the log, SSO recalculates the SHA-256 hash of the log file. If the current hash does not match the saved hash, the app reports that the log may have been altered.

## 9. Project rubric match

### Functionality

- Retrieves PIDs
- Retrieves process states
- Retrieves RAM and Swap
- Creates system snapshot logs
- Saves metadata such as timestamp, username, role, and OS user ID
- Verifies log integrity with SHA-256

### Security

- Requires login before launch
- Uses salted password hashing
- Enforces Administrator and Auditor roles
- Blocks restricted Auditor actions
- Records access denial as security alerts

### Code quality

The code is split into clear modules:

- `sso/security.py` for authentication, hashing, RBAC, and audit events
- `sso/monitor.py` for OS monitoring and `/proc` parsing
- `sso/logging_integrity.py` for snapshot logs and hash verification
- `main.py` for the Rich terminal interface
- `main_basic.py` for the older simple CLI version
