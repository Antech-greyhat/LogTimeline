# Contributing to LogTimeline

Thanks for taking a look! LogTimeline is a learning-focused, open-source
project, and friendly contributions of every size are welcome — including a
one-line note telling us which distro you tested on.

This guide is intentionally short.

---

## Ground rules (what keeps the project simple)

- **Standard library only.** No third-party packages, ever. If a feature seems
  to need one, open an issue to discuss first.
- **Readable over clever.** This project doubles as a way to learn Python.
  Prefer short functions that do one thing, with clear names.
- **Type hints and docstrings** on every module, class and function.
- **Comments explain _why_**, especially around log-parsing and timezone
  decisions.
- **PascalCase** for files and folders (`AuthLogParser.py`, `Samples/`). The
  conventional exceptions keep their standard names: `README.md`, `LICENSE`,
  `CONTRIBUTING.md`, `.gitignore`, and Python's `__init__.py`.
- **Read-only and safe.** The tool never writes near a source log, never shells
  out (`subprocess`, `os.system`, `eval`, `exec`, `pickle` are off-limits), and
  never makes network connections.

---

## Running the tests

From the repository root:

```bash
python3 -m unittest discover -s Tests -p "Test*.py" -t .
```

The `-p "Test*.py"` pattern is required because our test files are PascalCase;
the default discovery pattern only looks for lowercase `test*.py`.

Run a single test module while developing:

```bash
python3 -m unittest Tests.TestAuthLogParser -v
```

Please make sure the whole suite passes before opening a pull request, and add
tests for anything you change.

---

## How to add a new event type

Event recognition lives in **one** place. To add a type:

1. Add a constant to `EventType` in [`Core/EventModel.py`](Core/EventModel.py)
   and to the `ALL_EVENT_TYPES` tuple just below it.
2. Add a recognizer for it in
   [`Parsers/AuthLogParser.py`](Parsers/AuthLogParser.py) — a narrow regex and
   a short branch in the matching `_recognize_*` method.
3. Add a test in [`Tests/TestAuthLogParser.py`](Tests/TestAuthLogParser.py)
   using a **real** example line (documentation-reserved IPs only).

That is it — the timeline, filters, summary and output formats all work from
the shared `Event`, so they pick up the new type automatically.

**Please do not invent log formats.** If you cannot verify a message against a
real line, treat it as unsupported and say so, rather than guessing.

---

## Reporting which distro you tested on

This is genuinely useful and takes a minute. Run:

```bash
# 1. Confirm the file and its timestamp format
head -n 1 /var/log/auth.log

# 2. Run the tool against a small slice
python3 LogTimeline.py --file /var/log/auth.log | tail -n 20
```

Then open an issue titled `Distro report: <name> <version>` and paste:

- your distro and version (e.g. `Ubuntu 24.04`),
- the **first field only** of one log line (so we can see the timestamp
  format) — scrub anything sensitive,
- whether the tool worked, and the summary footer it printed.

**Never paste real usernames, IP addresses or hostnames.** Replace them with
`REDACTED` or documentation-reserved values.

---

## Sample data rules

All files in `Samples/` are **synthetic**. If you add one:

- use only documentation-reserved IP ranges: `192.0.2.0/24`,
  `198.51.100.0/24`, `203.0.113.0/24`;
- never include a real hostname, username, or address;
- keep timestamps in the ISO 8601 format the tool supports.

---

## Reporting a security issue responsibly

If you find a security problem (for example a way to defeat the terminal-output
sanitizing, or a crash on crafted input), **please do not open a public issue
with a working exploit.** Instead, open a minimal private report — a GitHub
security advisory on the repository, or a short issue that says only "security
issue, please advise where to send details" — and we will follow up. Give us a
reasonable chance to fix it before any public disclosure.

Thank you for helping keep LogTimeline simple, honest and safe.
