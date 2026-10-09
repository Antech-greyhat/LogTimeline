#!/usr/bin/env python3
"""LogTimeline - build a chronological security timeline from an auth.log.

This file is the entry point. It handles only the command line, wiring the
pieces together, and turning expected problems into friendly messages. The
real work lives in the ``Core`` and ``Parsers`` packages.

Typical use:
    python3 LogTimeline.py                      # read /var/log/auth.log
    python3 LogTimeline.py --file PATH          # read a specific file
    python3 LogTimeline.py --format json        # machine-readable output
    python3 LogTimeline.py --help               # the full option list

Exit codes:
    0  success
    1  a runtime or input problem we handled (bad file, bad date, no events)
    2  a usage error on the command line (argparse's default)
"""

import sys

# Check the Python version before anything else. We rely on behavior that is
# only guaranteed on 3.9+, so we want a clear message rather than a confusing
# error later. This block avoids f-strings on purpose so it still runs on very
# old interpreters that would otherwise choke before printing anything.
if sys.version_info < (3, 9):
    sys.stderr.write(
        "LogTimeline needs Python 3.9 or newer. You are running "
        "{0}.{1}.\n".format(sys.version_info[0], sys.version_info[1])
    )
    raise SystemExit(1)

import argparse
import os

from Core.EventModel import ALL_EVENT_TYPES
from Core.TimeUtils import parse_user_datetime, UnsupportedTimestampError
from Core.TimelineBuilder import filter_events, sort_events, build_summary
from Core.Formatters import format_text, format_json
from Parsers.AuthLogParser import AuthLogParser


VERSION = "0.1.0"
DEFAULT_LOG_PATH = "/var/log/auth.log"

# Exit codes, named for readability (see the module docstring).
EXIT_OK = 0
EXIT_PROBLEM = 1


def build_arg_parser() -> argparse.ArgumentParser:
    """Create the argparse parser with every supported flag."""
    parser = argparse.ArgumentParser(
        prog="LogTimeline.py",
        description="Build a chronological security timeline from a Linux "
                    "auth.log file (SSH logins, failures, and sudo use).",
        epilog="v0.1 reads ISO 8601 auth.log files only. See the README for "
               "supported systems and the roadmap.",
    )
    parser.add_argument(
        "--file", default=DEFAULT_LOG_PATH, metavar="PATH",
        help="log file to read (default: %(default)s)",
    )
    parser.add_argument(
        "--since", metavar="DATE",
        help="only show events at or after this ISO date/datetime "
             "(no timezone means UTC)",
    )
    parser.add_argument(
        "--until", metavar="DATE",
        help="only show events at or before this ISO date/datetime "
             "(no timezone means UTC)",
    )
    parser.add_argument(
        "--type", action="append", dest="types",
        choices=list(ALL_EVENT_TYPES), metavar="NAME",
        help="only show this event type; repeat for several. One of: "
             + ", ".join(ALL_EVENT_TYPES),
    )
    parser.add_argument(
        "--format", choices=("text", "json"), default="text",
        help="output format (default: %(default)s)",
    )
    parser.add_argument(
        "--output", metavar="PATH",
        help="write the timeline to a file instead of the terminal",
    )
    parser.add_argument(
        "--local", action="store_true",
        help="show times in the machine's local timezone (text output only)",
    )
    parser.add_argument(
        "--show-gaps", action="store_true",
        help="show elapsed time since the previous event (text output only)",
    )
    parser.add_argument(
        "--no-color", action="store_true",
        help="disable colored output (also off automatically when the output "
             "is not a terminal or when NO_COLOR is set)",
    )
    parser.add_argument(
        "--version", action="version", version="LogTimeline " + VERSION,
    )
    return parser


def should_use_color(no_color_flag: bool, writing_to_file: bool) -> bool:
    """Decide whether to emit ANSI colors.

    Color is on only when ALL of these hold: the user did not pass
    ``--no-color``; the ``NO_COLOR`` environment variable is not set; we are
    writing to the terminal (not to a file); and stdout is really a terminal.
    """
    if no_color_flag:
        return False
    if os.environ.get("NO_COLOR") is not None:
        return False
    if writing_to_file:
        return False
    return sys.stdout.isatty()


def read_events(path: str):
    """Open ``path`` read-only and parse it into events (streaming).

    Returns ``(events, parser)`` so the caller can read the parser's counters
    for the summary. Lets the usual ``OSError`` subclasses propagate
    (``FileNotFoundError``, ``PermissionError``, ...) for the caller to handle.
    """
    parser = AuthLogParser()
    events = []
    # Mode "r" is read-only: we never open the log for writing or appending.
    # errors="replace" means one malformed byte becomes the Unicode
    # replacement character instead of crashing the whole run.
    with open(path, "r", encoding="utf-8", errors="replace") as handle:
        for event in parser.parse_file(handle):
            events.append(event)
    return events, parser


def _file_not_found_message(path: str) -> str:
    return (
        "Could not find the log file '{0}'.\n"
        "  - Check the path, or point at another file with --file.\n"
        "  - Some systems are journal-only and have no /var/log/auth.log by\n"
        "    default (for example Debian 12+ and Arch Linux). Reading the\n"
        "    systemd journal is planned for v0.2.\n"
    ).format(path)


def _permission_message(path: str) -> str:
    return (
        "Permission denied reading '{0}'.\n"
        "  - Auth logs are usually readable only by root or the 'adm' group.\n"
        "  - Try again with sudo, or add your user to the 'adm' group:\n"
        "        sudo usermod -aG adm $USER   (then log out and back in)\n"
    ).format(path)


def _classic_format_message(path: str, classic_count: int) -> str:
    return (
        "No events recognized in '{0}'.\n"
        "  - {1} line(s) look like the classic syslog format, for example\n"
        "    'Oct  8 07:39:51 ...', which has no year and no timezone.\n"
        "  - v0.1 supports ISO 8601 timestamps only, so that format is not\n"
        "    supported yet. See Docs/SupportedSystems.md for details.\n"
    ).format(path, classic_count)


def main(argv=None) -> int:
    """Run the tool. Returns an exit code (0 ok, 1 handled problem).

    ``argv`` lets tests call ``main(["--file", ...])`` directly; when it is
    ``None`` argparse reads the real command line.
    """
    parser = build_arg_parser()
    args = parser.parse_args(argv)

    # Parse the time filters early so a bad value fails fast and clearly.
    since = None
    until = None
    try:
        if args.since:
            since = parse_user_datetime(args.since)
        if args.until:
            until = parse_user_datetime(args.until)
    except UnsupportedTimestampError as error:
        sys.stderr.write("Problem with a date filter: {0}\n".format(error))
        return EXIT_PROBLEM

    if since is not None and until is not None and since > until:
        sys.stderr.write("Problem with date filters: --since must be at or before --until.\n")
        return EXIT_PROBLEM

    if args.output:
        try:
            same_file = os.path.exists(args.output) and os.path.samefile(args.file, args.output)
        except OSError:
            same_file = False
        if same_file:
            sys.stderr.write("Refusing to overwrite the input log with --output. Choose a different path.\n")
            return EXIT_PROBLEM

    # Read and parse the log file, turning common failures into friendly text.
    try:
        all_events, log_parser = read_events(args.file)
    except FileNotFoundError:
        sys.stderr.write(_file_not_found_message(args.file))
        return EXIT_PROBLEM
    except PermissionError:
        sys.stderr.write(_permission_message(args.file))
        return EXIT_PROBLEM
    except IsADirectoryError:
        sys.stderr.write(
            "'{0}' is a directory, not a file. Point --file at an auth.log "
            "file.\n".format(args.file)
        )
        return EXIT_PROBLEM
    except OSError as error:
        # Catch-all for other I/O problems (e.g. a broken symlink) so the user
        # sees a message instead of a raw traceback.
        sys.stderr.write(
            "Could not read '{0}': {1}\n".format(args.file, error)
        )
        return EXIT_PROBLEM

    # Case: the file had no usable lines at all.
    if log_parser.lines_read == 0:
        sys.stderr.write(
            "The file '{0}' is empty - there is nothing to show.\n".format(
                args.file
            )
        )
        return EXIT_PROBLEM

    # Case: we read lines but recognized no events.
    if not all_events:
        if log_parser.classic_format_lines > 0:
            sys.stderr.write(
                _classic_format_message(args.file, log_parser.classic_format_lines)
            )
        else:
            sys.stderr.write(
                "No recognized events in '{0}': read {1} line(s), skipped all "
                "{1}. Nothing matched the event types v0.1 understands.\n".format(
                    args.file, log_parser.lines_read
                )
            )
        return EXIT_PROBLEM

    # Filter first (fewer events to sort), then sort by UTC time.
    selected = filter_events(all_events, since=since, until=until, types=args.types)
    ordered = sort_events(selected)

    summary = build_summary(
        ordered,
        lines_read=log_parser.lines_read,
        lines_skipped=log_parser.lines_skipped,
    )

    writing_to_file = args.output is not None
    use_color = should_use_color(args.no_color, writing_to_file)

    if args.format == "json":
        rendered = format_json(ordered, summary, use_local=args.local)
    else:
        rendered = format_text(
            ordered, summary, use_local=args.local, use_color=use_color,
            show_gaps=args.show_gaps,
        )

    # Send the result to a file or to standard output.
    if writing_to_file:
        try:
            with open(args.output, "w", encoding="utf-8") as out:
                out.write(rendered + "\n")
        except OSError as error:
            sys.stderr.write(
                "Could not write to '{0}': {1}\n".format(args.output, error)
            )
            return EXIT_PROBLEM
        # Confirmation on stderr so it does not pollute piped output.
        sys.stderr.write(
            "Wrote {0} event(s) to '{1}'.\n".format(len(ordered), args.output)
        )
    else:
        sys.stdout.write(rendered + "\n")

    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
