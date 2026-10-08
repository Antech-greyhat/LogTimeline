# Supported Systems

LogTimeline v0.1 is defined **by capability, not by distribution name**. It
supports:

> **Any Linux system that has a readable `/var/log/auth.log` whose lines use
> ISO 8601 timestamps** (for example `2026-10-08T07:39:51.894612-04:00`).

If that sentence describes your machine, the tool should work. If it does not,
this page explains why and what is planned.

---

## Why "capability, not distro"

Whether `/var/log/auth.log` exists depends on which logging software is
installed, not on the distribution's name:

- **Debian 12 (Bookworm) and later** no longer install `rsyslog` by default.
  A fresh install logs **only** to the systemd journal, so there is **no**
  `/var/log/auth.log` until `rsyslog` (or similar) is installed.
- **Arch Linux** has no `auth.log` by default either (journal-only unless you
  install `syslog-ng` or `rsyslog`).
- Two machines running the "same" distro can therefore differ, depending on
  whether a syslog daemon is present.

Rather than claim support for distro names we have not verified, v0.1 states
the one thing that actually matters: *is there a readable ISO 8601 `auth.log`?*

---

## Status table

| System | Status | Notes |
| --- | --- | --- |
| **Kali Linux** (with `/var/log/auth.log`) | Tested | Verified by the author on Kali in a VM. This is the reference platform. |
| **Ubuntu** | Untested, expected to work *if* `auth.log` exists | Not verified by the author. Please report your result. |
| **Parrot OS** | Untested, expected to work *if* `auth.log` exists | Not verified by the author. Please report your result. |
| **Debian 12+** | Not supported yet (journal-only by default) | No `auth.log` unless you install `rsyslog`. Journald support is planned. |
| **Arch Linux** | Not supported yet (journal-only by default) | No `auth.log` unless you install a syslog daemon. Journald support is planned. |
| **systemd journal (journald)** | Planned (v0.2) | Reading the journal directly is the next milestone. |

"Untested" means exactly that: the format is the same, so it *should* work, but
the author has not run it there and will not claim otherwise.

---

## Check your own machine in 30 seconds

**1. Does the file exist and can you read it?**

```bash
ls -l /var/log/auth.log
```

- *No such file* → your system is probably journal-only (see below).
- *Permission denied* → you are not in the `adm` group; see the Security Notes
  in the README.

**2. What timestamp format does it use?** Look at the first field of a line:

```bash
head -n 1 /var/log/auth.log
```

- Starts with a year, like `2026-10-08T07:39:51.894612-04:00` → **ISO 8601**,
  supported.
- Starts with a month name, like `Oct  8 07:39:51` → **classic syslog**, not
  supported yet (no year, no timezone — see below).

**3. Journal-only? Confirm with:**

```bash
journalctl -t sshd -t sudo --no-pager | tail
```

If that shows events but `/var/log/auth.log` is missing, you are journal-only
and should wait for v0.2 (or install `rsyslog` to get an `auth.log`).

---

## Why the classic syslog format is not supported yet

A classic line looks like:

```
Oct  8 07:39:51 kali sudo: ...
```

It has **no year** and **no timezone offset**. LogTimeline's whole job is to
sort events correctly across different offsets by converting everything to UTC.
A timestamp with no offset cannot be converted without guessing, and a
timestamp with no year is ambiguous around New Year. Rather than guess and risk
ordering events wrongly, v0.1 detects this format and tells you it is not
supported yet. Parsing it (using file metadata or an assumed year/timezone) is
on the roadmap.

---

## Roadmap for broader support

- **v0.2** — systemd journal (journald) adapter, which covers Debian 12+ and
  Arch out of the box.
- **v0.3** — classic syslog timestamp format, plus rotated and gzipped logs
  (`auth.log.1`, `auth.log.2.gz`).

See the README roadmap for the full picture.
