#!/usr/bin/env python3
"""
AirDrop Observatory TUI (macOS)

Terminal UI to observe AirDrop behavior during discovery/transfer by
collecting live telemetry from macOS subsystems.

Data sources:
  - Unified logs (sharingd, AirDrop, AWDL hints)
  - awdl0 interface status + live packet counters
  - Bonjour browse for AirDrop service advertisement
  - sharingd socket visibility via lsof
  - (Optional) packet capture on awdl0 via tcpdump (requires sudo/root)

Security model:
  - Passive observation only.
  - No decryption of payloads.

Usage:
  python3 airdrop_observatory.py [--tcpdump] [--logfile FILE] [--log-format text|jsonl]

Controls:
  TAB / left/right  Switch channel tabs
  s                 Start monitoring
  x                 Stop monitoring
  c                 Clear current channel
  C                 Clear all channels
  e                 Export all logs to file
  /                 Enter filter mode (regex)
  ESC               Clear filter / exit filter mode
  G                 Resume auto-scroll (jump to bottom)
  g                 Jump to top
  q                 Quit

Log format (text):
  {ISO8601} {LEVEL:5} [{CHANNEL:10}] {message}

Log format (jsonl):
  {"ts":"...","epoch":...,"level":"...","channel":"...","source":"...","msg":"..."}

Requirements:
  Python 3.6+ (stdlib only — no external dependencies)
  macOS (uses macOS-specific tools: log, dns-sd, ifconfig, lsof)
"""

from __future__ import annotations

import argparse
import curses
import enum
import json
import os
import queue
import re
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional, TextIO, Tuple


# ---------------------------------------------------------------------------
# Unified log record
# ---------------------------------------------------------------------------

class Level(enum.IntEnum):
    """Log severity levels, ordered by increasing severity."""

    DEBUG = 10
    INFO = 20
    WARN = 30
    ERROR = 40

    def tag(self) -> str:
        """Fixed-width 5-char tag for text formatting."""
        return self.name.ljust(5)


@dataclass(frozen=True)
class LogRecord:
    """Immutable structured log record — the single unit of data across
    all channels, display buffers, file sinks, and exports.

    Every line produced by any worker or the engine itself passes through
    this structure before reaching a buffer or file.
    """

    timestamp_utc: str          # ISO 8601 with microseconds
    timestamp_epoch: float      # time.time() for sorting/math
    level: Level
    channel: str                # display channel: "sharingd", "airdrop", etc.
    source: str                 # originating worker or "engine"
    message: str                # the payload text

    # -- Formatters --------------------------------------------------------

    def format_text(self) -> str:
        """Render as a fixed-layout text line.

        Format:
          2026-02-24T18:24:34.123456Z INFO  [sharingd  ] peer discovered ...
        """
        return (
            f"{self.timestamp_utc} {self.level.tag()} "
            f"[{self.channel:<10}] {self.message}"
        )

    def format_jsonl(self) -> str:
        """Render as a single-line JSON object (JSONL / ndjson)."""
        obj = {
            "ts": self.timestamp_utc,
            "epoch": self.timestamp_epoch,
            "level": self.level.name,
            "channel": self.channel,
            "source": self.source,
            "msg": self.message,
        }
        return json.dumps(obj, ensure_ascii=False, separators=(",", ":"))

    def format_display(self) -> str:
        """Short format for TUI display (channel omitted — shown by tab).

        Format:
          18:24:34.123 INFO  message text here
        """
        try:
            t_part = self.timestamp_utc.split("T")[1].rstrip("Z")
            hms_ms = t_part[:12]  # HH:MM:SS.mmm
        except (IndexError, ValueError):
            hms_ms = "??:??:??.???"
        return f"{hms_ms} {self.level.tag()} {self.message}"


def _make_record(
    level: Level, channel: str, source: str, message: str
) -> LogRecord:
    """Create a LogRecord stamped with the current UTC time."""
    now = time.time()
    dt = datetime.fromtimestamp(now, tz=timezone.utc)
    iso = dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond:06d}Z"
    return LogRecord(
        timestamp_utc=iso,
        timestamp_epoch=now,
        level=level,
        channel=channel,
        source=source,
        message=message,
    )


def _infer_level(text: str) -> Level:
    """Infer severity from ad-hoc bracket-prefixed tags in worker output."""
    if text.startswith("[error]"):
        return Level.ERROR
    if text.startswith("[warn]"):
        return Level.WARN
    if text.startswith("[status]"):
        return Level.INFO
    return Level.DEBUG


# ---------------------------------------------------------------------------
# File log sink
# ---------------------------------------------------------------------------

class FileSink:
    """Thread-safe append-only file writer for LogRecords.

    Writes one record per line, flushed immediately (line-buffered).
    """

    def __init__(self, path: str, fmt: str = "text") -> None:
        self._lock = threading.Lock()
        self._fh: TextIO = open(path, "a", encoding="utf-8", buffering=1)
        self._formatter: Callable[[LogRecord], str] = (
            LogRecord.format_jsonl if fmt == "jsonl" else LogRecord.format_text
        )

    def write(self, record: LogRecord) -> None:
        """Append a single record."""
        line = self._formatter(record)
        with self._lock:
            self._fh.write(line + "\n")

    def close(self) -> None:
        """Flush and close the underlying file."""
        with self._lock:
            self._fh.flush()
            self._fh.close()


# ---------------------------------------------------------------------------
# Subprocess workers
# ---------------------------------------------------------------------------

@dataclass
class ProcSpec:
    """Specification for a monitored subprocess."""

    name: str
    argv: List[str]
    requires_root: bool = False
    coalesce: bool = False  # merge continuation lines into parent record


class StreamWorker(threading.Thread):
    """Run a long-lived subprocess, emit stdout lines as LogRecords.

    When coalesce=True on the ProcSpec, consecutive lines are merged into
    a single LogRecord whenever a line does NOT start with the macOS
    unified-log compact timestamp pattern (YYYY-MM-DD HH:MM:SS.nnn).
    This handles multi-line entries like setAwdlSequence arrays.
    """

    # macOS `log stream --style compact` entry prefix
    _RE_LOG_ENTRY = re.compile(r"^\d{4}-\d{2}-\d{2}\s+\d{2}:\d{2}:\d{2}\.\d+\s")

    # Separator used when flattening continuation lines for single-line output
    CONTINUATION_SEP = " \u23ce "  # ⏎ visible return symbol

    def __init__(
        self,
        spec: ProcSpec,
        channel: str,
        out_queue: "queue.Queue[LogRecord]",
        stop_event: threading.Event,
    ) -> None:
        super().__init__(daemon=True)
        self.spec = spec
        self.channel = channel
        self.out_queue = out_queue
        self.stop_event = stop_event
        self.proc: Optional[subprocess.Popen[str]] = None
        self._pending: Optional[str] = None  # buffered head line for coalesce

    def _emit(self, level: Level, msg: str) -> None:
        self.out_queue.put(
            _make_record(level, self.channel, self.spec.name, msg)
        )

    def _flush_pending(self) -> None:
        """Emit the buffered coalesced line, if any."""
        if self._pending is not None:
            self._emit(_infer_level(self._pending), self._pending)
            self._pending = None

    def run(self) -> None:
        if self.spec.requires_root and os.geteuid() != 0:
            self._emit(Level.INFO, "skipped — requires root (run with sudo)")
            return

        try:
            cmd_str = " ".join(self.spec.argv)
            self._emit(Level.INFO, f"starting: {cmd_str}")
            self.proc = subprocess.Popen(
                self.spec.argv,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
                bufsize=1,
                preexec_fn=os.setsid if hasattr(os, "setsid") else None,
            )
        except FileNotFoundError:
            self._emit(Level.ERROR, "command not found")
            return
        except PermissionError:
            self._emit(Level.ERROR, "permission denied")
            return
        except Exception as exc:
            self._emit(Level.ERROR, f"failed to start: {exc!r}")
            return

        assert self.proc is not None and self.proc.stdout is not None

        try:
            while not self.stop_event.is_set():
                line = self.proc.stdout.readline()
                if line == "":
                    code = self.proc.poll()
                    self._flush_pending()
                    self._emit(Level.INFO, f"process exited (code={code})")
                    break
                stripped = line.rstrip("\n")

                if not self.spec.coalesce:
                    # Simple mode: one line = one record
                    self._emit(_infer_level(stripped), stripped)
                    continue

                # Coalesce mode: buffer lines until next entry header
                if self._RE_LOG_ENTRY.match(stripped):
                    # New entry starts — flush the previous one
                    self._flush_pending()
                    self._pending = stripped
                else:
                    # Continuation line — append to pending
                    if self._pending is not None:
                        self._pending += self.CONTINUATION_SEP + stripped.strip()
                    else:
                        # Orphan continuation (before first entry) — emit standalone
                        self._emit(Level.DEBUG, stripped)

        finally:
            self._flush_pending()
            self._kill()
            self._emit(Level.INFO, "stopped")

    def _kill(self) -> None:
        if not self.proc:
            return
        try:
            if hasattr(os, "killpg") and self.proc.pid:
                os.killpg(self.proc.pid, signal.SIGTERM)
            else:
                self.proc.terminate()
        except Exception:
            pass


class PollWorker(threading.Thread):
    """Periodically run a command and emit output as LogRecords."""

    def __init__(
        self,
        name: str,
        channel: str,
        poll_seconds: float,
        argv: List[str],
        out_queue: "queue.Queue[LogRecord]",
        stop_event: threading.Event,
        requires_root: bool = False,
    ) -> None:
        super().__init__(daemon=True)
        self.name = name
        self.channel = channel
        self.poll_seconds = poll_seconds
        self.argv = argv
        self.out_queue = out_queue
        self.stop_event = stop_event
        self.requires_root = requires_root

    def _emit(self, level: Level, msg: str) -> None:
        self.out_queue.put(
            _make_record(level, self.channel, self.name, msg)
        )

    def run(self) -> None:
        if self.requires_root and os.geteuid() != 0:
            self._emit(Level.INFO, "skipped — requires root")
            return

        cmd_str = " ".join(self.argv)
        self._emit(Level.INFO, f"polling every {self.poll_seconds:.1f}s: {cmd_str}")

        while not self.stop_event.is_set():
            try:
                res = subprocess.run(
                    self.argv,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    text=True,
                    timeout=self.poll_seconds * 2,
                    check=False,
                )
                for raw_line in res.stdout.rstrip("\n").split("\n"):
                    self._emit(Level.DEBUG, raw_line)
            except FileNotFoundError:
                self._emit(Level.ERROR, "command not found")
                break
            except PermissionError:
                self._emit(Level.ERROR, "permission denied")
                break
            except subprocess.TimeoutExpired:
                self._emit(Level.WARN, "poll timed out")
            except Exception as exc:
                self._emit(Level.ERROR, f"poll failed: {exc!r}")
                break

            slept = 0.0
            while slept < self.poll_seconds and not self.stop_event.is_set():
                time.sleep(min(0.2, self.poll_seconds - slept))
                slept += 0.2

        self._emit(Level.INFO, "stopped")


class CallablePollWorker(threading.Thread):
    """Periodically call a Python function and emit results as LogRecords."""

    def __init__(
        self,
        name: str,
        channel: str,
        poll_seconds: float,
        fn: Callable[[], List[Tuple[Level, str]]],
        out_queue: "queue.Queue[LogRecord]",
        stop_event: threading.Event,
    ) -> None:
        super().__init__(daemon=True, name=f"callable-{name}")
        self.worker_name = name
        self.channel = channel
        self.poll_seconds = poll_seconds
        self.fn = fn
        self.out_queue = out_queue
        self.stop_event = stop_event

    def _emit(self, level: Level, msg: str) -> None:
        self.out_queue.put(_make_record(level, self.channel, self.worker_name, msg))

    def run(self) -> None:
        self._emit(Level.INFO, "started")
        while not self.stop_event.is_set():
            try:
                results = self.fn()
                for level, msg in results:
                    self._emit(level, msg)
            except Exception as exc:
                self._emit(Level.ERROR, f"poll fn failed: {exc!r}")
            slept = 0.0
            while slept < self.poll_seconds and not self.stop_event.is_set():
                time.sleep(min(0.2, self.poll_seconds - slept))
                slept += 0.2
        self._emit(Level.INFO, "stopped")


# ---------------------------------------------------------------------------
# Channel / buffer management
# ---------------------------------------------------------------------------

MAX_BUFFER_LINES: int = 10000

CHANNELS: List[str] = [
    "sharingd",
    "airdrop",
    "awdl0_if",
    "awdl0_cnt",
    "bonjour",
    "sockets",
    "tcpdump",
]

WORKER_TO_CHANNEL: Dict[str, str] = {
    "sharingd_log": "sharingd",
    "airdrop_log": "airdrop",
    "awdl0_status": "awdl0_if",
    "awdl0_counters": "awdl0_cnt",
    "bonjour_browse": "bonjour",
    "sharingd_sockets": "sockets",
    "tcpdump_awdl0": "tcpdump",
    # Security monitoring (activated by --security)
    "prefs_watchdog": "security",
    "quarantine_checker": "security",
    "filetype_scanner": "security",
    "net_listener_checker": "security",
    "callservicesd_log": "callservicesd",
    "rapportd_log": "rapportd",
    "studentd_log": "studentd",
}


class ChannelBuffer:
    """Thread-safe ring buffer of LogRecords for a single channel."""

    def __init__(self, max_lines: int = MAX_BUFFER_LINES) -> None:
        self._lock = threading.Lock()
        self._records: List[LogRecord] = []
        self._max = max_lines
        self.new_count: int = 0

    def append(self, record: LogRecord) -> None:
        """Add a record."""
        with self._lock:
            self._records.append(record)
            if len(self._records) > self._max:
                del self._records[: len(self._records) - self._max]
            self.new_count += 1

    def get_records(self) -> List[LogRecord]:
        """Return a snapshot of all records."""
        with self._lock:
            return list(self._records)

    def clear(self) -> None:
        """Clear all records."""
        with self._lock:
            self._records.clear()
            self.new_count = 0

    def mark_viewed(self) -> None:
        """Reset new-record counter."""
        with self._lock:
            self.new_count = 0

    @property
    def count(self) -> int:
        """Current record count."""
        with self._lock:
            return len(self._records)


# ---------------------------------------------------------------------------
# Highlight rules — keyword patterns for visual emphasis + tooltips
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class HighlightRule:
    """A pattern that triggers visual highlighting and a hover tooltip."""

    pattern: "re.Pattern[str]"
    color_pair_idx: int   # curses color pair number (assigned in TUI init)
    marker: str           # gutter character for flagged lines
    category: str         # short category label
    tooltip: str          # explanation shown on mouse hover / click

    def finditer(self, text: str) -> List[Tuple[int, int, "HighlightRule"]]:
        """Return (start, end, rule) for every non-overlapping match."""
        return [
            (m.start(), m.end(), self)
            for m in self.pattern.finditer(text)
        ]


# Color pair indices 10-14 are reserved for highlights (set up in TUI init).
# Rules are evaluated in order; first match per character position wins.
HIGHLIGHT_RULES: List[HighlightRule] = [
    # -- Discovery / Bonjour --
    HighlightRule(
        pattern=re.compile(
            r"(?i)\b(?:discover\w*|peer\s*(?:found|lost|appear|disappear)"
            r"|browse\w*|Bonjour|_airdrop\._tcp|Add|Rmv|resolved)\b"
        ),
        color_pair_idx=10,
        marker="\u25c6",  # ◆
        category="discovery",
        tooltip="AirDrop discovery: peer/service advertisement via Bonjour/mDNS",
    ),
    # -- Transfer lifecycle --
    HighlightRule(
        pattern=re.compile(
            r"(?i)\b(?:transfer\w*|send\w*|receiv\w*|accept\w*"
            r"|reject\w*|declin\w*|cancel\w*|askPerm\w*"
            r"|prepareSend\w*|handleAsk\w*)\b"
        ),
        color_pair_idx=11,
        marker="\u25b6",  # ▶
        category="transfer",
        tooltip="AirDrop file transfer event: send/receive/accept/reject lifecycle",
    ),
    # -- AWDL / radio layer --
    HighlightRule(
        pattern=re.compile(
            r"(?i)\b(?:AWDL|awdl0|wlan0[:\s]com\.apple\.p2p"
            r"|setChannel\w*|setAwdl\w*|chanSeq\w*|TxMinRate"
            r"|channelSequence\w*|AWDL\s*ON|AWDL\s*OFF)\b"
        ),
        color_pair_idx=12,
        marker="\u2637",  # ☷ (radio/wave)
        category="awdl",
        tooltip="AWDL radio layer: channel sequence, power state, Wi-Fi peer-to-peer",
    ),
    # -- Security / identity --
    HighlightRule(
        pattern=re.compile(
            r"(?i)\b(?:identity|certificate|cert\b|TLS|validation"
            r"|hash\w*|encrypt\w*|decrypt\w*|verify\w*"
            r"|SecTrust\w*|keychain)\b"
        ),
        color_pair_idx=13,
        marker="\u26bf",  # ⚿ (key)
        category="security",
        tooltip="Security/identity: certificate validation, encryption, trust evaluation",
    ),
    # -- State transitions --
    HighlightRule(
        pattern=re.compile(
            r"(?i)\b(?:activ(?:e|at)\w*|inactiv\w*|enabl\w*|disabl\w*"
            r"|start(?:ed|ing)|stop(?:ped|ping)"
            r"|(?:interface|link)\s*(?:up|down))\b"
        ),
        color_pair_idx=14,
        marker="\u25cf",  # ●
        category="state",
        tooltip="State transition: interface/service activation or deactivation",
    ),
    # -- Security monitoring: auto-accept (--security) --
    HighlightRule(
        pattern=re.compile(r"(?i)\b(?:AlwaysAutoAccept|auto.?accept|silent.?accept)\b"),
        color_pair_idx=16,
        marker="\u26a0",  # ⚠
        category="auto-accept",
        tooltip="DANGER: AirDrop auto-accept — files delivered without user prompt",
    ),
    # -- Security monitoring: quarantine bypass --
    HighlightRule(
        pattern=re.compile(
            r"(?i)\b(?:DisableQuarantine|quarantine.?(?:skip|bypass)|MISSING QUARANTINE)\b"
        ),
        color_pair_idx=16,
        marker="\u26a0",  # ⚠
        category="quarantine-skip",
        tooltip="DANGER: Gatekeeper quarantine disabled or missing on received file",
    ),
    # -- Security monitoring: encryption disable --
    HighlightRule(
        pattern=re.compile(
            r"(?i)\b(?:DisableEncryption|DisableContinuityTLS"
            r"|disableFaceTimeKeyExchange|encryption.?(?:off|disable))\b"
        ),
        color_pair_idx=16,
        marker="\u26a0",  # ⚠
        category="encryption-disable",
        tooltip="DANGER: Transport encryption disabled — traffic vulnerable to interception",
    ),
    # -- Security monitoring: debug/test mode --
    HighlightRule(
        pattern=re.compile(
            r"(?i)\b(?:EnableDebugMode|AUTestModePassword"
            r"|allowHTTPSplunkServerForTests|DebugMode|TestMode)\b"
        ),
        color_pair_idx=17,
        marker="\u2691",  # ⚑
        category="debug-mode",
        tooltip="WARNING: Debug/test mode active — security checks may be weakened",
    ),
    # -- Security monitoring: auth bypass / injection --
    HighlightRule(
        pattern=re.compile(
            r"(?i)\b(?:allowUnauthenticated|BypassAuthentication"
            r"|forceUnpromptedRemote|INJECTED|DisableBlastdoor)\b"
        ),
        color_pair_idx=16,
        marker="\u26a0",  # ⚠
        category="auth-bypass",
        tooltip="DANGER: Authentication or authorization bypass detected",
    ),
]


@dataclass
class HighlightSpan:
    """A matched highlight region on a screen row, for tooltip lookup."""

    col_start: int
    col_end: int
    rule: HighlightRule


def compute_highlights(
    text: str, rules: List[HighlightRule]
) -> List[HighlightSpan]:
    """Find all highlight spans in *text*, resolving overlaps (first wins)."""
    raw: List[Tuple[int, int, HighlightRule]] = []
    for rule in rules:
        raw.extend(rule.finditer(text))
    # Sort by start position, then by rule priority (list order)
    raw.sort(key=lambda t: (t[0], rules.index(t[2])))

    spans: List[HighlightSpan] = []
    occupied_until = 0
    for start, end, rule in raw:
        if start < occupied_until:
            continue  # overlap — skip
        spans.append(HighlightSpan(col_start=start, col_end=end, rule=rule))
        occupied_until = end
    return spans


# ---------------------------------------------------------------------------
# Security monitoring: preference watchdog + quarantine + file scanner + net
# ---------------------------------------------------------------------------

_MISSING = object()

DANGEROUS_PREFS: Dict[str, List[str]] = {
    "com.apple.sharing": [
        "AlwaysAutoAccept", "DisableQuarantine", "DisableContinuityTLS",
        "AUTestModePassword", "EnableDebugMode", "DisableEncryption",
        "pretendDeviceWaitingForGuestModeApproval", "pretendNotUnlockedRecently",
    ],
    "com.apple.TelephonyUtilities": [
        "disableFaceTimeKeyExchange", "DisableBlastdoorValidationPrompt",
        "disable-receptionist-disclosure-checks", "allowOutgoingCallsWhenLocked",
    ],
    "com.apple.classroom": [
        "forceUnpromptedRemoteScreenObservation",
        "allowClassroomLockDevice",
        "allowClassroomOpenApp",
        "allowClassroomOpenURL",
    ],
    "com.apple.rapport": ["allowUnauthenticated", "ForceL2CAP"],
    "com.apple.securityuploadd": [
        "allowInsecureSplunkCert", "allowHTTPSplunkServerForTests", "disableUploads",
    ],
    "com.apple.intelligenceflow": [
        "agenticPlannerZincUrl", "disableToolBoxAllowList",
    ],
    "com.apple.gamed": ["BypassAuthentication"],
}

# Classroom keys have per-device suffixes — need prefix matching
_CLASSROOM_PREFIX_KEYS = [
    "forceUnpromptedRemoteScreenObservation",
    "allowClassroomLockDevice",
    "allowClassroomOpenApp",
    "allowClassroomOpenURL",
]


def _make_prefs_checker() -> Callable[[], List[Tuple[Level, str]]]:
    """Factory returning a stateful preference watchdog callable."""
    baseline: Dict[Tuple[str, str], Any] = {}
    first_run = True

    def _read_key(domain: str, key: str) -> Any:
        try:
            res = subprocess.run(
                ["defaults", "read", domain, key],
                capture_output=True, text=True, timeout=2,
            )
            return res.stdout.strip() if res.returncode == 0 else _MISSING
        except Exception:
            return _MISSING

    def _read_classroom_prefixes() -> Dict[Tuple[str, str], str]:
        """Read com.apple.classroom and match prefix keys."""
        found: Dict[Tuple[str, str], str] = {}
        try:
            res = subprocess.run(
                ["defaults", "read", "com.apple.classroom"],
                capture_output=True, text=True, timeout=3,
            )
            if res.returncode != 0:
                return found
            for line in res.stdout.splitlines():
                line = line.strip().strip(";").strip('"')
                for prefix in _CLASSROOM_PREFIX_KEYS:
                    if line.startswith(prefix) and "=" in line:
                        key = line.split("=")[0].strip().strip('"')
                        val = line.split("=", 1)[1].strip().strip(";").strip()
                        found[("com.apple.classroom", key)] = val
        except Exception:
            pass
        return found

    def check() -> List[Tuple[Level, str]]:
        nonlocal baseline, first_run
        results: List[Tuple[Level, str]] = []
        current: Dict[Tuple[str, str], Any] = {}

        for domain, keys in DANGEROUS_PREFS.items():
            if domain == "com.apple.classroom":
                current.update(_read_classroom_prefixes())
            else:
                for key in keys:
                    current[(domain, key)] = _read_key(domain, key)

        if first_run:
            for (domain, key), val in current.items():
                if val is not _MISSING:
                    results.append((
                        Level.WARN,
                        f"[PREFS] EXISTING: {domain} {key} = {val}",
                    ))
            if not results:
                results.append((Level.INFO, "[PREFS] baseline clean — no dangerous keys set"))
            baseline = dict(current)
            first_run = False
        else:
            for dk, val in current.items():
                old = baseline.get(dk, _MISSING)
                if val != old:
                    domain, key = dk
                    if val is not _MISSING and old is _MISSING:
                        results.append((
                            Level.ERROR,
                            f"[PREFS] INJECTED: {domain} {key} = {val}",
                        ))
                    elif val is _MISSING and old is not _MISSING:
                        results.append((
                            Level.WARN,
                            f"[PREFS] REMOVED: {domain} {key} (was {old})",
                        ))
                    else:
                        results.append((
                            Level.ERROR,
                            f"[PREFS] CHANGED: {domain} {key}: {old} -> {val}",
                        ))
            baseline = dict(current)
        return results

    return check


def _make_quarantine_checker(
    watch_dir: Optional[str] = None,
) -> Callable[[], List[Tuple[Level, str]]]:
    """Factory for quarantine xattr verification on new Downloads."""
    watch_dir = watch_dir or os.path.expanduser("~/Downloads")
    seen: set = set()

    def check() -> List[Tuple[Level, str]]:
        results: List[Tuple[Level, str]] = []
        now = time.time()
        try:
            entries = os.listdir(watch_dir)
        except OSError:
            return [(Level.WARN, "[QUAR] cannot read ~/Downloads")]
        for name in entries:
            path = os.path.join(watch_dir, name)
            if path in seen:
                continue
            try:
                st = os.stat(path)
            except OSError:
                continue
            if now - st.st_mtime > 60:
                continue
            seen.add(path)
            res = subprocess.run(
                ["xattr", "-p", "com.apple.quarantine", path],
                capture_output=True, text=True, timeout=2,
            )
            if res.returncode != 0:
                results.append((
                    Level.ERROR,
                    f"[QUAR] MISSING QUARANTINE: {name} — Gatekeeper bypass!",
                ))
            else:
                results.append((
                    Level.INFO, f"[QUAR] OK: {name} has quarantine xattr",
                ))
        return results

    return check


_DANGEROUS_EXTENSIONS = frozenset({
    ".app", ".ipa", ".mobileconfig", ".command", ".pkg",
    ".dmg", ".scpt", ".workflow", ".action",
})


def _make_filetype_scanner(
    watch_dir: Optional[str] = None,
) -> Callable[[], List[Tuple[Level, str]]]:
    """Factory for dangerous file type detection in Downloads."""
    watch_dir = watch_dir or os.path.expanduser("~/Downloads")
    seen: set = set()

    def check() -> List[Tuple[Level, str]]:
        results: List[Tuple[Level, str]] = []
        now = time.time()
        try:
            entries = os.listdir(watch_dir)
        except OSError:
            return []
        for name in entries:
            path = os.path.join(watch_dir, name)
            if path in seen:
                continue
            try:
                st = os.stat(path)
            except OSError:
                continue
            if now - st.st_mtime > 120:
                continue
            seen.add(path)
            _, ext = os.path.splitext(name.lower())
            if ext in _DANGEROUS_EXTENSIONS:
                results.append((
                    Level.ERROR,
                    f"[FILE] DANGEROUS TYPE: {name} ({ext}) in ~/Downloads",
                ))
        return results

    return check


def _make_net_listener_checker() -> Callable[[], List[Tuple[Level, str]]]:
    """Factory for network listener baseline-and-diff monitoring."""
    baseline_ports: set = set()
    first_run = True

    def check() -> List[Tuple[Level, str]]:
        nonlocal baseline_ports, first_run
        results: List[Tuple[Level, str]] = []
        current: set = set()
        try:
            res = subprocess.run(
                ["lsof", "-iTCP", "-sTCP:LISTEN", "-n", "-P"],
                capture_output=True, text=True, timeout=5,
            )
            for line in res.stdout.strip().split("\n")[1:]:
                parts = line.split()
                if len(parts) >= 9:
                    current.add((parts[0], parts[8]))
        except Exception:
            return [(Level.WARN, "[NET] failed to check listeners")]

        if first_run:
            baseline_ports = current
            results.append((Level.INFO, f"[NET] baseline: {len(current)} listeners"))
            first_run = False
        else:
            for proc, addr in current - baseline_ports:
                results.append((Level.WARN, f"[NET] NEW LISTENER: {proc} on {addr}"))
            for proc, addr in baseline_ports - current:
                results.append((Level.INFO, f"[NET] listener closed: {proc} on {addr}"))
            baseline_ports = current
        return results

    return check


# ---------------------------------------------------------------------------
# Monitor engine
# ---------------------------------------------------------------------------

class MonitorEngine:
    """Manages workers, routes LogRecords to channel buffers and file sink."""

    def __init__(
        self,
        enable_tcpdump: bool = False,
        enable_security: bool = False,
        file_sink: Optional[FileSink] = None,
    ) -> None:
        self.enable_tcpdump = enable_tcpdump
        self._enable_security = enable_security
        self._file_sink = file_sink
        self._out_queue: "queue.Queue[LogRecord]" = queue.Queue()
        self._stop_event = threading.Event()
        self._workers: List[threading.Thread] = []
        self._drain_thread: Optional[threading.Thread] = None
        self.running = False

        # Extend channels for security mode
        if self._enable_security:
            for ch in ("security", "callservicesd", "rapportd", "studentd"):
                if ch not in CHANNELS:
                    CHANNELS.append(ch)

        self.buffers: Dict[str, ChannelBuffer] = {
            ch: ChannelBuffer() for ch in CHANNELS
        }

    def _route(self, record: LogRecord) -> None:
        """Send a LogRecord to the correct channel buffer and file sink."""
        if record.channel in self.buffers:
            self.buffers[record.channel].append(record)
        if self._file_sink:
            self._file_sink.write(record)

    def inject(self, level: Level, channel: str, message: str) -> None:
        """Create and route an engine-internal record."""
        self._route(_make_record(level, channel, "engine", message))

    def start(self) -> None:
        """Start all monitoring workers."""
        if self.running:
            return
        self.running = True
        self._stop_event.clear()

        self.inject(Level.INFO, "sharingd", "engine starting")

        specs: List[ProcSpec] = [
            ProcSpec(
                name="sharingd_log",
                argv=[
                    "log", "stream", "--style", "compact",
                    "--predicate", 'process == "sharingd"',
                    "--info",
                ],
                coalesce=True,
            ),
            ProcSpec(
                name="airdrop_log",
                argv=[
                    "log", "stream", "--style", "compact",
                    "--predicate",
                    '(subsystem CONTAINS[c] "AirDrop") OR '
                    '(eventMessage CONTAINS[c] "AirDrop") OR '
                    '(eventMessage CONTAINS[c] "AWDL")',
                    "--info",
                ],
                coalesce=True,
            ),
            ProcSpec(
                name="bonjour_browse",
                argv=["dns-sd", "-B", "_airdrop._tcp"],
            ),
            ProcSpec(
                name="awdl0_counters",
                argv=["netstat", "-I", "awdl0", "1"],
            ),
        ]

        pollers: List[Tuple[str, str, float, List[str], bool]] = [
            ("awdl0_status", "awdl0_if", 2.0, ["ifconfig", "awdl0"], False),
            (
                "sharingd_sockets", "sockets", 3.0,
                [
                    "bash", "-lc",
                    "lsof -n -i | grep -E "
                    "'sharingd|\\*:dpap|_airdrop' || true",
                ],
                False,
            ),
        ]

        if self.enable_tcpdump:
            specs.append(
                ProcSpec(
                    name="tcpdump_awdl0",
                    argv=["tcpdump", "-l", "-n", "-i", "awdl0"],
                    requires_root=True,
                )
            )
        else:
            self.inject(
                Level.INFO, "tcpdump",
                "tcpdump disabled (use --tcpdump and run as root)",
            )

        # Security monitoring workers
        if self._enable_security:
            for proc in ("callservicesd", "rapportd", "studentd"):
                specs.append(ProcSpec(
                    name=f"{proc}_log",
                    argv=[
                        "log", "stream", "--style", "compact",
                        "--predicate", f'process == "{proc}"', "--info",
                    ],
                    coalesce=True,
                ))
            self.inject(Level.INFO, "security", "security monitoring enabled")
        else:
            for ch in ("security", "callservicesd", "rapportd", "studentd"):
                if ch in self.buffers:
                    self.inject(
                        Level.INFO, ch,
                        "disabled (use --security to enable)",
                    )

        self._workers = []

        for spec in specs:
            channel = WORKER_TO_CHANNEL[spec.name]
            w = StreamWorker(
                spec=spec,
                channel=channel,
                out_queue=self._out_queue,
                stop_event=self._stop_event,
            )
            self._workers.append(w)
            w.start()

        for name, channel, secs, argv, needs_root in pollers:
            p = PollWorker(
                name=name,
                channel=channel,
                poll_seconds=secs,
                argv=argv,
                out_queue=self._out_queue,
                stop_event=self._stop_event,
                requires_root=needs_root,
            )
            self._workers.append(p)
            p.start()

        # Security callable poll workers
        if self._enable_security:
            security_polls: List[Tuple[str, float, Callable]] = [
                ("prefs_watchdog", 2.0, _make_prefs_checker()),
                ("quarantine_checker", 3.0, _make_quarantine_checker()),
                ("filetype_scanner", 5.0, _make_filetype_scanner()),
                ("net_listener_checker", 5.0, _make_net_listener_checker()),
            ]
            for name, secs, fn in security_polls:
                channel = WORKER_TO_CHANNEL[name]
                w = CallablePollWorker(
                    name=name, channel=channel, poll_seconds=secs, fn=fn,
                    out_queue=self._out_queue, stop_event=self._stop_event,
                )
                self._workers.append(w)
                w.start()

        self._drain_thread = threading.Thread(
            target=self._drain_loop, daemon=True
        )
        self._drain_thread.start()

    def stop(self) -> None:
        """Signal all workers to stop."""
        if not self.running:
            return
        self._stop_event.set()
        self.running = False

    def shutdown(self) -> None:
        """Stop workers and close file sink."""
        self.stop()
        if self._file_sink:
            self._file_sink.close()
            self._file_sink = None

    def clear_channel(self, channel: str) -> None:
        """Clear a single channel buffer."""
        if channel in self.buffers:
            self.buffers[channel].clear()

    def clear_all(self) -> None:
        """Clear all channel buffers."""
        for buf in self.buffers.values():
            buf.clear()

    def _drain_loop(self) -> None:
        """Background thread: move LogRecords from queue into buffers/sinks."""
        while not self._stop_event.is_set() or not self._out_queue.empty():
            try:
                record = self._out_queue.get(timeout=0.1)
                self._route(record)
            except queue.Empty:
                continue

    def export_logs(self, path: str, fmt: str = "text") -> int:
        """Export all channel buffers to a file in unified format.

        Records are merged across channels and sorted chronologically.

        Args:
            path: Destination file path.
            fmt: 'text' for human-readable, 'jsonl' for machine-parseable.

        Returns:
            Number of records written.
        """
        formatter = (
            LogRecord.format_jsonl if fmt == "jsonl" else LogRecord.format_text
        )

        all_records: List[LogRecord] = []
        for ch in CHANNELS:
            all_records.extend(self.buffers[ch].get_records())
        all_records.sort(key=lambda r: r.timestamp_epoch)

        with open(path, "w", encoding="utf-8") as f:
            if fmt == "text":
                f.write(
                    f"# AirDrop Observatory export — "
                    f"{time.strftime('%Y-%m-%dT%H:%M:%S%z')}\n"
                )
                f.write(f"# Records: {len(all_records)}\n")
                f.write(
                    "# Format: {ISO8601} {LEVEL:5} "
                    "[{CHANNEL:10}] {message}\n"
                )
                f.write("#\n")
            for record in all_records:
                f.write(formatter(record) + "\n")

        return len(all_records)


# ---------------------------------------------------------------------------
# TUI
# ---------------------------------------------------------------------------

class AirDropTUI:
    """Curses-based terminal UI for the AirDrop Observatory."""

    def __init__(
        self,
        stdscr: "curses.window",
        engine: MonitorEngine,
        export_format: str = "text",
    ) -> None:
        self.stdscr = stdscr
        self.engine = engine
        self.export_format = export_format
        self.active_idx: int = 0
        self.scroll_offset: int = 0
        self.auto_scroll: bool = True
        self.filter_text: str = ""
        self.filter_re: Optional[re.Pattern[str]] = None
        self.filter_mode: bool = False
        self.show_help: bool = False

        # Tooltip state
        self._tooltip_text: str = ""
        self._tooltip_cat: str = ""
        self._tooltip_y: int = 0
        self._tooltip_x: int = 0
        # Map screen row → list of (col_start, col_end, HighlightRule)
        self._row_highlights: Dict[int, List[HighlightSpan]] = {}

        curses.start_color()
        curses.use_default_colors()
        # Base UI pairs (1-8)
        curses.init_pair(1, curses.COLOR_CYAN, -1)       # INFO level
        curses.init_pair(2, curses.COLOR_RED, -1)         # ERROR level
        curses.init_pair(3, curses.COLOR_YELLOW, -1)      # WARN level
        curses.init_pair(4, curses.COLOR_BLACK, curses.COLOR_CYAN)
        curses.init_pair(5, curses.COLOR_WHITE, -1)
        curses.init_pair(6, curses.COLOR_GREEN, -1)
        curses.init_pair(7, curses.COLOR_BLACK, curses.COLOR_WHITE)
        curses.init_pair(8, curses.COLOR_BLACK, curses.COLOR_YELLOW)
        # Highlight pairs (10-14) — distinct from base UI
        curses.init_pair(10, curses.COLOR_GREEN, -1)      # discovery
        curses.init_pair(11, curses.COLOR_MAGENTA, -1)    # transfer
        curses.init_pair(12, curses.COLOR_CYAN, -1)       # AWDL/radio
        curses.init_pair(13, curses.COLOR_RED, -1)        # security
        curses.init_pair(14, curses.COLOR_YELLOW, -1)     # state change
        # Security alert pairs (16-17)
        curses.init_pair(16, curses.COLOR_RED, curses.COLOR_YELLOW)     # critical
        curses.init_pair(17, curses.COLOR_BLACK, curses.COLOR_MAGENTA)  # debug/test
        # Tooltip box
        curses.init_pair(15, curses.COLOR_WHITE, curses.COLOR_BLUE)

        curses.curs_set(0)
        self.stdscr.nodelay(True)
        self.stdscr.timeout(100)

        # Enable mouse — motion tracking for hover tooltips
        curses.mousemask(
            curses.ALL_MOUSE_EVENTS | curses.REPORT_MOUSE_POSITION
        )
        # Request terminal motion reporting (xterm-compatible)
        try:
            sys.stdout.write("\033[?1003h")
            sys.stdout.flush()
        except Exception:
            pass

    @property
    def active_channel(self) -> str:
        """Currently selected channel name."""
        return CHANNELS[self.active_idx]

    def run(self) -> None:
        """Main event loop."""
        try:
            while True:
                self._draw()
                key = self.stdscr.getch()
                if key == -1:
                    continue
                if self.show_help:
                    self.show_help = False
                    continue
                if key == curses.KEY_MOUSE:
                    self._handle_mouse()
                    continue
                # Any non-mouse key dismisses tooltip
                self._tooltip_text = ""
                if self.filter_mode:
                    self._handle_filter_key(key)
                    continue
                if self._handle_key(key):
                    break
        finally:
            # Disable terminal mouse motion reporting
            try:
                sys.stdout.write("\033[?1003l")
                sys.stdout.flush()
            except Exception:
                pass

    def _handle_key(self, key: int) -> bool:
        """Handle a keypress. Return True to quit."""
        if key == ord("q") or key == ord("Q"):
            self.engine.shutdown()
            return True
        if key == ord("s"):
            self.engine.start()
        elif key == ord("x"):
            self.engine.stop()
        elif key == ord("c"):
            self.engine.clear_channel(self.active_channel)
            self.scroll_offset = 0
        elif key == ord("C"):
            self.engine.clear_all()
            self.scroll_offset = 0
        elif key == ord("e"):
            self._do_export()
        elif key == ord("/"):
            self.filter_mode = True
            self.filter_text = ""
            curses.curs_set(1)
        elif key == 27:
            self.filter_text = ""
            self.filter_re = None
        elif key == ord("?"):
            self.show_help = True
        elif key == ord("\t") or key == curses.KEY_RIGHT:
            self._switch_tab(1)
        elif key == curses.KEY_BTAB or key == curses.KEY_LEFT:
            self._switch_tab(-1)
        elif key == curses.KEY_UP or key == ord("k"):
            self.auto_scroll = False
            self.scroll_offset = max(0, self.scroll_offset - 1)
        elif key == curses.KEY_DOWN or key == ord("j"):
            self.scroll_offset += 1
        elif key == curses.KEY_PPAGE:
            h = self.stdscr.getmaxyx()[0] - 4
            self.auto_scroll = False
            self.scroll_offset = max(0, self.scroll_offset - h)
        elif key == curses.KEY_NPAGE:
            h = self.stdscr.getmaxyx()[0] - 4
            self.scroll_offset += h
        elif key == ord("G"):
            self.auto_scroll = True
        elif key == ord("g"):
            self.auto_scroll = False
            self.scroll_offset = 0
        return False

    def _handle_filter_key(self, key: int) -> None:
        """Handle keypresses in filter input mode."""
        if key == 27 or key == ord("\n"):
            self.filter_mode = False
            curses.curs_set(0)
            try:
                self.filter_re = (
                    re.compile(self.filter_text, re.IGNORECASE)
                    if self.filter_text
                    else None
                )
            except re.error:
                self.filter_re = None
        elif key in (curses.KEY_BACKSPACE, 127, 8):
            self.filter_text = self.filter_text[:-1]
        elif 32 <= key <= 126:
            self.filter_text += chr(key)

    def _handle_mouse(self) -> None:
        """Process a mouse event — look up tooltip for hovered highlight."""
        try:
            _, mx, my, _, bstate = curses.getmouse()
        except curses.error:
            return

        # Check if mouse is over a highlight span
        spans = self._row_highlights.get(my, [])
        for span in spans:
            if span.col_start <= mx < span.col_end:
                self._tooltip_text = span.rule.tooltip
                self._tooltip_cat = span.rule.category
                self._tooltip_y = my
                self._tooltip_x = mx
                return

        # Not on a highlight — dismiss tooltip
        self._tooltip_text = ""

    def _switch_tab(self, direction: int) -> None:
        """Switch to adjacent channel tab."""
        self.engine.buffers[self.active_channel].mark_viewed()
        self.active_idx = (self.active_idx + direction) % len(CHANNELS)
        self.engine.buffers[self.active_channel].mark_viewed()
        self.scroll_offset = 0
        self.auto_scroll = True

    def _do_export(self) -> None:
        """Export logs to a timestamped file in cwd."""
        ts = time.strftime("%Y%m%d_%H%M%S")
        ext = "jsonl" if self.export_format == "jsonl" else "log"
        path = f"airdrop_export_{ts}.{ext}"
        try:
            count = self.engine.export_logs(path, fmt=self.export_format)
            self.engine.inject(
                Level.INFO, self.active_channel,
                f"exported {count} records ({self.export_format}) "
                f"to {os.path.abspath(path)}",
            )
        except Exception as exc:
            self.engine.inject(
                Level.ERROR, self.active_channel,
                f"export failed: {exc!r}",
            )

    def _get_filtered_records(self) -> List[LogRecord]:
        """Get records for active channel, optionally filtered by regex."""
        records = self.engine.buffers[self.active_channel].get_records()
        if self.filter_re:
            records = [
                r for r in records
                if self.filter_re.search(r.message)
                or self.filter_re.search(r.level.name)
            ]
        return records

    # -- Drawing -----------------------------------------------------------

    def _draw(self) -> None:
        """Render the full TUI frame."""
        self.stdscr.erase()
        max_y, max_x = self.stdscr.getmaxyx()
        if max_y < 6 or max_x < 40:
            self._safe_addstr(0, 0, "Terminal too small", curses.A_BOLD)
            self.stdscr.refresh()
            return

        self.engine.buffers[self.active_channel].mark_viewed()
        self._draw_tabs(0, max_x)
        self._safe_addstr(1, 0, "\u2500" * max_x, curses.A_DIM)
        self._draw_log(2, max_y - 4, max_x)
        self._safe_addstr(max_y - 2, 0, "\u2500" * max_x, curses.A_DIM)
        self._draw_status_bar(max_y - 1, max_x)

        if self.show_help:
            self._draw_help(max_y, max_x)
        elif self._tooltip_text:
            self._draw_tooltip(max_y, max_x)

        self.stdscr.refresh()

    def _draw_tabs(self, y: int, max_x: int) -> None:
        """Draw the channel tab bar."""
        col = 0
        for i, ch in enumerate(CHANNELS):
            buf = self.engine.buffers[ch]
            new = buf.new_count if i != self.active_idx else 0
            label = f" {ch} "
            if new > 0:
                label = f" {ch}({new}) "
            if i == self.active_idx:
                attr = curses.color_pair(4) | curses.A_BOLD
            elif new > 0:
                attr = curses.color_pair(8) | curses.A_BOLD
            else:
                attr = curses.A_DIM
            if col + len(label) < max_x:
                self._safe_addstr(y, col, label, attr)
            col += len(label)

    def _draw_log(self, top: int, height: int, width: int) -> None:
        """Draw the log records with keyword highlighting and gutter markers."""
        self._row_highlights.clear()
        records = self._get_filtered_records()
        total = len(records)

        if self.auto_scroll:
            self.scroll_offset = max(0, total - height)
        max_scroll = max(0, total - height)
        self.scroll_offset = min(self.scroll_offset, max_scroll)

        if total == 0:
            msg = "No data \u2014 press 's' to start monitoring"
            self._safe_addstr(
                top + height // 2,
                max(0, (width - len(msg)) // 2),
                msg, curses.A_DIM,
            )
            return

        # Reserve 2 cols for gutter ("M " where M is a marker character)
        gutter_width = 2
        text_width = width - gutter_width

        start = self.scroll_offset
        end = min(start + height, total)

        for row_idx, rec_idx in enumerate(range(start, end)):
            record = records[rec_idx]
            screen_y = top + row_idx
            base_attr = self._level_attr(record.level)
            display_text = record.format_display()

            # Compute highlights on the raw message (not the timestamp prefix)
            spans = compute_highlights(display_text, HIGHLIGHT_RULES)

            # Gutter marker: use the highest-priority (first) match's marker
            if spans:
                marker = spans[0].rule.marker + " "
                marker_attr = (
                    curses.color_pair(spans[0].rule.color_pair_idx)
                    | curses.A_BOLD
                )
            else:
                marker = "  "
                marker_attr = curses.A_DIM

            self._safe_addstr(screen_y, 0, marker, marker_attr)

            # Render text in segments: base attr for non-highlighted,
            # highlight attr for matched spans
            truncated = display_text[: text_width]
            col = gutter_width

            # Build adjusted spans relative to truncated string
            adjusted_spans: List[HighlightSpan] = []
            for span in spans:
                s = span.col_start
                e = min(span.col_end, len(truncated))
                if s >= len(truncated):
                    break
                adjusted_spans.append(
                    HighlightSpan(
                        col_start=col + s,
                        col_end=col + e,
                        rule=span.rule,
                    )
                )

            # Store for tooltip lookup (screen coordinates)
            if adjusted_spans:
                self._row_highlights[screen_y] = adjusted_spans

            # Draw the line in segments
            pos = 0
            for span in spans:
                s = span.col_start
                e = min(span.col_end, len(truncated))
                if s >= len(truncated):
                    break
                # Text before this span
                if pos < s:
                    self._safe_addstr(
                        screen_y, col + pos,
                        truncated[pos:s], base_attr,
                    )
                # Highlighted span
                hl_attr = (
                    curses.color_pair(span.rule.color_pair_idx)
                    | curses.A_BOLD
                )
                self._safe_addstr(
                    screen_y, col + s,
                    truncated[s:e], hl_attr,
                )
                pos = e

            # Remaining text after last span
            if pos < len(truncated):
                self._safe_addstr(
                    screen_y, col + pos,
                    truncated[pos:], base_attr,
                )

        # Scroll percentage indicator
        if total > height and max_scroll > 0:
            pct = int((self.scroll_offset / max_scroll) * 100)
            indicator = f"{pct}%"
            self._safe_addstr(
                top, max(0, width - len(indicator) - 1),
                indicator, curses.A_DIM,
            )

    def _draw_status_bar(self, y: int, max_x: int) -> None:
        """Draw the bottom status bar."""
        bar = curses.color_pair(7)
        self._safe_addstr(y, 0, " " * max_x, bar)

        if self.engine.running:
            state = " \u25cf MONITORING "
            self._safe_addstr(y, 0, state, curses.color_pair(6) | curses.A_BOLD)
        else:
            state = " \u25cb IDLE "
            self._safe_addstr(y, 0, state, bar | curses.A_DIM)
        col = len(state)

        if self.filter_mode:
            ftxt = f" /{self.filter_text}\u2588"
            self._safe_addstr(y, col, ftxt, bar | curses.A_BOLD)
            col += len(ftxt)
        elif self.filter_text:
            ftxt = f" /{self.filter_text}/"
            self._safe_addstr(y, col, ftxt, bar)
            col += len(ftxt)

        records = self._get_filtered_records()
        right_parts = [f"{len(records)} lines"]
        if not self.auto_scroll:
            right_parts.insert(0, "\u2195 manual")
        if self.engine._file_sink:
            right_parts.append("\u25c9 logging")
        right = "  ".join(right_parts) + " "
        rx = max_x - len(right)
        if rx > col:
            self._safe_addstr(y, rx, right, bar)

        hints = " s:start x:stop TAB:switch /:filter ?:help q:quit "
        hx = col + 2
        if (rx - hx) > len(hints):
            self._safe_addstr(y, hx, hints, bar | curses.A_DIM)

    def _draw_tooltip(self, max_y: int, max_x: int) -> None:
        """Draw a floating tooltip box near the mouse position."""
        if not self._tooltip_text:
            return

        tip_attr = curses.color_pair(15) | curses.A_BOLD
        border_attr = curses.color_pair(15)

        # Build tooltip content lines
        cat_line = f" [{self._tooltip_cat}]"
        # Word-wrap tooltip text to ~50 chars
        wrap_width = min(52, max_x - 6)
        words = self._tooltip_text.split()
        lines: List[str] = []
        current = ""
        for word in words:
            if current and len(current) + 1 + len(word) > wrap_width:
                lines.append(current)
                current = word
            else:
                current = f"{current} {word}" if current else word
        if current:
            lines.append(current)

        box_inner_w = max(len(cat_line), max(len(l) for l in lines)) + 2
        box_w = box_inner_w + 2  # border
        box_h = len(lines) + 3  # top border + cat line + lines + bottom

        # Position: prefer below and right of cursor, clamp to screen
        ty = self._tooltip_y + 1
        tx = self._tooltip_x

        if ty + box_h >= max_y - 1:
            ty = max(0, self._tooltip_y - box_h)
        if tx + box_w >= max_x:
            tx = max(0, max_x - box_w - 1)

        # Draw box
        top_border = "\u250c" + "\u2500" * box_inner_w + "\u2510"
        bot_border = "\u2514" + "\u2500" * box_inner_w + "\u2518"
        self._safe_addstr(ty, tx, top_border, border_attr)
        self._safe_addstr(
            ty + 1, tx,
            "\u2502" + cat_line.ljust(box_inner_w) + "\u2502",
            tip_attr,
        )
        for i, line in enumerate(lines):
            padded = " " + line.ljust(box_inner_w - 1)
            self._safe_addstr(
                ty + 2 + i, tx,
                "\u2502" + padded[:box_inner_w] + "\u2502",
                border_attr,
            )
        self._safe_addstr(ty + 2 + len(lines), tx, bot_border, border_attr)

    def _draw_help(self, max_y: int, max_x: int) -> None:
        """Draw a centered help overlay."""
        help_lines = [
            "\u2554" + "\u2550" * 46 + "\u2557",
            "\u2551      AirDrop Observatory \u2014 Controls       \u2551",
            "\u2560" + "\u2550" * 46 + "\u2563",
            "\u2551  s              Start monitoring             \u2551",
            "\u2551  x              Stop monitoring              \u2551",
            "\u2551  TAB/\u2190/\u2192        Switch channel               \u2551",
            "\u2551  \u2191/\u2193/j/k        Scroll log                   \u2551",
            "\u2551  PgUp/PgDn      Page scroll                  \u2551",
            "\u2551  G              Auto-scroll (bottom)         \u2551",
            "\u2551  g              Jump to top                  \u2551",
            "\u2551  /              Filter (regex on msg+lvl)    \u2551",
            "\u2551  ESC            Clear filter                 \u2551",
            "\u2551  c              Clear channel                \u2551",
            "\u2551  C              Clear all                    \u2551",
            "\u2551  e              Export logs                  \u2551",
            "\u2551  q              Quit                         \u2551",
            "\u2560" + "\u2550" * 46 + "\u2563",
            "\u2551  Gutter markers (leftmost column):           \u2551",
            "\u2551  \u25c6  discovery  (peer/Bonjour/mDNS)         \u2551",
            "\u2551  \u25b6  transfer   (send/receive/accept)       \u2551",
            "\u2551  \u2637  awdl       (radio/channel/p2p)         \u2551",
            "\u2551  \u26bf  security   (cert/TLS/identity)         \u2551",
            "\u2551  \u25cf  state      (activate/enable/up/down)   \u2551",
            "\u2551  \u26a0  alert      (security: inject/bypass)    \u2551",
            "\u2551  \u2691  debug      (debug/test mode active)     \u2551",
            "\u2551                                              \u2551",
            "\u2551  Hover or click a highlighted keyword for    \u2551",
            "\u2551  a tooltip explaining its significance.      \u2551",
            "\u2551                                              \u2551",
            "\u2551        Press any key to close                \u2551",
            "\u255a" + "\u2550" * 46 + "\u255d",
        ]
        box_h = len(help_lines)
        box_w = 48
        sy = max(0, (max_y - box_h) // 2)
        sx = max(0, (max_x - box_w) // 2)
        for i, line in enumerate(help_lines):
            self._safe_addstr(
                sy + i, sx, line,
                curses.color_pair(4) | curses.A_BOLD,
            )

    def _level_attr(self, level: Level) -> int:
        """Return curses attribute for a log level."""
        if level == Level.INFO:
            return curses.color_pair(1)
        if level == Level.ERROR:
            return curses.color_pair(2) | curses.A_BOLD
        if level == Level.WARN:
            return curses.color_pair(3)
        return 0

    def _safe_addstr(
        self, y: int, x: int, text: str, attr: int = 0
    ) -> None:
        """Write text, silently ignoring out-of-bounds."""
        try:
            max_y, max_x = self.stdscr.getmaxyx()
            if y < 0 or y >= max_y or x < 0 or x >= max_x:
                return
            avail = max_x - x
            if avail <= 0:
                return
            self.stdscr.addnstr(y, x, text, avail, attr)
        except curses.error:
            pass


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    """Parse args and launch the TUI."""
    parser = argparse.ArgumentParser(
        description="AirDrop Observatory TUI — passive macOS AirDrop monitor",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Log formats:\n"
            "  text:  {ISO8601} {LEVEL:5} [{CHANNEL:10}] {message}\n"
            "  jsonl: {ts,epoch,level,channel,source,msg} per line\n"
        ),
    )
    parser.add_argument(
        "--tcpdump",
        action="store_true",
        help="Enable tcpdump on awdl0 (requires sudo/root)",
    )
    parser.add_argument(
        "--logfile",
        metavar="PATH",
        default=None,
        help="Write all records to this file in real time (append mode)",
    )
    parser.add_argument(
        "--log-format",
        choices=["text", "jsonl"],
        default="text",
        help="Format for --logfile and 'e' exports (default: text)",
    )
    parser.add_argument(
        "--security",
        action="store_true",
        help=(
            "Enable security monitoring: preference injection watchdog, "
            "quarantine verification, file type scanner, network listener "
            "monitor, and daemon channels (callservicesd, rapportd, studentd)"
        ),
    )
    parser.add_argument(
        "--headless",
        action="store_true",
        help=(
            "Run without TUI — stream records to stdout (and --logfile if set). "
            "Designed for LLM agents, CI pipelines, and background logging. "
            "Stop with Ctrl-C or SIGTERM."
        ),
    )
    parser.add_argument(
        "--duration",
        type=int,
        default=0,
        metavar="SECS",
        help="In headless mode, run for SECS seconds then exit (0 = run forever)",
    )
    args = parser.parse_args()

    file_sink: Optional[FileSink] = None
    if args.logfile:
        file_sink = FileSink(args.logfile, fmt=args.log_format)

    engine = MonitorEngine(
        enable_tcpdump=args.tcpdump,
        enable_security=args.security,
        file_sink=file_sink,
    )

    if args.headless:
        _run_headless(engine, args)
    else:
        def run_tui(stdscr: "curses.window") -> None:
            tui = AirDropTUI(stdscr, engine, export_format=args.log_format)
            try:
                tui.run()
            finally:
                engine.shutdown()

        try:
            curses.wrapper(run_tui)
        except KeyboardInterrupt:
            engine.shutdown()


def _run_headless(engine: MonitorEngine, args: argparse.Namespace) -> None:
    """Run without TUI — stream all records to stdout."""
    fmt = args.log_format
    formatter = LogRecord.format_jsonl if fmt == "jsonl" else LogRecord.format_text
    duration = args.duration

    engine.start()
    start_time = time.time()

    try:
        while True:
            # Drain all channel buffers and print new records
            for ch in CHANNELS:
                buf = engine.buffers.get(ch)
                if not buf:
                    continue
                records = buf.get_records()
                # Only print records we haven't seen yet
                # (use new_count as a proxy — print last N new records)
                new = buf.new_count
                if new > 0:
                    for record in records[-new:]:
                        try:
                            print(formatter(record), flush=True)
                        except BrokenPipeError:
                            engine.shutdown()
                            return
                    buf.mark_viewed()

            if duration > 0 and (time.time() - start_time) >= duration:
                break

            time.sleep(0.25)
    except KeyboardInterrupt:
        pass
    finally:
        engine.shutdown()


if __name__ == "__main__":
    main()
