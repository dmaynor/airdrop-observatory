# Security Audit Context: AirDrop Observatory

**Date:** 2026-03-29 | **Version:** 1785 lines | **Language:** Python 3.6+ (stdlib only)

---

## Architecture Overview

Single-file curses TUI that passively monitors macOS AirDrop/Continuity subsystems via subprocess log streams. Optional `--security` mode adds preference injection detection, quarantine verification, and multi-daemon monitoring.

```
[Subprocess Workers] → [Queue] → [Drain Loop] → [Channel Buffers] → [TUI / Headless stdout]
     (7-13 threads)     (1 queue)   (1 thread)     (7-11 ring bufs)     (main thread)
                                        ↓
                                  [FileSink (optional)]
```

**Trust boundaries:** Subprocess stdout (untrusted system command output), user CLI input (regex filter, file paths), file system (~/Downloads scanning).

---

## Critical Findings

### 1. ReDoS via User-Supplied Filter Regex (CRITICAL)

**Location:** Line 1329
```python
self.filter_re = re.compile(self.filter_text, re.IGNORECASE)
```

User input compiled to regex without validation. Applied on every visible record per render cycle (line 1392-1393, 100ms refresh). Catastrophic backtracking patterns like `(a+)+x` freeze the TUI.

**Fix:** Wrap in try/except, add complexity guard or timeout.

### 2. Symlink Following in Quarantine Checker (CRITICAL)

**Location:** Lines 812-824

`os.stat()` follows symlinks. Attacker creates `~/Downloads/file -> /target`, observatory runs `xattr -p com.apple.quarantine` on the target. Information disclosure of quarantine status for arbitrary files.

**Fix:** Add `os.path.islink(path)` check before stat/xattr.

### 3. Logfile Path Not Validated (HIGH)

**Location:** Line 1779

`--logfile` accepts any path. No traversal check, no permission restriction. Export creates files with default umask (potentially world-readable).

**Fix:** Validate path, use `os.open()` with 0o600 permissions.

### 4. Information Disclosure in Exports (HIGH)

Preference values, network listener addresses, and file names are logged and exported. Exports to shared directories or CI logs could leak security posture.

---

## Moderate Findings

### 5. Shell Anti-Pattern in lsof Poller (MEDIUM)

**Location:** Lines 1007-1009

```python
["bash", "-lc", "lsof -n -i | grep -E 'sharingd|\\*:dpap|_airdrop' || true"]
```

Hardcoded command — not exploitable from user input, but uses `bash -lc` unnecessarily.

### 6. Fragile lsof Output Parsing (MEDIUM)

**Location:** Lines 896-899

Assumes column 0 = process name, column 8 = address. Process names with spaces break parsing. IndexError not caught.

### 7. Headless Mode Race Condition (MEDIUM)

**Location:** Lines 1819-1830

`buf.get_records()` and `buf.new_count` read without atomic snapshot. Could print duplicates or skip records under heavy load.

### 8. Export Memory Spike (MEDIUM)

**Location:** Line 1146

All records (up to 70K across 7 channels) loaded into memory list before sorting and writing. Could spike to ~14MB temporarily.

---

## Low Findings

### 9. No Highlight Caching (LOW)

12 regex patterns computed per visible line per 100ms render cycle. Heavy tcpdump output with long lines could slow TUI.

### 10. Preference Parsing Fragility (LOW)

`defaults read` output parsed with string splits (lines 738-742). Malformed plist output could cause exceptions (caught by outer handler).

### 11. Export File Permissions (LOW)

Log files created with default umask. Should use 0o600 for files containing preference values and network data.

---

## Subprocess Inventory

| Command | Worker Type | Hardcoded | Shell | Root Required | Timeout |
|---------|------------|-----------|-------|---------------|---------|
| `log stream --predicate ...` | StreamWorker | Yes | No | No | None |
| `dns-sd -B _airdrop._tcp` | StreamWorker | Yes | No | No | None |
| `netstat -I awdl0 1` | StreamWorker | Yes | No | No | None |
| `tcpdump -l -n -i awdl0` | StreamWorker | Yes | No | Yes | None |
| `ifconfig awdl0` | PollWorker | Yes | No | No | 4s |
| `bash -lc "lsof ... \| grep ..."` | PollWorker | Yes | Yes* | No | 6s |
| `defaults read {domain} {key}` | CallablePollWorker | Yes | No | No | 2s |
| `defaults read com.apple.classroom` | CallablePollWorker | Yes | No | No | 3s |
| `xattr -p com.apple.quarantine {path}` | CallablePollWorker | Yes | No | No | 2s |
| `lsof -iTCP -sTCP:LISTEN -n -P` | CallablePollWorker | Yes | No | No | 5s |

*bash used for pipe, not for user input expansion

---

## Thread Safety Summary

| Component | Thread-Safe | Notes |
|-----------|:-----------:|-------|
| ChannelBuffer | Yes | Lock on all operations |
| Queue (drain loop) | Yes | stdlib queue.Queue |
| FileSink | Yes | Lock on write |
| LogRecord | Yes | Frozen dataclass (immutable) |
| Stop event | Yes | stdlib Event |
| Headless stdout print | **No** | Race between get_records and mark_viewed |
| Preference baseline | Yes | Single-thread closure |

---

## Data Sensitivity in Exports

| Data Type | Sensitivity | Present In |
|-----------|------------|-----------|
| Preference keys + values | HIGH | security channel, exports |
| Network listeners (proc:port) | MEDIUM | security channel, exports |
| File names from ~/Downloads | MEDIUM | security channel, exports |
| AirDrop peer hashes | LOW | sharingd/bonjour channels |
| AWDL interface addresses | LOW | awdl channels |
| Subprocess command lines | LOW | all channels (startup messages) |

---

## Attack Surface by Feature

### Default Mode (7 channels)
- **Input:** Hardcoded subprocess commands only
- **Risk:** Minimal — passive observation, no user-controlled data paths

### Security Mode (+4 channels, --security)
- **Input:** File system (~/Downloads), system preferences (defaults), network state (lsof)
- **Risk:** Symlink following in quarantine checker, preference value disclosure

### Headless Mode (--headless)
- **Input:** Same as above, output to stdout
- **Risk:** Race condition in output, sensitive data in stdout stream

### Filter Mode (/ key in TUI)
- **Input:** User-typed regex
- **Risk:** ReDoS — highest severity user-input vulnerability

---

## Recommendations Priority

| Priority | Fix | Effort |
|----------|-----|--------|
| P0 | ReDoS guard on filter regex | 5 lines |
| P0 | Symlink check in quarantine scanner | 2 lines |
| P1 | Logfile path validation + 0o600 perms | 10 lines |
| P1 | Document sensitive data in exports | README update |
| P2 | Replace bash pipe with Python lsof parsing | 15 lines |
| P2 | Atomic snapshot in headless drain | 10 lines |
| P3 | Highlight computation caching | 20 lines |
