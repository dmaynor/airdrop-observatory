# AirDrop Observatory

A terminal UI (TUI) for passively observing AirDrop behavior on macOS. It collects live telemetry from multiple macOS subsystems during AirDrop discovery and file transfers, displaying structured logs across categorized channels in a curses-based interface.

**Security model:** Passive observation only — no payloads are decrypted.

## Data Sources

- **Unified logs** — `sharingd`, AirDrop, and AWDL-related log streams
- **awdl0 interface** — interface status and live packet counters
- **Bonjour** — browses for `_airdrop._tcp` service advertisements via `dns-sd`
- **sharingd sockets** — socket visibility via `lsof`
- **Packet capture** — optional `tcpdump` on `awdl0` (requires sudo/root)

## Requirements

- macOS (uses macOS-specific tools: `log`, `dns-sd`, `ifconfig`, `lsof`)
- Python 3.6+ (stdlib only — no external dependencies)

## Installation on macOS

No installation needed. Clone the repo and run directly:

```bash
git clone <repo-url> && cd airdrop_observatory
chmod +x airdrop_observatory.py
```

## Usage

```bash
python3 airdrop_observatory.py [options]
```

Or run directly (the script has a shebang):

```bash
./airdrop_observatory.py [options]
```

### CLI Options

| Flag | Description |
|------|-------------|
| `--tcpdump` | Enable packet capture on `awdl0` (requires sudo/root) |
| `--logfile PATH` | Write all records to PATH in real time (append mode) |
| `--log-format {text,jsonl}` | Format for `--logfile` and exports (default: `text`) |

### Examples

Basic monitoring:

```bash
python3 airdrop_observatory.py
```

With packet capture (requires root):

```bash
sudo python3 airdrop_observatory.py --tcpdump
```

Log to a file in JSONL format:

```bash
python3 airdrop_observatory.py --logfile capture.jsonl --log-format jsonl
```

## TUI Controls

| Key | Action |
|-----|--------|
| `s` | Start monitoring |
| `x` | Stop monitoring |
| `TAB` / `←` `→` | Switch channel tabs |
| `c` | Clear current channel |
| `C` | Clear all channels |
| `e` | Export all logs to file |
| `/` | Enter filter mode (regex) |
| `ESC` | Clear filter / exit filter mode |
| `G` | Resume auto-scroll (jump to bottom) |
| `g` | Jump to top |
| `q` | Quit |

## Log Formats

**Text:**
```
{ISO8601} {LEVEL:5} [{CHANNEL:10}] {message}
```

**JSONL:**
```json
{"ts":"...","epoch":...,"level":"...","channel":"...","source":"...","msg":"..."}
```

## License

See repository for license details.
