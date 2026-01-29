# fast

A CLI speedtest tool using Netflix's fast.com infrastructure.

## Install

```bash
make install
```

Or with a custom prefix:

```bash
make install PREFIX=~/.local
```

## Usage

```bash
fast          # Run speedtest with live progress
fast --json   # Output JSON for scripting
```

## Output

```
Download
  440 Mbps

Upload
  59.1 Mbps

   Download    440 Mbps
   Upload     59.1 Mbps

   Latency
   Unloaded      124 ms
   Loaded        183 ms

   Client     Des Moines, US
              50.83.186.28  Mediacom
   Server(s)  Minneapolis, US | Chicago, US

   Data       549.6 MB ↓  70.9 MB ↑
```

## JSON Output

```bash
fast --json | jq
```

```json
{
  "download": { "bps": 397520880.41, "bytes": 520372224 },
  "upload": { "bps": 20890848.82, "bytes": 26607616 },
  "latency": { "unloaded_ms": 121.07, "loaded_ms": 348.73 },
  "client": { "ip": "50.83.186.28", "isp": "Mediacom", "city": "Des Moines", "country": "US" },
  "servers": ["Minneapolis, US", "Chicago, US"]
}
```

## Build

Requires Rust.

```bash
make          # Build release
make clean    # Clean build artifacts
```
