# NFC Service Rust

Rust NFC service for reading and writing **multiple NDEF records** on MIFARE and NTAG cards, exposed through a WebSocket server.

This README is based on commits in the branch (`main..feat/nfc-ws-v2`).

## Branch Commit History

1. `fca5819` (2026-02-04) - feat: allow reading and writing multiple ndef records through cli
2. `b2ee67a` (2026-02-05) - feat: integrate ws for reading & writing multi-ndef records
3. `45f2fdc` (2026-02-11) - refactor: make both mifare & ntag cards to read/write multiple ndef records
4. `f524705` (2026-02-11) - chore: update makefile

## What This Branch Adds

- Multi-record NDEF encode/decode (`TEXT`, `URL`, `APP`)
- WebSocket flow for:
  - checking reader status
  - writing multiple NDEF records
  - receiving reader/card/data events
- Unified multi-record handling for:
  - MIFARE Classic 1K
  - NTAG (Ultralight/NTAG family path in code)
- Makefile targets for build/lint/format/dev run

## Runtime Architecture

- NFC thread handles PC/SC operations and card events.
- WebSocket server runs on Tokio/Warp at `ws://127.0.0.1:3500`.
- Channel bridge:
  - WS -> NFC commands: `crossbeam_channel`
  - NFC -> WS events: `tokio::broadcast`

## WebSocket API

Connection URL:

```text
ws://127.0.0.1:3500
```

### Incoming Messages (client -> service)

1. Get reader status

```json
{ "type": "GET_READER_STATUS" }
```

2. Write data

`payloads` is a JSON string that deserializes into `Vec<NdefPayload>`.

```json
{
  "type": "WRITE_DATA",
  "payloads": "[{\"data_type\":\"TEXT\",\"content\":\"hello\"},{\"data_type\":\"URL\",\"content\":\"https://example.com\"},{\"data_type\":\"APP\",\"content\":\"com.example.app\"}]"
}
```

### Outgoing Messages (service -> client)

- `READER_STATUS { success: bool }`
- `CARD_STATUS { success: bool, message: string }`
- `DATA_READ_SUCCESS { data: NdefRecordResponse[] }`
- `DATA_READ_ERROR { error: string }`
- `DATA_WRITE_SUCCESS { message: string }`
- `DATA_WRITE_ERROR { error: string }`
- `READER_ERROR { error: string }`

Example read response:

```json
{
  "type": "DATA_READ_SUCCESS",
  "data": [
    { "record_id": 1, "record_type": "T", "payload": "hello" },
    { "record_id": 2, "record_type": "U", "payload": "https://example.com" }
  ]
}
```

## Build and Run

### Prerequisites

- Rust toolchain (edition 2024 project)
- PC/SC service and compatible NFC reader (for example ACR122U class readers)

### Commands

```bash
make build        # release build
make run          # cargo watch -x run
make lint         # cargo clippy
make fmt          # cargo fmt
make clean        # cargo clean
```

Direct run:

```bash
cargo run
```

## Notes

- The default entrypoint starts the WebSocket service.
- CLI helper logic for NFC read/write exists in code (`nfc_service_cli`) for manual flows, but the current `main` runs the WS server path.
