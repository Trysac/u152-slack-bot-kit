# Architecture

`@trysac/slack-bot-kit` is a zero-dependency, runtime-agnostic library designed for modern JavaScript runtimes with Web Crypto support (Node 20+, Deno, Cloudflare Workers, Bun).

## Component Diagram

```
Incoming Request
       │
       ▼
┌───────────────────────────────┐
│      verifySlackRequest       │
│  - Size check (< 1MB)         │
│  - Header extraction (CI)     │
│  - Drift verification         │
│  - HMAC-SHA256 (Web Crypto)   │
│  - Constant-time comparison   │
└──────────────┬────────────────┘
               │ Validated
               ▼
┌───────────────────────────────┐
│       handleSlackHttp         │
├──────────────┬────────────────┤
│ JSON         │ URL-Encoded    │
│ Verification │ Slash Command  │
│ (Challenge)  │ (Router)       │
└──────────────┴────────────────┘
```

## Security Design

1. **Constant-time comparison**: Hex decodes exactly 32 bytes and compares via bitwise XOR accumulator to guard against timing side-channel attacks.
2. **Capture before parse**: The raw HTTP request string must be verified prior to parsing to avoid encoding ambiguities.
3. **Sanitized telemetry**: The `onEvent` hook strictly prohibits logging secrets, signatures, or raw payloads.
