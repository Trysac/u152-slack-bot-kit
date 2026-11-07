# Testing Strategy

## Test Files
- `test/all.test.ts`: Core acceptance suite verifying signature vectors, timestamp boundaries, and error codes.
- `test/extended.test.ts`: Verifies CommandRouter dispatching logic and `handleSlackHttp` lifecycle events.
- `test/index.test.ts`: Extensive unit testing of `verifySlackRequest` edge cases (invalid options, header variations, signature malformations).
- `test/slack-bot-kit.test.ts`: Validation of the full acceptance test suite using Slack's published example vectors.

## Coverage Areas
- **Signature Verification**: Validates success/failure for valid, modified, andmalformed signatures.
- **Boundary Conditions**: Timestamp drift (stale/valid), max body size exceeded, missing headers, case-insensitive headers, invalid options (negative max bytes, zero tolerance).
- **Slash Command Parsing**: Validates required field presence and parsing of valid URL-encoded bodies.
- **Router Logic**: Dispatching correctly, handling unknown commands, error recovery in handlers, and duplicate registration protection.
- **Security Telemetry**: Explicit checks ensure the `onEvent` hook never captures the signing secret, the signature hex, or the raw body.
