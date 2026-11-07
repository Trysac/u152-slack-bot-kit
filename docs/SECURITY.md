# Security Model

## Threat Model
### Defended
- **Request Forgery/Tampering**: Every request is verified using the Slack v0 HMAC-SHA256 signature scheme keyed with the application's signing secret. Verification is performed using a constant-time comparison to prevent timing side-channel attacks.
- **Replay Attacks**: Every request is checked against a timestamp drift tolerance (default 300 seconds) to ensure requests are current.
- **Denial of Service**: The `verifySlackRequest` and `handleSlackHttp` functions enforce a strict body size limit (default 1,048,576 bytes) to prevent memory exhaustion from large payloads.

### Not Defended
- **Application-Level Security**: This kit does not sanitize the logic inside your custom command handlers; insecure logic in a handler is the responsibility of the implementer.
- **Log Injection/Telemetry**: While this kit provides an `onEvent` callback that excludes secrets and raw bodies, it does not control how the consuming application logs data passed to it.
- **Upstream Slack Compromise**: This library assumes the signing secret remains confidential.

## Limits
- Default body size limit: 1,048,576 bytes (configurable).
- Default timestamp tolerance: 300 seconds (configurable).
- Timestamp validation: Must be 1 to 12 digits.
