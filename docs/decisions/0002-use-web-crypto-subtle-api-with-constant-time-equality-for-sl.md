# Use Web Crypto subtle API with constant-time equality for Slack v0 verification

Status: accepted (generated, pending human review)

## Context

Slack requests require HMAC-SHA256 verification of the raw basestring. Existing packages often depend on Node.js-specific crypto modules or third-party libraries, limiting portability across edge runtimes (Cloudflare Workers, Deno, modern Node.js) and risking timing side-channels if string comparison is used.

## Decision

Implement verification purely using standard `globalThis.crypto.subtle` (importKey and sign) with a dedicated constant-time equality check over decoded 32-byte arrays, and decouple the HTTP layer from specific web server frameworks.

## Consequences

The library has zero runtime dependencies, runs in all standard JavaScript environments supporting Web Crypto, and protects against timing attacks while keeping the core auditable.
