# @trysac/slack-bot-kit

Framework-free Slack bot kit: v0 request signature verification, slash command parsing and routing, url_verification handling, and typed responses for Node.js 20+ and Web Crypto runtimes.

## The Problem
Slack apps must verify every request with the v0 HMAC signature and a timestamp window to ensure security, yet small bots often skip it, compare signatures with insecure operators, or parse the body after a framework has already re-encoded it. This kit provides the auditable, secure core required for Slack integrations without the overhead of heavy frameworks.

## Installation
```bash
npm install @trysac/slack-bot-kit
```

## Usage
```ts
import { CommandRouter, handleSlackHttp, inChannel } from "@trysac/slack-bot-kit";
const router = new CommandRouter().on("/deploy", (cmd) => inChannel(`Deployed ${cmd.text}`));
const res = await handleSlackHttp(
  { rawBody, headers, contentType: "application/x-www-form-urlencoded" },
  { signingSecret: process.env.SLACK_SIGNING_SECRET!, router, now: () => Math.floor(Date.now() / 1000) }
);
```

## API Reference

### Core Functions
- `verifySlackRequest(input)`: Validates Slack v0 signatures using HMAC-SHA256. Throws `SlackError` on failure.
- `parseSlashCommand(rawBody)`: Parses `application/x-www-form-urlencoded` bodies into a typed `SlashCommand` object.
- `handleSlackHttp(req, opts)`: Dispatches verified HTTP requests to command routers or JSON handlers.
- `ephemeral(text)` / `inChannel(text)`: Creates typed `SlackResponse` objects.

### Classes
- `CommandRouter`: Manages slash command handlers. Registers commands via `.on(command, handler)` and dispatches via `.dispatch(cmd)`.
- `SlackError`: Base error class with code: `missing_header`, `invalid_timestamp`, `stale_timestamp`, `bad_signature`, `body_too_large`, `invalid_payload`, `invalid_options`.

## Why not @slack/bolt?
@slack/bolt is a feature-rich framework including integrated server infrastructure, OAuth support, and a dependency tree that can increase cold start times in serverless environments. This library is a lightweight, framework-agnostic alternative consisting only of verification, routing, and dispatch logic.

## Security
See [docs/SECURITY.md](docs/SECURITY.md) for the threat model and limits.
