/**
 * Zero-dependency Slack bot kit for Node.js 20+ and Web Crypto runtimes.
 *
 * Provides v0 request signature verification, slash command parsing, command routing,
 * and HTTP request handling without external runtime dependencies or server frameworks.
 */

/**
 * Valid error codes emitted by {@link SlackError}.
 */
export type SlackErrorCode =
  | "missing_header"
  | "invalid_timestamp"
  | "stale_timestamp"
  | "bad_signature"
  | "body_too_large"
  | "invalid_payload"
  | "invalid_options";

/**
 * Base error class for all Slack operations.
 */
export class SlackError extends Error {
  public readonly code: SlackErrorCode;

  constructor(code: SlackErrorCode, message: string) {
    super(message);
    this.name = "SlackError";
    this.code = code;
    Object.setPrototypeOf(this, new.target.prototype);
  }
}

/**
 * Parameters for verifying a Slack v0 request signature.
 */
export interface VerifySlackRequestInput {
  /** Raw HTTP request body as received before parsing. */
  readonly rawBody: string;
  /** HTTP headers (keys are matched case-insensitively). */
  readonly headers: Record<string, string | undefined>;
  /** Slack app signing secret. */
  readonly signingSecret: string;
  /** Current Unix timestamp in seconds. */
  readonly nowSeconds: number;
  /** Maximum allowed drift between nowSeconds and request timestamp in seconds (default 300). */
  readonly toleranceSeconds?: number;
  /** Maximum raw body size in UTF-8 bytes (default 1_048_576). */
  readonly maxBodyBytes?: number;
}

/**
 * Parsed Slash Command payload with camelCase field names.
 */
export interface SlashCommand {
  readonly command: string;
  readonly text: string;
  readonly userId: string;
  readonly userName: string;
  readonly teamId: string;
  readonly channelId: string;
  readonly responseUrl: string;
  readonly triggerId: string;
}

/**
 * Slack response structure returned to slash command callers.
 */
export interface SlackResponse {
  readonly response_type: "ephemeral" | "in_channel";
  readonly text: string;
}

/**
 * Event payload sent to the onEvent hook in {@link handleSlackHttp}.
 * Strictly sanitised: never contains bodies, secrets, or signature digests.
 */
export interface SlackEvent {
  readonly type: "verified" | "rejected" | "dispatched" | "handler_error";
  readonly code?: string;
  readonly command?: string;
}

/**
 * HTTP request input received by {@link handleSlackHttp}.
 */
export interface SlackHttpRequest {
  readonly rawBody: string;
  readonly headers: Record<string, string | undefined>;
  readonly contentType: string;
}

/**
 * HTTP response output produced by {@link handleSlackHttp}.
 */
export interface SlackHttpResponse {
  readonly status: number;
  readonly headers: Record<string, string>;
  readonly body: string;
}

/**
 * Handler options for {@link handleSlackHttp}.
 */
export interface HandleSlackHttpOptions {
  readonly signingSecret: string;
  readonly router: CommandRouter;
  readonly now: () => number;
  readonly onEvent?: (e: SlackEvent) => void;
}

const DEFAULT_TOLERANCE_SECONDS = 300;
const DEFAULT_MAX_BODY_BYTES = 1_048_576;
const TIMESTAMP_REGEX = /^[0-9]{1,12}$/;
const COMMAND_REGEX = /^\/[a-z0-9_-]{1,32}$/;
const SIGNATURE_PREFIX = "v0=";
const HEX_CHARS = "0123456789abcdef";
const MAX_CHALLENGE_LENGTH = 100;

/**
 * Decodes a 64-character lowercase hex string into 32 bytes.
 * Returns null if the hex string is invalid.
 */
function decodeHex64(hex: string): Uint8Array | null {
  if (hex.length !== 64) {
    return null;
  }
  const out = new Uint8Array(32);
  for (let i = 0; i < 32; i++) {
    const c1 = hex.charCodeAt(i * 2);
    const c2 = hex.charCodeAt(i * 2 + 1);
    const d1 = decodeHexNibble(c1);
    const d2 = decodeHexNibble(c2);
    if (d1 === -1 || d2 === -1) {
      return null;
    }
    out[i] = (d1 << 4) | d2;
  }
  return out;
}

function decodeHexNibble(code: number): number {
  if (code >= 48 && code <= 57) {
    return code - 48;
  }
  if (code >= 97 && code <= 102) {
    return code - 87;
  }
  return -1;
}

/**
 * Constant-time comparison between two 32-byte arrays.
 */
function constantTimeEqual(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== 32 || b.length !== 32) {
    return false;
  }
  let diff = 0;
  for (let i = 0; i < 32; i++) {
    const ai = a[i] ?? 0;
    const bi = b[i] ?? 0;
    diff |= ai ^ bi;
  }
  return diff === 0;
}

/**
 * Converts an ArrayBuffer to a 64-character lowercase hex string.
 */
function toHex(buf: ArrayBuffer): string {
  const bytes = new Uint8Array(buf);
  let res = "";
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i] ?? 0;
    const hi = (b >> 4) & 0x0f;
    const lo = b & 0x0f;
    res += HEX_CHARS.charAt(hi) + HEX_CHARS.charAt(lo);
  }
  return res;
}

/**
 * Finds a header value case-insensitively.
 */
function getHeaderCaseInsensitive(
  headers: Record<string, string | undefined>,
  name: string,
): string | undefined {
  const lower = name.toLowerCase();
  for (const key of Object.keys(headers)) {
    if (key.toLowerCase() === lower) {
      return headers[key];
    }
  }
  return undefined;
}

/**
 * Verifies the Slack request signature according to the Slack v0 specification.
 *
 * Checks are executed in order: options, size, headers, timestamp, signature.
 *
 * @throws {SlackError} On invalid options, size limit exceeded, missing headers, stale timestamp, or bad signature.
 */
export async function verifySlackRequest(input: VerifySlackRequestInput): Promise<void> {
  const { signingSecret, nowSeconds, rawBody, headers } = input;
  const toleranceSeconds = input.toleranceSeconds ?? DEFAULT_TOLERANCE_SECONDS;
  const maxBodyBytes = input.maxBodyBytes ?? DEFAULT_MAX_BODY_BYTES;

  // 1. Validate options
  if (typeof signingSecret !== "string" || signingSecret.length === 0) {
    throw new SlackError("invalid_options", "signingSecret must be a non-empty string");
  }
  if (!Number.isFinite(nowSeconds)) {
    throw new SlackError("invalid_options", "nowSeconds must be a finite number");
  }
  if (!Number.isFinite(toleranceSeconds) || toleranceSeconds <= 0) {
    throw new SlackError("invalid_options", "toleranceSeconds must be a positive number");
  }
  if (!Number.isFinite(maxBodyBytes) || maxBodyBytes < 0) {
    throw new SlackError("invalid_options", "maxBodyBytes must be a non-negative number");
  }
  if (typeof rawBody !== "string") {
    throw new SlackError("invalid_options", "rawBody must be a string");
  }
  if (!headers || typeof headers !== "object") {
    throw new SlackError("invalid_options", "headers must be an object");
  }

  // 2. Validate body size (UTF-8 bytes limit)
  const textEncoder = new TextEncoder();
  const rawBodyBytes = textEncoder.encode(rawBody);
  if (rawBodyBytes.byteLength > maxBodyBytes) {
    throw new SlackError("body_too_large", "rawBody exceeds maxBodyBytes");
  }

  // 3. Validate headers
  const timestampHeader = getHeaderCaseInsensitive(headers, "x-slack-request-timestamp");
  if (typeof timestampHeader !== "string" || timestampHeader.trim() === "") {
    throw new SlackError("missing_header", "Missing x-slack-request-timestamp header");
  }

  const signatureHeader = getHeaderCaseInsensitive(headers, "x-slack-signature");
  if (typeof signatureHeader !== "string" || signatureHeader.trim() === "") {
    throw new SlackError("missing_header", "Missing x-slack-signature header");
  }

  // 4. Validate timestamp
  if (!TIMESTAMP_REGEX.test(timestampHeader)) {
    throw new SlackError("invalid_timestamp", "x-slack-request-timestamp is invalid");
  }
  const timestamp = Number.parseInt(timestampHeader, 10);
  if (Math.abs(nowSeconds - timestamp) > toleranceSeconds) {
    throw new SlackError("stale_timestamp", "x-slack-request-timestamp drift exceeds tolerance");
  }

  // 5. Validate signature
  if (!signatureHeader.startsWith(SIGNATURE_PREFIX)) {
    throw new SlackError("bad_signature", "x-slack-signature does not have v0 prefix");
  }
  const providedHex = signatureHeader.slice(SIGNATURE_PREFIX.length);
  const providedBytes = decodeHex64(providedHex);
  if (providedBytes === null) {
    throw new SlackError("bad_signature", "x-slack-signature is not valid lowercase 64-hex");
  }

  const baseString = `v0:${timestampHeader}:${rawBody}`;
  const baseBytes = textEncoder.encode(baseString);
  const secretBytes = textEncoder.encode(signingSecret);

  const cryptoKey = await globalThis.crypto.subtle.importKey(
    "raw",
    secretBytes,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );

  const computedSignatureBuffer = await globalThis.crypto.subtle.sign("HMAC", cryptoKey, baseBytes);
  const computedHex = toHex(computedSignatureBuffer);
  const computedBytes = decodeHex64(computedHex);

  if (computedBytes === null || !constantTimeEqual(providedBytes, computedBytes)) {
    throw new SlackError("bad_signature", "Computed signature does not match");
  }
}

/**
 * Parses a Slack slash command URL-encoded body into a typed {@link SlashCommand}.
 *
 * @throws {SlackError} With code 'invalid_payload' if any required field is missing.
 */
export function parseSlashCommand(rawBody: string): SlashCommand {
  if (typeof rawBody !== "string" || rawBody.length === 0) {
    throw new SlackError("invalid_payload", "Body is empty or not a string");
  }

  const params = new URLSearchParams(rawBody);
  const command = params.get("command");
  const userId = params.get("user_id");
  const teamId = params.get("team_id");
  const channelId = params.get("channel_id");
  const responseUrl = params.get("response_url");
  const triggerId = params.get("trigger_id");

  if (
    command === null ||
    userId === null ||
    teamId === null ||
    channelId === null ||
    responseUrl === null ||
    triggerId === null
  ) {
    throw new SlackError("invalid_payload", "Missing required slash command parameters");
  }

  const text = params.get("text") ?? "";
  const userName = params.get("user_name") ?? "";

  return {
    command,
    text,
    userId,
    userName,
    teamId,
    channelId,
    responseUrl,
    triggerId,
  };
}

/**
 * Creates an ephemeral response (visible only to the triggering user).
 */
export function ephemeral(text: string): SlackResponse {
  return {
    response_type: "ephemeral",
    text,
  };
}

/**
 * Creates an in-channel response (visible to everyone in the channel).
 */
export function inChannel(text: string): SlackResponse {
  return {
    response_type: "in_channel",
    text,
  };
}

/**
 * CommandRouter manages slash command handlers and dispatches parsed commands.
 */
export class CommandRouter {
  private readonly handlers = new Map<
    string,
    (cmd: SlashCommand) => SlackResponse | Promise<SlackResponse>
  >();

  /**
   * Registers a handler for a slash command.
   * Command names must match /^\/[a-z0-9_-]{1,32}$/.
   *
   * @throws {SlackError} On invalid command name or duplicate registration.
   */
  public on(
    command: string,
    handler: (cmd: SlashCommand) => SlackResponse | Promise<SlackResponse>,
  ): this {
    if (typeof command !== "string" || !COMMAND_REGEX.test(command)) {
      throw new SlackError("invalid_options", `Invalid command name: ${command.slice(0, 50)}`);
    }
    if (typeof handler !== "function") {
      throw new SlackError("invalid_options", "handler must be a function");
    }
    if (this.handlers.has(command)) {
      throw new SlackError("invalid_options", `Handler already registered for command ${command}`);
    }
    this.handlers.set(command, handler);
    return this;
  }

  /**
   * Dispatches a slash command to its registered handler.
   */
  public async dispatch(cmd: SlashCommand): Promise<SlackResponse> {
    const handler = this.handlers.get(cmd.command);
    if (!handler) {
      return ephemeral(`Unknown command: ${cmd.command}`);
    }
    try {
      return await handler(cmd);
    } catch {
      return ephemeral("Something went wrong.");
    }
  }
}

/**
 * Verifies and handles an incoming HTTP request from Slack.
 */
export async function handleSlackHttp(
  req: SlackHttpRequest,
  opts: HandleSlackHttpOptions,
): Promise<SlackHttpResponse> {
  const { signingSecret, router, now, onEvent } = opts;
  const nowSeconds = now();

  // 1. Verify request signature
  try {
    await verifySlackRequest({
      rawBody: req.rawBody,
      headers: req.headers,
      signingSecret,
      nowSeconds,
    });
    onEvent?.({ type: "verified" });
  } catch (err) {
    const code = err instanceof SlackError ? err.code : "bad_signature";
    onEvent?.({ type: "rejected", code });
    return {
      status: 401,
      headers: { "content-type": "text/plain" },
      body: "",
    };
  }

  // Clean content type without parameters
  const normalizedContentType = (req.contentType || "").split(";")[0]?.trim().toLowerCase() ?? "";

  // 2. Handle JSON requests
  if (normalizedContentType === "application/json") {
    let parsedJson: unknown;
    try {
      parsedJson = JSON.parse(req.rawBody);
    } catch {
      return {
        status: 400,
        headers: { "content-type": "text/plain" },
        body: "",
      };
    }

    if (typeof parsedJson === "object" && parsedJson !== null && "type" in parsedJson) {
      const payload = parsedJson as { type?: unknown; challenge?: unknown };
      if (payload.type === "url_verification") {
        if (
          typeof payload.challenge === "string" &&
          payload.challenge.length <= MAX_CHALLENGE_LENGTH
        ) {
          return {
            status: 200,
            headers: { "content-type": "text/plain" },
            body: payload.challenge,
          };
        }
        return {
          status: 400,
          headers: { "content-type": "text/plain" },
          body: "",
        };
      }
    }

    // Other JSON payloads return 200 with empty body
    return {
      status: 200,
      headers: { "content-type": "text/plain" },
      body: "",
    };
  }

  // 3. Handle form-urlencoded (Slash command)
  if (normalizedContentType === "application/x-www-form-urlencoded") {
    let cmd: SlashCommand;
    try {
      cmd = parseSlashCommand(req.rawBody);
    } catch {
      return {
        status: 400,
        headers: { "content-type": "text/plain" },
        body: "",
      };
    }

    let response: SlackResponse;
    try {
      response = await router.dispatch(cmd);
      if (response.text === "Something went wrong.") {
        onEvent?.({ type: "handler_error", command: cmd.command });
      } else {
        onEvent?.({ type: "dispatched", command: cmd.command });
      }
    } catch {
      onEvent?.({ type: "handler_error", command: cmd.command });
      response = ephemeral("Something went wrong.");
    }

    return {
      status: 200,
      headers: { "content-type": "application/json" },
      body: JSON.stringify(response),
    };
  }

  // Unsupported content type
  return {
    status: 400,
    headers: { "content-type": "text/plain" },
    body: "",
  };
}
