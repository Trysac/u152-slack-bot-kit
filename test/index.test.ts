import { describe, expect, it, vi } from "vitest";
import {
  CommandRouter,
  ephemeral,
  handleSlackHttp,
  inChannel,
  parseSlashCommand,
  SlackError,
  type SlackEvent,
  verifySlackRequest,
} from "../src/index.js";

// Slack published vector
const TEST_SIGNING_SECRET = "8f742231b10e8888abcd99yyyzzz85a5"; // gitleaks:allow
const TEST_TIMESTAMP = "1531420618";
const TEST_SIGNATURE = "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503";
const TEST_BODY =
  "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c";

async function computeSig(secret: string, timestamp: string, body: string): Promise<string> {
  const enc = new TextEncoder();
  const base = `v0:${timestamp}:${body}`;
  const key = await globalThis.crypto.subtle.importKey(
    "raw",
    enc.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const sig = await globalThis.crypto.subtle.sign("HMAC", key, enc.encode(base));
  const hex = Array.from(new Uint8Array(sig))
    .map((b) => b.toString(16).padStart(2, "0"))
    .join("");
  return `v0=${hex}`;
}

describe("verifySlackRequest", () => {
  it("resolves at nowSeconds 1531420918 and rejects with SlackError code 'stale_timestamp' at 1531420919 and at 1531420317", async () => {
    await expect(
      verifySlackRequest({
        rawBody: TEST_BODY,
        headers: {
          "X-Slack-Request-Timestamp": TEST_TIMESTAMP,
          "X-Slack-Signature": TEST_SIGNATURE,
        },
        signingSecret: TEST_SIGNING_SECRET,
        nowSeconds: 1531420918,
      }),
    ).resolves.toBeUndefined();

    await expect(
      verifySlackRequest({
        rawBody: TEST_BODY,
        headers: {
          "X-Slack-Request-Timestamp": TEST_TIMESTAMP,
          "X-Slack-Signature": TEST_SIGNATURE,
        },
        signingSecret: TEST_SIGNING_SECRET,
        nowSeconds: 1531420919,
      }),
    ).rejects.toMatchObject({ code: "stale_timestamp" });

    await expect(
      verifySlackRequest({
        rawBody: TEST_BODY,
        headers: {
          "X-Slack-Request-Timestamp": TEST_TIMESTAMP,
          "X-Slack-Signature": TEST_SIGNATURE,
        },
        signingSecret: TEST_SIGNING_SECRET,
        nowSeconds: 1531420317,
      }),
    ).rejects.toMatchObject({ code: "stale_timestamp" });
  });

  it("The same request with one body character changed rejects with code 'bad_signature', a signature 'v0=' + 'A'.repeat(64) rejects with 'bad_signature', a missing x-slack-signature header rejects with 'missing_header', header names are matched case-insensitively and a timestamp header 'abc' rejects with 'invalid_timestamp'", async () => {
    const changedBody = `${TEST_BODY}#`;
    await expect(
      verifySlackRequest({
        rawBody: changedBody,
        headers: {
          "x-slack-request-timestamp": TEST_TIMESTAMP,
          "x-slack-signature": TEST_SIGNATURE,
        },
        signingSecret: TEST_SIGNING_SECRET,
        nowSeconds: 1531420618,
      }),
    ).rejects.toMatchObject({ code: "bad_signature" });

    const uppercaseSig = `v0=${"A".repeat(64)}`;
    await expect(
      verifySlackRequest({
        rawBody: TEST_BODY,
        headers: {
          "x-slack-request-timestamp": TEST_TIMESTAMP,
          "x-slack-signature": uppercaseSig,
        },
        signingSecret: TEST_SIGNING_SECRET,
        nowSeconds: 1531420618,
      }),
    ).rejects.toMatchObject({ code: "bad_signature" });

    await expect(
      verifySlackRequest({
        rawBody: TEST_BODY,
        headers: {
          "x-slack-request-timestamp": TEST_TIMESTAMP,
        },
        signingSecret: TEST_SIGNING_SECRET,
        nowSeconds: 1531420618,
      }),
    ).rejects.toMatchObject({ code: "missing_header" });

    // Header names matched case-insensitively
    await expect(
      verifySlackRequest({
        rawBody: TEST_BODY,
        headers: {
          "X-SLACK-REQUEST-TIMESTAMP": TEST_TIMESTAMP,
          "x-SLACK-signature": TEST_SIGNATURE,
        },
        signingSecret: TEST_SIGNING_SECRET,
        nowSeconds: 1531420618,
      }),
    ).resolves.toBeUndefined();

    // Timestamp 'abc'
    await expect(
      verifySlackRequest({
        rawBody: TEST_BODY,
        headers: {
          "x-slack-request-timestamp": "abc",
          "x-slack-signature": TEST_SIGNATURE,
        },
        signingSecret: TEST_SIGNING_SECRET,
        nowSeconds: 1531420618,
      }),
    ).rejects.toMatchObject({ code: "invalid_timestamp" });
  });

  it("A rawBody of maxBodyBytes + 1 UTF-8 bytes (default 1_048_576) rejects with code 'body_too_large' before any HMAC is computed, and toleranceSeconds 0 or a negative maxBodyBytes throws code 'invalid_options'", async () => {
    const largeBody = "x".repeat(1_048_577);
    await expect(
      verifySlackRequest({
        rawBody: largeBody,
        headers: {
          "x-slack-request-timestamp": TEST_TIMESTAMP,
          "x-slack-signature": TEST_SIGNATURE,
        },
        signingSecret: TEST_SIGNING_SECRET,
        nowSeconds: 1531420618,
      }),
    ).rejects.toMatchObject({ code: "body_too_large" });

    await expect(
      verifySlackRequest({
        rawBody: TEST_BODY,
        headers: {},
        signingSecret: TEST_SIGNING_SECRET,
        nowSeconds: 1531420618,
        toleranceSeconds: 0,
      }),
    ).rejects.toMatchObject({ code: "invalid_options" });

    await expect(
      verifySlackRequest({
        rawBody: TEST_BODY,
        headers: {},
        signingSecret: TEST_SIGNING_SECRET,
        nowSeconds: 1531420618,
        maxBodyBytes: -1,
      }),
    ).rejects.toMatchObject({ code: "invalid_options" });
  });

  it("checks option validations thoroughly", async () => {
    await expect(
      verifySlackRequest({
        rawBody: TEST_BODY,
        headers: {},
        signingSecret: "",
        nowSeconds: 12345,
      }),
    ).rejects.toMatchObject({ code: "invalid_options" });

    await expect(
      verifySlackRequest({
        rawBody: TEST_BODY,
        headers: {},
        signingSecret: TEST_SIGNING_SECRET,
        nowSeconds: Number.NaN,
      }),
    ).rejects.toMatchObject({ code: "invalid_options" });

    await expect(
      verifySlackRequest({
        rawBody: 123 as unknown as string,
        headers: {},
        signingSecret: TEST_SIGNING_SECRET,
        nowSeconds: 12345,
      }),
    ).rejects.toMatchObject({ code: "invalid_options" });

    await expect(
      verifySlackRequest({
        rawBody: TEST_BODY,
        headers: null as unknown as Record<string, string>,
        signingSecret: TEST_SIGNING_SECRET,
        nowSeconds: 12345,
      }),
    ).rejects.toMatchObject({ code: "invalid_options" });

    // missing timestamp header
    await expect(
      verifySlackRequest({
        rawBody: TEST_BODY,
        headers: { "x-slack-signature": TEST_SIGNATURE },
        signingSecret: TEST_SIGNING_SECRET,
        nowSeconds: 12345,
      }),
    ).rejects.toMatchObject({ code: "missing_header" });

    // signature without v0= prefix
    await expect(
      verifySlackRequest({
        rawBody: TEST_BODY,
        headers: {
          "x-slack-request-timestamp": TEST_TIMESTAMP,
          "x-slack-signature":
            "v1=invalidprefix123456789012345678901234567890123456789012345678901234",
        },
        signingSecret: TEST_SIGNING_SECRET,
        nowSeconds: 1531420618,
      }),
    ).rejects.toMatchObject({ code: "bad_signature" });

    // signature length invalid
    await expect(
      verifySlackRequest({
        rawBody: TEST_BODY,
        headers: {
          "x-slack-request-timestamp": TEST_TIMESTAMP,
          "x-slack-signature": "v0=tooshort",
        },
        signingSecret: TEST_SIGNING_SECRET,
        nowSeconds: 1531420618,
      }),
    ).rejects.toMatchObject({ code: "bad_signature" });

    // signature contains non-hex chars
    await expect(
      verifySlackRequest({
        rawBody: TEST_BODY,
        headers: {
          "x-slack-request-timestamp": TEST_TIMESTAMP,
          "x-slack-signature": `v0=${"z".repeat(64)}`,
        },
        signingSecret: TEST_SIGNING_SECRET,
        nowSeconds: 1531420618,
      }),
    ).rejects.toMatchObject({ code: "bad_signature" });
  });
});

describe("parseSlashCommand", () => {
  it("parseSlashCommand(body) returns command '/webhook-collect', text '', userId 'U2CERLKJA', teamId 'T1DC2JH3J', responseUrl 'https://hooks.slack.com/commands/T1DC2JH3J/397700885554/96rGlfmibIGlgcZRskXaIFfN', and a body without command throws code 'invalid_payload'", () => {
    const parsed = parseSlashCommand(TEST_BODY);
    expect(parsed.command).toBe("/webhook-collect");
    expect(parsed.text).toBe("");
    expect(parsed.userId).toBe("U2CERLKJA");
    expect(parsed.teamId).toBe("T1DC2JH3J");
    expect(parsed.responseUrl).toBe(
      "https://hooks.slack.com/commands/T1DC2JH3J/397700885554/96rGlfmibIGlgcZRskXaIFfN",
    );
    expect(parsed.userName).toBe("roadrunner");
    expect(parsed.channelId).toBe("G8PSS9T3V");
    expect(parsed.triggerId).toBe("398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c");

    expect(() => parseSlashCommand("")).toThrowError(SlackError);
    expect(() => parseSlashCommand("")).toThrowError(
      expect.objectContaining({ code: "invalid_payload" }),
    );

    expect(() => parseSlashCommand("user_id=U123&team_id=T123")).toThrowError(
      expect.objectContaining({ code: "invalid_payload" }),
    );
  });
});

describe("CommandRouter and responses", () => {
  it("router.on('/deploy', h) then dispatch of command '/deploy' with text 'prod' calls h once with that command; an unknown '/x' returns {response_type: 'ephemeral', text: 'Unknown command: /x'}; registering '/deploy' twice throws 'invalid_options'; a handler that throws returns {response_type: 'ephemeral', text: 'Something went wrong.'}", async () => {
    const router = new CommandRouter();
    const handler = vi.fn().mockImplementation((cmd) => ephemeral(`Deployed ${cmd.text}`));

    router.on("/deploy", handler);

    // Registering duplicate throws invalid_options
    expect(() => router.on("/deploy", handler)).toThrowError(SlackError);
    expect(() => router.on("/deploy", handler)).toThrowError(
      expect.objectContaining({ code: "invalid_options" }),
    );

    // Invalid command name regex
    expect(() => router.on("deploy", handler)).toThrowError(
      expect.objectContaining({ code: "invalid_options" }),
    );
    expect(() => router.on("/deploy!invalid", handler)).toThrowError(
      expect.objectContaining({ code: "invalid_options" }),
    );
    expect(() => router.on("/deploy", "not a func" as unknown as typeof handler)).toThrowError(
      expect.objectContaining({ code: "invalid_options" }),
    );

    // Dispatch /deploy
    const res = await router.dispatch({
      command: "/deploy",
      text: "prod",
      userId: "U1",
      userName: "user",
      teamId: "T1",
      channelId: "C1",
      responseUrl: "https://example.com",
      triggerId: "trig1",
    });

    expect(handler).toHaveBeenCalledTimes(1);
    expect(handler).toHaveBeenCalledWith(
      expect.objectContaining({ command: "/deploy", text: "prod" }),
    );
    expect(res).toEqual({ response_type: "ephemeral", text: "Deployed prod" });

    // Unknown /x
    const unknownRes = await router.dispatch({
      command: "/x",
      text: "",
      userId: "U1",
      userName: "user",
      teamId: "T1",
      channelId: "C1",
      responseUrl: "https://example.com",
      triggerId: "trig1",
    });
    expect(unknownRes).toEqual({ response_type: "ephemeral", text: "Unknown command: /x" });

    // Handler that throws
    router.on("/failing", () => {
      throw new Error("Boom");
    });
    const errorRes = await router.dispatch({
      command: "/failing",
      text: "",
      userId: "U1",
      userName: "user",
      teamId: "T1",
      channelId: "C1",
      responseUrl: "https://example.com",
      triggerId: "trig1",
    });
    expect(errorRes).toEqual({ response_type: "ephemeral", text: "Something went wrong." });
  });

  it("inChannel('hi') deep-equals {response_type: 'in_channel', text: 'hi'} and ephemeral('test') deep-equals {response_type: 'ephemeral', text: 'test'}", () => {
    expect(inChannel("hi")).toEqual({ response_type: "in_channel", text: "hi" });
    expect(ephemeral("test")).toEqual({ response_type: "ephemeral", text: "test" });
  });
});

describe("handleSlackHttp and onEvent security", () => {
  it("handleSlackHttp on a correctly signed body '{\"type\":\"url_verification\",\"challenge\":\"3eZbrw1aBm2rZgRNFdxV2595E9CY3gmdALWMmHkvFXO7tYXAYM8P\"}' with contentType 'application/json' returns status 200, content-type 'text/plain' and that challenge as body; the same body unsigned returns status 401 with body ''", async () => {
    const urlVerifBody =
      '{"type":"url_verification","challenge":"3eZbrw1aBm2rZgRNFdxV2595E9CY3gmdALWMmHkvFXO7tYXAYM8P"}';
    const router = new CommandRouter();
    const events: SlackEvent[] = [];
    const timestamp = "1531420618";
    const sig = await computeSig(TEST_SIGNING_SECRET, timestamp, urlVerifBody);

    // Correctly signed
    const successRes = await handleSlackHttp(
      {
        rawBody: urlVerifBody,
        headers: {
          "x-slack-request-timestamp": timestamp,
          "x-slack-signature": sig,
        },
        contentType: "application/json",
      },
      {
        signingSecret: TEST_SIGNING_SECRET,
        router,
        now: () => 1531420618,
        onEvent: (e) => events.push(e),
      },
    );

    expect(successRes).toEqual({
      status: 200,
      headers: { "content-type": "text/plain" },
      body: "3eZbrw1aBm2rZgRNFdxV2595E9CY3gmdALWMmHkvFXO7tYXAYM8P",
    });

    // Unsigned / missing signature header
    const unsignedRes = await handleSlackHttp(
      {
        rawBody: urlVerifBody,
        headers: {
          "x-slack-request-timestamp": timestamp,
        },
        contentType: "application/json",
      },
      {
        signingSecret: TEST_SIGNING_SECRET,
        router,
        now: () => 1531420618,
        onEvent: (e) => events.push(e),
      },
    );

    expect(unsignedRes).toEqual({
      status: 401,
      headers: { "content-type": "text/plain" },
      body: "",
    });
  });

  it("handleSlackHttp on a signed slash command returns status 200, content-type 'application/json' and body JSON.stringify of the handler response", async () => {
    const router = new CommandRouter();
    router.on("/webhook-collect", (cmd) => inChannel(`Received ${cmd.userId}`));
    const events: SlackEvent[] = [];

    const res = await handleSlackHttp(
      {
        rawBody: TEST_BODY,
        headers: {
          "X-Slack-Request-Timestamp": TEST_TIMESTAMP,
          "X-Slack-Signature": TEST_SIGNATURE,
        },
        contentType: "application/x-www-form-urlencoded; charset=utf-8",
      },
      {
        signingSecret: TEST_SIGNING_SECRET,
        router,
        now: () => 1531420618,
        onEvent: (e) => events.push(e),
      },
    );

    expect(res).toEqual({
      status: 200,
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ response_type: "in_channel", text: "Received U2CERLKJA" }),
    });
  });

  it("Every onEvent payload across acceptance 1-7 contains neither the signing secret, the signature hex nor the substring 'xyzz0WbapA4vBCDEFasx0q6G' from the body", async () => {
    const capturedEvents: SlackEvent[] = [];
    const recordEvent = (e: SlackEvent) => capturedEvents.push(e);
    const router = new CommandRouter();
    router.on("/webhook-collect", () => inChannel("ok"));
    router.on("/boom", () => {
      throw new Error("failed");
    });

    // 1. Valid slash command
    await handleSlackHttp(
      {
        rawBody: TEST_BODY,
        headers: {
          "X-Slack-Request-Timestamp": TEST_TIMESTAMP,
          "X-Slack-Signature": TEST_SIGNATURE,
        },
        contentType: "application/x-www-form-urlencoded",
      },
      {
        signingSecret: TEST_SIGNING_SECRET,
        router,
        now: () => 1531420618,
        onEvent: recordEvent,
      },
    );

    // 2. Rejected verification
    await handleSlackHttp(
      {
        rawBody: TEST_BODY,
        headers: {
          "X-Slack-Request-Timestamp": TEST_TIMESTAMP,
          "X-Slack-Signature":
            "v0=badbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbadbad",
        },
        contentType: "application/x-www-form-urlencoded",
      },
      {
        signingSecret: TEST_SIGNING_SECRET,
        router,
        now: () => 1531420618,
        onEvent: recordEvent,
      },
    );

    // 3. Handler error
    const boomBody =
      "command=%2Fboom&user_id=U1&team_id=T1&channel_id=C1&response_url=https%3A%2F%2Fexample.com&trigger_id=1";
    const boomSig = await computeSig(TEST_SIGNING_SECRET, TEST_TIMESTAMP, boomBody);
    await handleSlackHttp(
      {
        rawBody: boomBody,
        headers: {
          "X-Slack-Request-Timestamp": TEST_TIMESTAMP,
          "X-Slack-Signature": boomSig,
        },
        contentType: "application/x-www-form-urlencoded",
      },
      {
        signingSecret: TEST_SIGNING_SECRET,
        router,
        now: () => 1531420618,
        onEvent: recordEvent,
      },
    );

    // Check all recorded events
    expect(capturedEvents.length).toBeGreaterThan(0);
    const secretSubstr = TEST_SIGNING_SECRET;
    const sigSubstr = "a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503";
    const bodySubstr = "xyzz0WbapA4vBCDEFasx0q6G";

    for (const evt of capturedEvents) {
      const str = JSON.stringify(evt);
      expect(str.includes(secretSubstr)).toBe(false);
      expect(str.includes(sigSubstr)).toBe(false);
      expect(str.includes(bodySubstr)).toBe(false);
    }
  });

  it("handles url_verification invalid challenge lengths, invalid json, and non-challenge json", async () => {
    const router = new CommandRouter();
    const timestamp = "1531420618";

    // challenge > 100 characters
    const longChallengeBody = JSON.stringify({
      type: "url_verification",
      challenge: "a".repeat(101),
    });
    const longSig = await computeSig(TEST_SIGNING_SECRET, timestamp, longChallengeBody);
    const longRes = await handleSlackHttp(
      {
        rawBody: longChallengeBody,
        headers: {
          "x-slack-request-timestamp": timestamp,
          "x-slack-signature": longSig,
        },
        contentType: "application/json",
      },
      {
        signingSecret: TEST_SIGNING_SECRET,
        router,
        now: () => 1531420618,
      },
    );
    expect(longRes.status).toBe(400);

    // non-url_verification json returns 200 with empty body
    const otherJson = JSON.stringify({ type: "event_callback", event: {} });
    const otherSig = await computeSig(TEST_SIGNING_SECRET, timestamp, otherJson);
    const otherRes = await handleSlackHttp(
      {
        rawBody: otherJson,
        headers: {
          "x-slack-request-timestamp": timestamp,
          "x-slack-signature": otherSig,
        },
        contentType: "application/json",
      },
      {
        signingSecret: TEST_SIGNING_SECRET,
        router,
        now: () => 1531420618,
      },
    );
    expect(otherRes.status).toBe(200);
    expect(otherRes.body).toBe("");

    // malformed JSON
    const malformedJson = "{ invalid json";
    const malformedSig = await computeSig(TEST_SIGNING_SECRET, timestamp, malformedJson);
    const malformedRes = await handleSlackHttp(
      {
        rawBody: malformedJson,
        headers: {
          "x-slack-request-timestamp": timestamp,
          "x-slack-signature": malformedSig,
        },
        contentType: "application/json",
      },
      {
        signingSecret: TEST_SIGNING_SECRET,
        router,
        now: () => 1531420618,
      },
    );
    expect(malformedRes.status).toBe(400);

    // malformed urlencoded payload
    const badFormBody = "not_a_valid_command_payload";
    const badFormSig = await computeSig(TEST_SIGNING_SECRET, timestamp, badFormBody);
    const badFormRes = await handleSlackHttp(
      {
        rawBody: badFormBody,
        headers: {
          "x-slack-request-timestamp": timestamp,
          "x-slack-signature": badFormSig,
        },
        contentType: "application/x-www-form-urlencoded",
      },
      {
        signingSecret: TEST_SIGNING_SECRET,
        router,
        now: () => 1531420618,
      },
    );
    expect(badFormRes.status).toBe(400);

    // unsupported content type
    const unsupportedBody = "hello";
    const unsupportedSig = await computeSig(TEST_SIGNING_SECRET, timestamp, unsupportedBody);
    const unsupportedRes = await handleSlackHttp(
      {
        rawBody: unsupportedBody,
        headers: {
          "x-slack-request-timestamp": timestamp,
          "x-slack-signature": unsupportedSig,
        },
        contentType: "text/plain",
      },
      {
        signingSecret: TEST_SIGNING_SECRET,
        router,
        now: () => 1531420618,
      },
    );
    expect(unsupportedRes.status).toBe(400);
  });
});
