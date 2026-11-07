import { describe, expect, it } from "vitest";
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

// Slack documentation published secret & vector:
const TEST_SIGNING_SECRET = "8f742231b10e8888abcd99yyyzzz85a5"; // gitleaks:allow
const TEST_TIMESTAMP = "1531420618";
const TEST_SIGNATURE = "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503";
const TEST_BODY =
  "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c";

describe("Slack Bot Kit specification tests", () => {
  it("Acceptance 1: verifySlackRequest resolves at 1531420918 and rejects with stale_timestamp at 1531420919 and 1531420317", async () => {
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

  it("Acceptance 2: modified body, A*64 sig, missing header, case insensitivity, invalid timestamp", async () => {
    // Changed body character
    await expect(
      verifySlackRequest({
        rawBody: `${TEST_BODY}!test`,
        headers: {
          "X-Slack-Request-Timestamp": TEST_TIMESTAMP,
          "X-Slack-Signature": TEST_SIGNATURE,
        },
        signingSecret: TEST_SIGNING_SECRET,
        nowSeconds: 1531420618,
      }),
    ).rejects.toMatchObject({ code: "bad_signature" });

    // 'v0=' + 'A'.repeat(64)
    await expect(
      verifySlackRequest({
        rawBody: TEST_BODY,
        headers: {
          "x-slack-request-timestamp": TEST_TIMESTAMP,
          "x-slack-signature": `v0=${"A".repeat(64)}`,
        },
        signingSecret: TEST_SIGNING_SECRET,
        nowSeconds: 1531420618,
      }),
    ).rejects.toMatchObject({ code: "bad_signature" });

    // Missing header
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

    // Case-insensitivity
    await expect(
      verifySlackRequest({
        rawBody: TEST_BODY,
        headers: {
          "X-SLACK-REQUEST-TIMESTAMP": TEST_TIMESTAMP,
          "X-SLACK-SIGNATURE": TEST_SIGNATURE,
        },
        signingSecret: TEST_SIGNING_SECRET,
        nowSeconds: 1531420618,
      }),
    ).resolves.toBeUndefined();

    // Invalid timestamp
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

  it("Acceptance 3: body_too_large and invalid_options", async () => {
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

  it("Acceptance 4: parseSlashCommand", () => {
    const cmd = parseSlashCommand(TEST_BODY);
    expect(cmd.command).toBe("/webhook-collect");
    expect(cmd.text).toBe("");
    expect(cmd.userId).toBe("U2CERLKJA");
    expect(cmd.teamId).toBe("T1DC2JH3J");
    expect(cmd.responseUrl).toBe(
      "https://hooks.slack.com/commands/T1DC2JH3J/397700885554/96rGlfmibIGlgcZRskXaIFfN",
    );

    expect(() => parseSlashCommand("")).toThrowError(SlackError);
    expect(() => parseSlashCommand("text=hello")).toThrowError(
      expect.objectContaining({ code: "invalid_payload" }),
    );
  });

  it("Acceptance 5-7: CommandRouter and handleSlackHttp", async () => {
    const router = new CommandRouter();
    router.on("/deploy", (cmd) => ephemeral(`ok ${cmd.text}`));
    const parsed = parseSlashCommand(
      "command=%2Fdeploy&text=prod&user_id=U1&team_id=T1&channel_id=C1&response_url=https%3A%2F%2Fexample.com&trigger_id=1",
    );
    const res = await router.dispatch(parsed);
    expect(res).toEqual({ response_type: "ephemeral", text: "ok prod" });
    expect(inChannel("hi")).toEqual({ response_type: "in_channel", text: "hi" });

    const events: SlackEvent[] = [];
    const httpRes = await handleSlackHttp(
      {
        rawBody: TEST_BODY,
        headers: {
          "x-slack-request-timestamp": TEST_TIMESTAMP,
          "x-slack-signature": TEST_SIGNATURE,
        },
        contentType: "application/x-www-form-urlencoded",
      },
      {
        signingSecret: TEST_SIGNING_SECRET,
        router,
        now: () => 1531420618,
        onEvent: (e) => events.push(e),
      },
    );
    expect(httpRes.status).toBe(200);
  });
});
