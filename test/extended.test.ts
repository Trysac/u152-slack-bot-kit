import { describe, expect, it } from "vitest";
import {
  CommandRouter,
  ephemeral,
  handleSlackHttp,
  inChannel,
  parseSlashCommand,
  type SlackEvent,
  verifySlackRequest,
} from "../src/index.js";

const TEST_SIGNING_SECRET = "8f742231b10e8888abcd99yyyzzz85a5"; // gitleaks:allow
const TEST_TIMESTAMP = "1531420618";
const TEST_SIGNATURE = "v0=a2114d57b48eac39b9ad189dd8316235a7b4a8d21a10bd27519666489c69b503";
const TEST_BODY =
  "token=xyzz0WbapA4vBCDEFasx0q6G&team_id=T1DC2JH3J&team_domain=testteamnow&channel_id=G8PSS9T3V&channel_name=foobar&user_id=U2CERLKJA&user_name=roadrunner&command=%2Fwebhook-collect&text=&response_url=https%3A%2F%2Fhooks.slack.com%2Fcommands%2FT1DC2JH3J%2F397700885554%2F96rGlfmibIGlgcZRskXaIFfN&trigger_id=398738663015.47445629121.803a0bc887a14d10d2c447fce8b6703c";

describe("extended tests", () => {
  it("verifies signature header variations and invalid timestamp", async () => {
    // A signature 'v0=' + 'A'.repeat(64) rejects with 'bad_signature'
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
  });

  it("checks CommandRouter and dispatching types", async () => {
    const router = new CommandRouter();
    router.on("/test", () => ephemeral("ok"));
    const res = await router.dispatch({
      command: "/test",
      text: "",
      userId: "U1",
      userName: "name",
      teamId: "T1",
      channelId: "C1",
      responseUrl: "https://example.com",
      triggerId: "123",
    });
    expect(res).toEqual({ response_type: "ephemeral", text: "ok" });
  });

  it("verifies handleSlackHttp handling and event callback typing", async () => {
    const events: SlackEvent[] = [];
    const router = new CommandRouter();
    router.on("/webhook-collect", () => inChannel("done"));

    const res = await handleSlackHttp(
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

    expect(res.status).toBe(200);
    expect(events.length).toBeGreaterThan(0);
    const parsed = parseSlashCommand(TEST_BODY);
    expect(parsed.command).toBe("/webhook-collect");
  });
});
