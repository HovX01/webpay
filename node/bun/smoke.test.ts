import { describe, expect, it } from "bun:test";
import { createWebPayClient } from "../src/index.ts";

describe("createWebPayClient (bun)", () => {
  it("creates a client", () => {
    const client = createWebPayClient();
    expect(client.ping()).toBe("webpay:ok");
  });
});
