import { describe, expect, it } from "vitest";
import { createWebPayClient } from "../src/index";

describe("createWebPayClient", () => {
  it("creates a client with a predictable health check", () => {
    const client = createWebPayClient();
    expect(client.ping()).toBe("webpay:ok");
  });
});
