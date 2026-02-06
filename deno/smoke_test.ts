import { createWebPayClient } from "../src/index.ts";

Deno.test("createWebPayClient (deno)", () => {
  const client = createWebPayClient();
  if (client.ping() !== "webpay-package:ok") {
    throw new Error("Unexpected ping response");
  }
});
