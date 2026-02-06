import { describe, expect, it, vi } from "vitest";
import {
  WEBPAY_SERVICES,
  WebPayServerClient,
  createWebPayServerClient,
  makeSignature,
  verifySignature
} from "../src/server";

function mockJsonResponse(payload: unknown, status = 200) {
  return {
    ok: status >= 200 && status < 300,
    status,
    text: async () => JSON.stringify(payload)
  };
}

describe("WebPay signature", () => {
  it("creates MD5 signature using the documented algorithm", () => {
    const params = {
      service: "webpay.acquire.queryOrder",
      sign_type: "MD5" as const,
      seller_code: "SELLER",
      out_trade_no: "ORDER-1",
      sign: "IGNORE"
    };

    expect(makeSignature(params, "abc123")).toBe("cfe72b9f39febd2fd45b82bb31e6452e");
  });

  it("creates HMAC-SHA256 signature using the documented algorithm", () => {
    const params = {
      service: "webpay.acquire.queryOrder",
      sign_type: "HMAC-SHA256" as const,
      seller_code: "SELLER",
      out_trade_no: "ORDER-1"
    };

    expect(makeSignature(params, "abc123")).toBe("3577bc4baa1eb1a11e94fc22db2b12f7dbe420a80c121d9b6a1a81b391c79788");
  });

  it("verifies payload signature", () => {
    const payload: Record<string, unknown> = {
      service: "webpay.acquire.queryOrder",
      sign_type: "MD5",
      seller_code: "SELLER",
      out_trade_no: "ORDER-1"
    };

    payload.sign = makeSignature(payload, "abc123");
    expect(verifySignature(payload, "abc123")).toBe(true);
    expect(verifySignature(payload, "wrong-secret")).toBe(false);
  });
});

describe("WebPay server client", () => {
  it("auto signs and sends gateway requests with bearer token", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      mockJsonResponse({
        success: true,
        data: { token: "order-token" }
      })
    );

    const client = createWebPayServerClient({
      apiSecretKey: "my-secret",
      accessToken: "ACCESS-TOKEN",
      sellerCode: "SELLER-CODE",
      fetch: fetchMock
    });

    const result = await client.queryOrder({ out_trade_no: "ORDER-1" });
    expect(result.success).toBe(true);

    expect(fetchMock).toHaveBeenCalledTimes(1);
    const [url, options] = fetchMock.mock.calls[0] as [string, Record<string, unknown>];
    expect(url).toBe("https://devwebpayment.kesspay.io/api/mch/v2/gateway");

    const headers = options.headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer ACCESS-TOKEN");

    const body = JSON.parse(options.body as string) as Record<string, unknown>;
    expect(body.service).toBe(WEBPAY_SERVICES.QUERY_ORDER);
    expect(body.seller_code).toBe("SELLER-CODE");
    expect(body.sign).toBe(makeSignature(body, "my-secret"));
  });

  it("authenticates with password flow when no access token is set", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(
        mockJsonResponse({
          token_type: "Bearer",
          expires_in: 1800,
          access_token: "AUTO-TOKEN",
          refresh_token: "REFRESH-TOKEN"
        })
      )
      .mockResolvedValueOnce(
        mockJsonResponse({
          success: true,
          data: []
        })
      );

    const client = new WebPayServerClient({
      apiSecretKey: "my-secret",
      credentials: {
        clientId: "CID",
        clientSecret: "CSECRET",
        username: "user@example.com",
        password: "pass123"
      },
      fetch: fetchMock
    });

    await client.listPaymentMethods();

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [authUrl] = fetchMock.mock.calls[0] as [string, Record<string, unknown>];
    expect(authUrl).toBe("https://devwebpayment.kesspay.io/oauth/token");

    const [, gatewayOptions] = fetchMock.mock.calls[1] as [string, Record<string, unknown>];
    const headers = gatewayOptions.headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer AUTO-TOKEN");
  });
});
