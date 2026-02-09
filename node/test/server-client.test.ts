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

const WEBPAY_ENV_KEYS = [
  "WEBPAY_API_SECRET_KEY",
  "WEBPAY_ACCESS_TOKEN",
  "WEBPAY_SELLER_CODE",
  "WEBPAY_BASE_URL",
  "WEBPAY_SIGN_TYPE",
  "WEBPAY_CLIENT_ID",
  "WEBPAY_CLIENT_SECRET",
  "WEBPAY_USERNAME",
  "WEBPAY_PASSWORD"
] as const;

type WebPayEnvKey = (typeof WEBPAY_ENV_KEYS)[number];

function withWebPayEnv(overrides: Partial<Record<WebPayEnvKey, string | undefined>>) {
  const keys = Object.keys(overrides) as WebPayEnvKey[];
  const previous: Partial<Record<WebPayEnvKey, string | undefined>> = {};

  for (const key of keys) {
    previous[key] = process.env[key];
    const next = overrides[key];
    if (typeof next === "string") {
      process.env[key] = next;
    } else {
      delete process.env[key];
    }
  }

  return () => {
    for (const key of keys) {
      const value = previous[key];
      if (typeof value === "string") {
        process.env[key] = value;
      } else {
        delete process.env[key];
      }
    }
  };
}

describe("WebPay signature", () => {
  it("normalizes lowercase MD5 sign_type", () => {
    const params = {
      service: "webpay.acquire.queryOrder",
      sign_type: "md5",
      seller_code: "SELLER",
      out_trade_no: "ORDER-1"
    };

    expect(makeSignature(params, "abc123")).toBe("cfe72b9f39febd2fd45b82bb31e6452e");
  });

  it("normalizes lowercase HMAC-SHA256 sign_type", () => {
    const params = {
      service: "webpay.acquire.queryOrder",
      sign_type: "hmac-sha256",
      seller_code: "SELLER",
      out_trade_no: "ORDER-1"
    };

    expect(makeSignature(params, "abc123")).toBe("3577bc4baa1eb1a11e94fc22db2b12f7dbe420a80c121d9b6a1a81b391c79788");
  });

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

  it("supports subscription lifecycle helper methods", async () => {
    const fetchMock = vi
      .fn()
      .mockResolvedValue(
        mockJsonResponse({
          success: true,
          data: {}
        })
      );

    const client = createWebPayServerClient({
      apiSecretKey: "my-secret",
      accessToken: "ACCESS-TOKEN",
      sellerCode: "SELLER-CODE",
      fetch: fetchMock
    });

    await client.generateSubscriptionLink({
      out_trade_no: "ORDER-1",
      total_amount: 10,
      currency: "USD",
      interval: "daily",
      notify_url: "https://merchant.example/notify"
    });
    await client.cancelSubscription({ code: "SUB-1" });
    await client.reActiveSubscription({ subscription_code: "SUB-1" });
    await client.getSubscriptionTrxs({ subscription_code: "SUB-1" });
    await client.getSubscriptions();

    const services = fetchMock.mock.calls.map(([, options]) => {
      const body = JSON.parse((options.body as string) ?? "{}") as Record<string, unknown>;
      return body.service;
    });

    expect(services).toEqual([
      WEBPAY_SERVICES.GENERATE_SUBSCRIPTION_LINK,
      WEBPAY_SERVICES.CANCEL_SUBSCRIPTION,
      WEBPAY_SERVICES.RE_ACTIVE_SUBSCRIPTION,
      WEBPAY_SERVICES.GET_SUBSCRIPTION_TRXS,
      WEBPAY_SERVICES.GET_SUBSCRIPTIONS
    ]);
  });

  it("creates client from WEBPAY_* env vars when options are omitted", async () => {
    const restore = withWebPayEnv({
      WEBPAY_API_SECRET_KEY: "env-secret",
      WEBPAY_ACCESS_TOKEN: "ENV-TOKEN",
      WEBPAY_SELLER_CODE: "ENV-SELLER"
    });

    try {
      const fetchMock = vi.fn().mockResolvedValue(
        mockJsonResponse({
          success: true,
          data: { ok: true }
        })
      );

      const client = createWebPayServerClient({ fetch: fetchMock });
      await client.queryOrder({ out_trade_no: "ORDER-ENV" });

      expect(fetchMock).toHaveBeenCalledTimes(1);
      const [, options] = fetchMock.mock.calls[0] as [string, Record<string, unknown>];
      const headers = options.headers as Record<string, string>;
      expect(headers.Authorization).toBe("Bearer ENV-TOKEN");

      const body = JSON.parse(options.body as string) as Record<string, unknown>;
      expect(body.seller_code).toBe("ENV-SELLER");
    } finally {
      restore();
    }
  });

  it("supports createWebPayServerClient.default() alias", () => {
    const restore = withWebPayEnv({
      WEBPAY_API_SECRET_KEY: "env-secret",
      WEBPAY_ACCESS_TOKEN: "ENV-TOKEN"
    });

    try {
      const fetchMock = vi.fn().mockResolvedValue(
        mockJsonResponse({
          success: true,
          data: { ok: true }
        })
      );

      const client = createWebPayServerClient.default({ fetch: fetchMock });
      expect(client).toBeInstanceOf(WebPayServerClient);
    } finally {
      restore();
    }
  });

  it("throws helpful error when API secret key is missing", () => {
    const restore = withWebPayEnv({
      WEBPAY_API_SECRET_KEY: undefined
    });

    try {
      expect(() => createWebPayServerClient({ fetch: vi.fn() })).toThrow("WEBPAY_API_SECRET_KEY");
    } finally {
      restore();
    }
  });
});
