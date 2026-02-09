import { describe, expect, it, vi } from "vitest";
import {
  WEBPAY_SERVICES,
  WebPayApiError,
  WebPayHttpError,
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

  it("authenticates first when credentials are configured, then uses oauth token for gateway routes", async () => {
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
          data: { ok: true }
        })
      );

    const client = new WebPayServerClient({
      apiSecretKey: "my-secret",
      accessToken: "STATIC-TOKEN",
      credentials: {
        clientId: "CID",
        clientSecret: "CSECRET",
        username: "user@example.com",
        password: "pass123"
      },
      fetch: fetchMock
    });

    await client.queryOrder({ out_trade_no: "ORDER-1" });

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [authUrl] = fetchMock.mock.calls[0] as [string, Record<string, unknown>];
    const [gatewayUrl, gatewayOptions] = fetchMock.mock.calls[1] as [string, Record<string, unknown>];
    expect(authUrl).toBe("https://devwebpayment.kesspay.io/oauth/token");
    expect(gatewayUrl).toBe("https://devwebpayment.kesspay.io/api/mch/v2/gateway");

    const headers = gatewayOptions.headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer AUTO-TOKEN");
  });

  it("re-authenticates and retries once when gateway responds with 401", async () => {
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
        mockJsonResponse(
          {
            message: "Unauthorized"
          },
          401
        )
      )
      .mockResolvedValueOnce(
        mockJsonResponse({
          token_type: "Bearer",
          expires_in: 1800,
          access_token: "NEW-TOKEN",
          refresh_token: "REFRESH-TOKEN"
        })
      )
      .mockResolvedValueOnce(
        mockJsonResponse({
          success: true,
          data: { ok: true }
        })
      );

    const client = new WebPayServerClient({
      apiSecretKey: "my-secret",
      accessToken: "STALE-TOKEN",
      sellerCode: "SELLER-CODE",
      credentials: {
        clientId: "CID",
        clientSecret: "CSECRET",
        username: "user@example.com",
        password: "pass123"
      },
      fetch: fetchMock
    });

    const result = await client.queryOrder({ out_trade_no: "ORDER-1" });
    expect(result.success).toBe(true);

    expect(fetchMock).toHaveBeenCalledTimes(4);
    const [initialAuthUrl] = fetchMock.mock.calls[0] as [string, Record<string, unknown>];
    const [firstGatewayUrl, firstGatewayOptions] = fetchMock.mock.calls[1] as [string, Record<string, unknown>];
    const [retryAuthUrl] = fetchMock.mock.calls[2] as [string, Record<string, unknown>];
    const [secondGatewayUrl, secondGatewayOptions] = fetchMock.mock.calls[3] as [string, Record<string, unknown>];

    expect(initialAuthUrl).toBe("https://devwebpayment.kesspay.io/oauth/token");
    expect(firstGatewayUrl).toBe("https://devwebpayment.kesspay.io/api/mch/v2/gateway");
    expect(retryAuthUrl).toBe("https://devwebpayment.kesspay.io/oauth/token");
    expect(secondGatewayUrl).toBe("https://devwebpayment.kesspay.io/api/mch/v2/gateway");

    const firstHeaders = firstGatewayOptions.headers as Record<string, string>;
    const secondHeaders = secondGatewayOptions.headers as Record<string, string>;
    expect(firstHeaders.Authorization).toBe("Bearer AUTO-TOKEN");
    expect(secondHeaders.Authorization).toBe("Bearer NEW-TOKEN");
  });

  it("throws actionable message for 401 when credentials are not configured", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      mockJsonResponse(
        {
          message: "Unauthorized"
        },
        401
      )
    );

    const client = createWebPayServerClient({
      apiSecretKey: "my-secret",
      accessToken: "STALE-TOKEN",
      fetch: fetchMock
    });

    await expect(client.queryOrder({ out_trade_no: "ORDER-1" })).rejects.toMatchObject({
      name: "WebPayHttpError",
      status: 401,
      message: expect.stringContaining("Access token is likely invalid or expired.")
    });
    expect(fetchMock).toHaveBeenCalledTimes(1);
  });

  it("includes gateway error response payload on WebPayApiError", async () => {
    const fetchMock = vi.fn().mockResolvedValue(
      mockJsonResponse({
        success: false,
        code: "INVALID_SIGN",
        message: "Invalid signature.",
        data: {
          request_id: "REQ-1"
        }
      })
    );

    const client = createWebPayServerClient({
      apiSecretKey: "my-secret",
      accessToken: "ACCESS-TOKEN",
      fetch: fetchMock
    });

    try {
      await client.queryOrder({ out_trade_no: "ORDER-1" });
      throw new Error("Expected queryOrder() to fail");
    } catch (error) {
      expect(error).toBeInstanceOf(WebPayApiError);
      const apiError = error as WebPayApiError;
      expect(apiError.message).toContain("Invalid signature.");
      expect(apiError.code).toBe("INVALID_SIGN");
      expect(apiError.details).toEqual({ request_id: "REQ-1" });
      expect(apiError.response).toMatchObject({
        success: false,
        code: "INVALID_SIGN"
      });
    }
  });

  it("includes http error response payload on WebPayHttpError", async () => {
    const httpPayload = {
      message: "Unauthorized",
      code: "AUTH_FAILED"
    };
    const fetchMock = vi.fn().mockResolvedValue(mockJsonResponse(httpPayload, 401));

    const client = createWebPayServerClient({
      apiSecretKey: "my-secret",
      accessToken: "ACCESS-TOKEN",
      fetch: fetchMock
    });

    try {
      await client.queryOrder({ out_trade_no: "ORDER-1" });
      throw new Error("Expected queryOrder() to fail");
    } catch (error) {
      expect(error).toBeInstanceOf(WebPayHttpError);
      const httpError = error as WebPayHttpError;
      expect(httpError.status).toBe(401);
      expect(httpError.message).toContain("Unauthorized");
      expect(httpError.details).toEqual(httpPayload);
      expect(httpError.response).toEqual(httpPayload);
    }
  });

  it("wraps network errors with status 0 and preserves cause", async () => {
    const cause = new Error("socket hang up");
    const fetchMock = vi.fn().mockRejectedValue(cause);

    const client = createWebPayServerClient({
      apiSecretKey: "my-secret",
      accessToken: "ACCESS-TOKEN",
      fetch: fetchMock
    });

    try {
      await client.queryOrder({ out_trade_no: "ORDER-1" });
      throw new Error("Expected queryOrder() to fail");
    } catch (error) {
      expect(error).toBeInstanceOf(WebPayHttpError);
      const httpError = error as WebPayHttpError;
      expect(httpError.status).toBe(0);
      expect(httpError.message).toContain("socket hang up");
      expect(httpError.response).toEqual({
        error: "network_error",
        message: "socket hang up"
      });
      expect(httpError.cause).toBe(cause);
    }
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
