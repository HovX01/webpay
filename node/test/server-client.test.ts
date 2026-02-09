import { constants, generateKeyPairSync, privateDecrypt } from "node:crypto";
import { mkdtempSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";

import { describe, expect, it, vi } from "vitest";
import {
  WEBPAY_SERVICES,
  WebPayApiError,
  WebPayHttpError,
  WebPayServerClient,
  createWebPayServerClient,
  encryptDirectPayCardToHex,
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
  "WEBPAY_SELLER_CODE",
  "WEBPAY_BASE_URL",
  "WEBPAY_SIGN_TYPE",
  "WEBPAY_CLIENT_ID",
  "WEBPAY_CLIENT_SECRET",
  "WEBPAY_USERNAME",
  "WEBPAY_PASSWORD",
  "WEBPAY_PUBLIC_KEY_PEM",
  "WEBPAY_PUBLIC_KEY_FILE"
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

describe("WebPay encryption", () => {
  it("encrypts direct pay card payload using documented card fields", () => {
    const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();

    const encryptedHex = encryptDirectPayCardToHex(
      {
        number: "5473500160001018",
        securityCode: "123",
        expiry: {
          month: "12",
          year: "35"
        }
      },
      publicKeyPem
    );

    const decrypted = privateDecrypt(
      {
        key: privateKey,
        padding: constants.RSA_PKCS1_PADDING
      },
      Buffer.from(encryptedHex, "hex")
    ).toString("utf8");

    expect(JSON.parse(decrypted)).toEqual({
      number: "5473500160001018",
      securityCode: "123",
      expiry: {
        month: "12",
        year: "35"
      }
    });
  });

  it("throws helpful error when required card fields are missing", () => {
    const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
    const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();

    expect(() =>
      encryptDirectPayCardToHex(
        {
          number: "5473500160001018",
          securityCode: "123",
          expiry: {
            month: "",
            year: "35"
          }
        },
        publicKeyPem
      )
    ).toThrow('Invalid direct pay card payload: "expiry.month" must be a non-empty string or number.');
  });
});

describe("WebPay server client", () => {
  it("auto signs and sends gateway requests with oauth bearer token", async () => {
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
          data: { token: "order-token" }
        })
      );

    const client = createWebPayServerClient({
      apiSecretKey: "my-secret",
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

    expect(fetchMock).toHaveBeenCalledTimes(2);
    const [authUrl, authOptions] = fetchMock.mock.calls[0] as [string, Record<string, unknown>];
    expect(authUrl).toBe("https://devwebpayment.kesspay.io/oauth/token");
    const authBody = JSON.parse(authOptions.body as string) as Record<string, unknown>;
    expect(authBody.grant_type).toBe("password");

    const [url, options] = fetchMock.mock.calls[1] as [string, Record<string, unknown>];
    expect(url).toBe("https://devwebpayment.kesspay.io/api/mch/v2/gateway");

    const headers = options.headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer AUTO-TOKEN");

    const body = JSON.parse(options.body as string) as Record<string, unknown>;
    expect(body.service).toBe(WEBPAY_SERVICES.QUERY_ORDER);
    expect(body.seller_code).toBe("SELLER-CODE");
    expect(body.sign).toBe(makeSignature(body, "my-secret"));
  });

  it("authenticates with password flow and uses bearer token", async () => {
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
    const [authUrl, authOptions] = fetchMock.mock.calls[0] as [string, Record<string, unknown>];
    expect(authUrl).toBe("https://devwebpayment.kesspay.io/oauth/token");
    const authBody = JSON.parse(authOptions.body as string) as Record<string, unknown>;
    expect(authBody.grant_type).toBe("password");

    const [, gatewayOptions] = fetchMock.mock.calls[1] as [string, Record<string, unknown>];
    const headers = gatewayOptions.headers as Record<string, string>;
    expect(headers.Authorization).toBe("Bearer AUTO-TOKEN");
  });

  it("authenticates once and reuses oauth token across gateway routes", async () => {
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
      )
      .mockResolvedValueOnce(
        mockJsonResponse({
          success: true,
          data: { ok: true }
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

    await client.queryOrder({ out_trade_no: "ORDER-1" });
    await client.queryOrder({ out_trade_no: "ORDER-2" });

    expect(fetchMock).toHaveBeenCalledTimes(3);
    const [authUrl, authOptions] = fetchMock.mock.calls[0] as [string, Record<string, unknown>];
    const [gatewayUrl, gatewayOptions] = fetchMock.mock.calls[1] as [string, Record<string, unknown>];
    const [secondGatewayUrl] = fetchMock.mock.calls[2] as [string, Record<string, unknown>];
    expect(authUrl).toBe("https://devwebpayment.kesspay.io/oauth/token");
    const authBody = JSON.parse(authOptions.body as string) as Record<string, unknown>;
    expect(authBody.grant_type).toBe("password");
    expect(gatewayUrl).toBe("https://devwebpayment.kesspay.io/api/mch/v2/gateway");
    expect(secondGatewayUrl).toBe("https://devwebpayment.kesspay.io/api/mch/v2/gateway");

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
    const [initialAuthUrl, initialAuthOptions] = fetchMock.mock.calls[0] as [string, Record<string, unknown>];
    const [firstGatewayUrl, firstGatewayOptions] = fetchMock.mock.calls[1] as [string, Record<string, unknown>];
    const [retryAuthUrl, retryAuthOptions] = fetchMock.mock.calls[2] as [string, Record<string, unknown>];
    const [secondGatewayUrl, secondGatewayOptions] = fetchMock.mock.calls[3] as [string, Record<string, unknown>];

    expect(initialAuthUrl).toBe("https://devwebpayment.kesspay.io/oauth/token");
    expect(firstGatewayUrl).toBe("https://devwebpayment.kesspay.io/api/mch/v2/gateway");
    expect(retryAuthUrl).toBe("https://devwebpayment.kesspay.io/oauth/token");
    expect(secondGatewayUrl).toBe("https://devwebpayment.kesspay.io/api/mch/v2/gateway");
    const initialAuthBody = JSON.parse(initialAuthOptions.body as string) as Record<string, unknown>;
    const retryAuthBody = JSON.parse(retryAuthOptions.body as string) as Record<string, unknown>;
    expect(initialAuthBody.grant_type).toBe("password");
    expect(retryAuthBody.grant_type).toBe("password");

    const firstHeaders = firstGatewayOptions.headers as Record<string, string>;
    const secondHeaders = secondGatewayOptions.headers as Record<string, string>;
    expect(firstHeaders.Authorization).toBe("Bearer AUTO-TOKEN");
    expect(secondHeaders.Authorization).toBe("Bearer NEW-TOKEN");
  });

  it("throws helpful error when oauth credentials are missing", () => {
    const restore = withWebPayEnv({
      WEBPAY_API_SECRET_KEY: "env-secret",
      WEBPAY_CLIENT_ID: undefined,
      WEBPAY_CLIENT_SECRET: undefined,
      WEBPAY_USERNAME: undefined,
      WEBPAY_PASSWORD: undefined
    });

    try {
      expect(() => createWebPayServerClient({ fetch: vi.fn() })).toThrow(
        "Missing OAuth password credentials"
      );
    } finally {
      restore();
    }
  });

  it("includes gateway error response payload on WebPayApiError", async () => {
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
      credentials: {
        clientId: "CID",
        clientSecret: "CSECRET",
        username: "user@example.com",
        password: "pass123"
      },
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
      .mockResolvedValueOnce(mockJsonResponse(httpPayload, 401))
      .mockResolvedValueOnce(
        mockJsonResponse({
          token_type: "Bearer",
          expires_in: 1800,
          access_token: "RETRY-TOKEN",
          refresh_token: "REFRESH-TOKEN"
        })
      )
      .mockResolvedValueOnce(mockJsonResponse(httpPayload, 401));

    const client = createWebPayServerClient({
      apiSecretKey: "my-secret",
      credentials: {
        clientId: "CID",
        clientSecret: "CSECRET",
        username: "user@example.com",
        password: "pass123"
      },
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
      credentials: {
        clientId: "CID",
        clientSecret: "CSECRET",
        username: "user@example.com",
        password: "pass123"
      },
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
      .mockResolvedValueOnce(
        mockJsonResponse({
          token_type: "Bearer",
          expires_in: 1800,
          access_token: "AUTO-TOKEN",
          refresh_token: "REFRESH-TOKEN"
        })
      )
      .mockResolvedValue(
        mockJsonResponse({
          success: true,
          data: {}
        })
      );

    const client = createWebPayServerClient({
      apiSecretKey: "my-secret",
      sellerCode: "SELLER-CODE",
      credentials: {
        clientId: "CID",
        clientSecret: "CSECRET",
        username: "user@example.com",
        password: "pass123"
      },
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

    const services = fetchMock.mock.calls
      .map(([, options]) => {
        const body = JSON.parse((options.body as string) ?? "{}") as Record<string, unknown>;
        return body.service;
      })
      .filter((service): service is string => typeof service === "string");

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
      WEBPAY_SELLER_CODE: "ENV-SELLER",
      WEBPAY_CLIENT_ID: "ENV-CID",
      WEBPAY_CLIENT_SECRET: "ENV-CSECRET",
      WEBPAY_USERNAME: "env.user@example.com",
      WEBPAY_PASSWORD: "env-pass"
    });

    try {
      const fetchMock = vi
        .fn()
        .mockResolvedValueOnce(
          mockJsonResponse({
            token_type: "Bearer",
            expires_in: 1800,
            access_token: "ENV-TOKEN",
            refresh_token: "ENV-REFRESH-TOKEN"
          })
        )
        .mockResolvedValueOnce(
          mockJsonResponse({
            success: true,
            data: { ok: true }
          })
        );

      const client = createWebPayServerClient({ fetch: fetchMock });
      await client.queryOrder({ out_trade_no: "ORDER-ENV" });

      expect(fetchMock).toHaveBeenCalledTimes(2);
      const [, authOptions] = fetchMock.mock.calls[0] as [string, Record<string, unknown>];
      const authBody = JSON.parse(authOptions.body as string) as Record<string, unknown>;
      expect(authBody.grant_type).toBe("password");

      const [, options] = fetchMock.mock.calls[1] as [string, Record<string, unknown>];
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
      WEBPAY_CLIENT_ID: "ENV-CID",
      WEBPAY_CLIENT_SECRET: "ENV-CSECRET",
      WEBPAY_USERNAME: "env.user@example.com",
      WEBPAY_PASSWORD: "env-pass"
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

  it("loads WEBPAY_PUBLIC_KEY_FILE and encrypts direct pay card from client helper", () => {
    const tempDir = mkdtempSync(join(tmpdir(), "webpay-public-key-"));
    try {
      const { publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
      const publicKeyPem = publicKey.export({ type: "spki", format: "pem" }).toString();
      const publicKeyPath = join(tempDir, "sandbox-public.key");
      writeFileSync(publicKeyPath, publicKeyPem, "utf8");

      const restore = withWebPayEnv({
        WEBPAY_API_SECRET_KEY: "env-secret",
        WEBPAY_CLIENT_ID: "ENV-CID",
        WEBPAY_CLIENT_SECRET: "ENV-CSECRET",
        WEBPAY_USERNAME: "env.user@example.com",
        WEBPAY_PASSWORD: "env-pass",
        WEBPAY_PUBLIC_KEY_FILE: publicKeyPath
      });

      try {
        const client = createWebPayServerClient({ fetch: vi.fn() });
        const encryptedHex = client.encryptDirectPayCard({
          number: "5473500160001018",
          securityCode: "123",
          expiry: {
            month: "12",
            year: "35"
          }
        });

        expect(encryptedHex).toMatch(/^[0-9a-f]+$/);
        expect(encryptedHex.length).toBeGreaterThan(0);
      } finally {
        restore();
      }
    } finally {
      rmSync(tempDir, { recursive: true, force: true });
    }
  });

  it("throws helpful error when client encrypt helper has no public key configured", () => {
    const client = createWebPayServerClient({
      apiSecretKey: "my-secret",
      credentials: {
        clientId: "CID",
        clientSecret: "CSECRET",
        username: "user@example.com",
        password: "pass123"
      },
      fetch: vi.fn()
    });

    expect(() =>
      client.encryptDirectPayCard({
        number: "5473500160001018",
        securityCode: "123",
        expiry: {
          month: "12",
          year: "35"
        }
      })
    ).toThrow("Missing WebPay RSA public key");
  });
});
