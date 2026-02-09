import { constants, createHash, createHmac, publicEncrypt } from "node:crypto";

import type {
  GatewayPayload,
  SignType,
  WebPayApiResponse,
  WebPayCancelSubscriptionRequest,
  WebPayCloseOrderRequest,
  WebPayDirectPayRequest,
  WebPayDirectPayResponseData,
  WebPayGatewayRequestByService,
  WebPayGatewayResponseByService,
  WebPayGeneratePaymentLinkRequest,
  WebPayGenerateSubscriptionLinkRequest,
  WebPayGenerateSubscriptionLinkResponseData,
  WebPayGetSubscriptionsRequest,
  WebPayGetSubscriptionTrxsRequest,
  WebPayHttpErrorOptions,
  WebPayKnownServiceName,
  WebPayListPaymentMethodsRequest,
  WebPayMessageResponseData,
  WebPayNativePayRequest,
  WebPayNativePayResponseData,
  WebPayOAuthPasswordCredentials,
  WebPayOAuthTokenResponse,
  WebPayOrderInfo,
  WebPayPaginatedData,
  WebPayPaymentMethod,
  WebPayQueryOrderByDateRangeRequest,
  WebPayQueryOrderByDateRangeResponseData,
  WebPayQueryOrderRequest,
  WebPayQueryRefundRequest,
  WebPayReActiveSubscriptionRequest,
  WebPayRefundHistory,
  WebPayRefundRequest,
  WebPaySaveCardRequest,
  WebPayServerClientInput,
  WebPayServerClientOptions,
  WebPaySubscriptionInfo,
  WebPaySubscriptionRequest,
  WebPaySubscriptionResponseData,
  WebPaySubscriptionTrxInfo,
  WebPayQuickPayRequest
} from "./server.types";

export type * from "./server.types";

export const WEBPAY_SERVICES = {
  LIST_PAYMENT_METHODS: "webpay.acquire.getpaymentmethods",
  GENERATE_PAYMENT_LINK: "webpay.acquire.createorder",
  NATIVE_PAY: "webpay.acquire.nativePay",
  QUICK_PAY: "webpay.acquire.quickpay",
  DIRECT_PAY: "webpay.acquire.directPay",
  CLOSE_ORDER: "webpay.acquire.closeorder",
  QUERY_ORDER: "webpay.acquire.queryOrder",
  QUERY_REFUND: "webpay.acquire.queryRefund",
  QUERY_ORDER_BY_DATE_RANGE: "webpay.acquire.queryorderbydaterange",
  REFUND: "webpay.acquire.v2Refund",
  SAVE_CARD: "webpay.acquire.saveCard",
  SUBSCRIPTION: "webpay.acquire.subscription",
  GENERATE_SUBSCRIPTION_LINK: "webpay.acquire.generateSubscriptionLink",
  CANCEL_SUBSCRIPTION: "webpay.acquire.cancelSubscription",
  RE_ACTIVE_SUBSCRIPTION: "webpay.acquire.reActiveSubscription",
  GET_SUBSCRIPTION_TRXS: "webpay.acquire.getSubscriptionTrxs",
  GET_SUBSCRIPTIONS: "webpay.acquire.getSubscriptions"
} as const;

export class WebPayHttpError extends Error {
  readonly status: number;
  readonly details: unknown;
  readonly response: unknown;
  readonly cause?: unknown;

  constructor(message: string, options: WebPayHttpErrorOptions) {
    super(message);
    this.name = "WebPayHttpError";
    this.status = options.status;
    this.details = options.details;
    this.response = options.details;
    this.cause = options.cause;
  }
}

export class WebPayApiError extends Error {
  readonly response: WebPayApiResponse<unknown>;
  readonly details: unknown;
  readonly code?: string | number;

  constructor(message: string, response: WebPayApiResponse<unknown>) {
    const detailMessage = extractHttpErrorMessage(response);
    super(appendDetailToMessage(message, detailMessage));
    this.name = "WebPayApiError";
    this.response = response;
    this.details = response.data;
    this.code = extractApiErrorCode(response);
  }
}

type FetchLike = NonNullable<WebPayServerClientOptions["fetch"]>;
type FetchResponseLike = Awaited<ReturnType<FetchLike>>;

export type WebPayServerClientFactory = ((options?: WebPayServerClientInput) => WebPayServerClient) & {
  default: (options?: WebPayServerClientInput) => WebPayServerClient;
};
function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function assertServerRuntime(): void {
  if ("window" in globalThis && typeof (globalThis as { window?: unknown }).window !== "undefined") {
    throw new Error("WebPay server client must run on the server side.");
  }
}

function normalizeBaseUrl(baseUrl?: string): string {
  return (baseUrl ?? "https://devwebpayment.kesspay.io").replace(/\/+$/, "");
}

function resolveFetch(fetchImpl?: FetchLike): FetchLike {
  if (fetchImpl) {
    return fetchImpl;
  }
  if (typeof globalThis.fetch !== "function") {
    throw new Error("No fetch implementation found. Pass options.fetch in server environments without global fetch.");
  }
  return globalThis.fetch as unknown as FetchLike;
}

function getEnvValue(name: string): string | undefined {
  const value = process.env[name];
  if (!value) {
    return undefined;
  }

  const trimmed = value.trim();
  if (!trimmed) {
    return undefined;
  }

  return trimmed;
}

function normalizeSignType(signType: string | undefined): SignType | undefined {
  if (!signType) {
    return undefined;
  }

  const normalized = signType.trim().toUpperCase();
  if (normalized === "MD5" || normalized === "HMAC-SHA256") {
    return normalized;
  }

  return undefined;
}

function resolveCredentialsFromEnv(): WebPayOAuthPasswordCredentials | undefined {
  const clientId = getEnvValue("WEBPAY_CLIENT_ID");
  const clientSecret = getEnvValue("WEBPAY_CLIENT_SECRET");
  const username = getEnvValue("WEBPAY_USERNAME");
  const password = getEnvValue("WEBPAY_PASSWORD");

  if (!clientId && !clientSecret && !username && !password) {
    return undefined;
  }

  if (!clientId || !clientSecret || !username || !password) {
    throw new Error(
      "Incomplete WEBPAY OAuth credentials. Set WEBPAY_CLIENT_ID, WEBPAY_CLIENT_SECRET, WEBPAY_USERNAME, WEBPAY_PASSWORD."
    );
  }

  return {
    clientId,
    clientSecret,
    username,
    password
  };
}

function resolveServerClientOptions(options: WebPayServerClientInput = {}): WebPayServerClientOptions {
  const apiSecretKey = options.apiSecretKey ?? getEnvValue("WEBPAY_API_SECRET_KEY");
  if (!apiSecretKey) {
    throw new Error("Missing WebPay API secret key. Provide options.apiSecretKey or set WEBPAY_API_SECRET_KEY.");
  }

  const signType = options.signType ?? normalizeSignType(getEnvValue("WEBPAY_SIGN_TYPE")) ?? "MD5";
  const credentials = options.credentials ?? resolveCredentialsFromEnv();
  if (!credentials) {
    throw new Error(
      "Missing OAuth password credentials. Provide options.credentials or set WEBPAY_CLIENT_ID, WEBPAY_CLIENT_SECRET, WEBPAY_USERNAME, WEBPAY_PASSWORD."
    );
  }

  return {
    apiSecretKey,
    baseUrl: options.baseUrl ?? getEnvValue("WEBPAY_BASE_URL"),
    signType,
    sellerCode: options.sellerCode ?? getEnvValue("WEBPAY_SELLER_CODE"),
    credentials,
    fetch: options.fetch
  };
}

function extractHttpErrorMessage(details: unknown): string | undefined {
  if (!isRecord(details)) {
    return undefined;
  }

  const detailKeys = ["message", "error_description", "error", "detail", "msg"] as const;
  for (const key of detailKeys) {
    const value = details[key];
    if (typeof value !== "string") {
      continue;
    }

    const trimmed = value.trim();
    if (trimmed) {
      return trimmed;
    }
  }

  return undefined;
}

function extractApiErrorCode(details: unknown): string | number | undefined {
  if (!isRecord(details)) {
    return undefined;
  }

  const codeKeys = ["code", "error_code", "status_code"] as const;
  for (const key of codeKeys) {
    const value = details[key];
    if (typeof value === "string" || typeof value === "number") {
      return value;
    }
  }

  return undefined;
}

function appendDetailToMessage(baseMessage: string, detailMessage?: string): string {
  if (!detailMessage) {
    return baseMessage;
  }
  if (baseMessage.includes(detailMessage)) {
    return baseMessage;
  }
  return `${baseMessage} ${detailMessage}`;
}

function toErrorMessage(error: unknown): string {
  if (error instanceof Error && typeof error.message === "string" && error.message.trim().length > 0) {
    return error.message.trim();
  }
  return String(error);
}

function isSignable(value: unknown): boolean {
  if (value === null || value === undefined) {
    return false;
  }
  if (Array.isArray(value)) {
    return false;
  }
  if (typeof value === "object") {
    return false;
  }
  if (value === "") {
    return false;
  }
  return true;
}

export function toUrlParams(values: Record<string, unknown>): string {
  return Object.keys(values)
    .sort()
    .filter((key) => key !== "sign" && isSignable(values[key]))
    .map((key) => `${key}=${String(values[key]).trim()}`)
    .join("&");
}

export function makeSignature(values: Record<string, unknown>, apiSecretKey: string): string {
  const signType = normalizeSignType(typeof values.sign_type === "string" ? values.sign_type : undefined) ?? "MD5";
  const valuesForSigning =
    typeof values.sign_type === "string" && values.sign_type !== signType
      ? {
          ...values,
          sign_type: signType
        }
      : values;
  const base = `${toUrlParams(valuesForSigning)}&key=${apiSecretKey}`;

  if (signType === "HMAC-SHA256") {
    return createHmac("sha256", apiSecretKey).update(base).digest("hex");
  }

  return createHash("md5").update(base).digest("hex");
}

export function verifySignature(values: Record<string, unknown>, apiSecretKey: string): boolean {
  const sign = values.sign;
  if (typeof sign !== "string" || sign.length === 0) {
    return false;
  }
  return makeSignature(values, apiSecretKey) === sign;
}

export function encryptToHex(plainText: string, publicKeyPem: string): string {
  const encrypted = publicEncrypt(
    {
      key: publicKeyPem,
      padding: constants.RSA_PKCS1_PADDING
    },
    Buffer.from(plainText, "utf8")
  );

  return encrypted.toString("hex");
}

export function encryptObjectToHex(payload: Record<string, unknown>, publicKeyPem: string): string {
  return encryptToHex(JSON.stringify(payload), publicKeyPem);
}

export class WebPayServerClient {
  private readonly baseUrl: string;
  private readonly fetchImpl: FetchLike;
  private readonly apiSecretKey: string;
  private readonly signType: SignType;
  private readonly defaultSellerCode?: string;
  private readonly credentials: WebPayOAuthPasswordCredentials;
  private accessToken?: string;

  constructor(options: WebPayServerClientOptions) {
    assertServerRuntime();

    this.baseUrl = normalizeBaseUrl(options.baseUrl);
    this.fetchImpl = resolveFetch(options.fetch);
    this.apiSecretKey = options.apiSecretKey;
    this.signType = options.signType ?? "MD5";
    this.defaultSellerCode = options.sellerCode;
    this.credentials = options.credentials;
  }

  async authenticateWithPassword(credentials?: WebPayOAuthPasswordCredentials): Promise<WebPayOAuthTokenResponse> {
    const payload = credentials ?? this.credentials;
    const response = await this.postJson<WebPayOAuthTokenResponse>("/oauth/token", {
      grant_type: "password",
      client_id: payload.clientId,
      client_secret: payload.clientSecret,
      username: payload.username,
      password: payload.password
    });

    this.accessToken = response.access_token;
    return response;
  }

  async refreshAccessToken(refreshToken: string, clientId: string, clientSecret: string): Promise<WebPayOAuthTokenResponse> {
    const response = await this.postJson<WebPayOAuthTokenResponse>("/oauth/token", {
      grant_type: "refresh_token",
      client_id: clientId,
      client_secret: clientSecret,
      refresh_token: refreshToken
    });

    this.accessToken = response.access_token;
    return response;
  }

  async gateway<TService extends WebPayKnownServiceName>(
    service: TService,
    payload: WebPayGatewayRequestByService<TService>
  ): Promise<WebPayApiResponse<WebPayGatewayResponseByService<TService>>>;
  async gateway<TData = unknown>(service: string, payload?: GatewayPayload): Promise<WebPayApiResponse<TData>>;
  async gateway<TData = unknown>(service: string, payload: GatewayPayload = {}): Promise<WebPayApiResponse<TData>> {
    const accessToken = await this.getOrAuthenticateAccessToken();
    const requestPayload: GatewayPayload = {
      service,
      sign_type: this.signType,
      ...payload
    };

    if (!requestPayload.sign_type) {
      requestPayload.sign_type = this.signType;
    } else if (typeof requestPayload.sign_type === "string") {
      requestPayload.sign_type = normalizeSignType(requestPayload.sign_type) ?? this.signType;
    }

    if (!requestPayload.sign) {
      requestPayload.sign = makeSignature(requestPayload, this.apiSecretKey);
    }

    const response = await this.postGatewayWithAuthRetry<TData>(requestPayload, accessToken);

    if (response && typeof response.success === "boolean" && !response.success) {
      throw new WebPayApiError("WebPay gateway request failed.", response as WebPayApiResponse<unknown>);
    }

    return response;
  }

  async listPaymentMethods(payload: WebPayListPaymentMethodsRequest = {}): Promise<WebPayApiResponse<WebPayPaymentMethod[]>> {
    return this.gateway(WEBPAY_SERVICES.LIST_PAYMENT_METHODS, payload);
  }

  async generatePaymentLink(payload: WebPayGeneratePaymentLinkRequest): Promise<WebPayApiResponse<WebPayOrderInfo>> {
    return this.gateway(WEBPAY_SERVICES.GENERATE_PAYMENT_LINK, this.withDefaultSellerCode(payload));
  }

  async nativePay(payload: WebPayNativePayRequest): Promise<WebPayApiResponse<WebPayNativePayResponseData>> {
    return this.gateway(WEBPAY_SERVICES.NATIVE_PAY, this.withDefaultSellerCode(payload));
  }

  async quickPay(payload: WebPayQuickPayRequest): Promise<WebPayApiResponse<WebPayOrderInfo>> {
    return this.gateway(WEBPAY_SERVICES.QUICK_PAY, this.withDefaultSellerCode(payload));
  }

  async directPay(payload: WebPayDirectPayRequest): Promise<WebPayApiResponse<WebPayDirectPayResponseData>> {
    return this.gateway(WEBPAY_SERVICES.DIRECT_PAY, this.withDefaultSellerCode(payload));
  }

  async closeOrder(payload: WebPayCloseOrderRequest): Promise<WebPayApiResponse<WebPayOrderInfo>> {
    return this.gateway(WEBPAY_SERVICES.CLOSE_ORDER, this.withDefaultSellerCode(payload));
  }

  async queryOrder(payload: WebPayQueryOrderRequest): Promise<WebPayApiResponse<WebPayOrderInfo>> {
    return this.gateway(WEBPAY_SERVICES.QUERY_ORDER, this.withDefaultSellerCode(payload));
  }

  async queryRefund(payload: WebPayQueryRefundRequest): Promise<WebPayApiResponse<WebPayRefundHistory>> {
    return this.gateway(WEBPAY_SERVICES.QUERY_REFUND, this.withDefaultSellerCode(payload));
  }

  async queryOrderByDateRange(
    payload: WebPayQueryOrderByDateRangeRequest
  ): Promise<WebPayApiResponse<WebPayQueryOrderByDateRangeResponseData>> {
    return this.gateway(WEBPAY_SERVICES.QUERY_ORDER_BY_DATE_RANGE, this.withDefaultSellerCode(payload));
  }

  async refund(payload: WebPayRefundRequest): Promise<WebPayApiResponse<WebPayRefundHistory>> {
    return this.gateway(WEBPAY_SERVICES.REFUND, this.withDefaultSellerCode(payload));
  }

  async saveCard(payload: WebPaySaveCardRequest): Promise<WebPayApiResponse<{ link: string }>> {
    return this.gateway(WEBPAY_SERVICES.SAVE_CARD, this.withDefaultSellerCode(payload));
  }

  async subscription(payload: WebPaySubscriptionRequest): Promise<WebPayApiResponse<WebPaySubscriptionResponseData>> {
    return this.gateway(WEBPAY_SERVICES.SUBSCRIPTION, this.withDefaultSellerCode(payload));
  }

  async generateSubscriptionLink(
    payload: WebPayGenerateSubscriptionLinkRequest
  ): Promise<WebPayApiResponse<WebPayGenerateSubscriptionLinkResponseData>> {
    return this.gateway(WEBPAY_SERVICES.GENERATE_SUBSCRIPTION_LINK, this.withDefaultSellerCode(payload));
  }

  async cancelSubscription(payload: WebPayCancelSubscriptionRequest): Promise<WebPayApiResponse<WebPayMessageResponseData>> {
    return this.gateway(WEBPAY_SERVICES.CANCEL_SUBSCRIPTION, this.withDefaultSellerCode(payload));
  }

  async reActiveSubscription(payload: WebPayReActiveSubscriptionRequest): Promise<WebPayApiResponse<WebPayMessageResponseData>> {
    return this.gateway(WEBPAY_SERVICES.RE_ACTIVE_SUBSCRIPTION, this.withDefaultSellerCode(payload));
  }

  async getSubscriptionTrxs(
    payload: WebPayGetSubscriptionTrxsRequest = {}
  ): Promise<WebPayApiResponse<WebPayPaginatedData<WebPaySubscriptionTrxInfo>>> {
    return this.gateway(WEBPAY_SERVICES.GET_SUBSCRIPTION_TRXS, this.withDefaultSellerCode(payload));
  }

  async getSubscriptions(payload: WebPayGetSubscriptionsRequest = {}): Promise<WebPayApiResponse<WebPayPaginatedData<WebPaySubscriptionInfo>>> {
    return this.gateway(WEBPAY_SERVICES.GET_SUBSCRIPTIONS, this.withDefaultSellerCode(payload));
  }

  private withDefaultSellerCode<TPayload extends { seller_code?: string }>(payload: TPayload): TPayload {
    if (!this.defaultSellerCode || payload.seller_code) {
      return payload;
    }

    return {
      ...payload,
      seller_code: this.defaultSellerCode
    } as TPayload;
  }

  private async getOrAuthenticateAccessToken(): Promise<string> {
    if (this.accessToken) {
      return this.accessToken;
    }

    const auth = await this.authenticateWithPassword();
    return auth.access_token;
  }

  private async postGatewayWithAuthRetry<TData>(
    payload: GatewayPayload,
    accessToken: string
  ): Promise<WebPayApiResponse<TData>> {
    try {
      return await this.postJson<WebPayApiResponse<TData>>("/api/mch/v2/gateway", payload, accessToken);
    } catch (error) {
      if (!(error instanceof WebPayHttpError) || error.status !== 401) {
        throw error;
      }

      const auth = await this.authenticateWithPassword();
      return this.postJson<WebPayApiResponse<TData>>("/api/mch/v2/gateway", payload, auth.access_token);
    }
  }

  private async postJson<T>(path: string, payload: Record<string, unknown>, accessToken?: string): Promise<T> {
    const headers: Record<string, string> = {
      "Content-Type": "application/json"
    };

    if (accessToken) {
      headers.Authorization = `Bearer ${accessToken}`;
    }

    let response: FetchResponseLike;
    try {
      response = await this.fetchImpl(`${this.baseUrl}${path}`, {
        method: "POST",
        headers,
        body: JSON.stringify(payload)
      });
    } catch (cause) {
      const detailMessage = toErrorMessage(cause);
      throw new WebPayHttpError(`WebPay request failed before receiving HTTP response. ${detailMessage}`, {
        status: 0,
        details: {
          error: "network_error",
          message: detailMessage
        },
        cause
      });
    }

    let data: unknown;
    try {
      data = await parseJsonResponse(response);
    } catch (cause) {
      const detailMessage = toErrorMessage(cause);
      throw new WebPayHttpError(`WebPay failed to parse HTTP response. ${detailMessage}`, {
        status: response.status,
        details: {
          error: "response_parse_error",
          message: detailMessage
        },
        cause
      });
    }

    if (!response.ok) {
      const detailMessage = extractHttpErrorMessage(data);
      const message = appendDetailToMessage(`WebPay request failed with status ${response.status}.`, detailMessage);
      throw new WebPayHttpError(message, {
        status: response.status,
        details: data
      });
    }

    if (isRecord(data)) {
      return data as unknown as T;
    }

    throw new Error("WebPay returned a non-object JSON response.");
  }
}

async function parseJsonResponse(response: FetchResponseLike): Promise<unknown> {
  const raw = await response.text();
  if (!raw) {
    return {};
  }

  try {
    return JSON.parse(raw);
  } catch {
    return { raw };
  }
}

function createResolvedWebPayServerClient(options: WebPayServerClientInput = {}): WebPayServerClient {
  return new WebPayServerClient(resolveServerClientOptions(options));
}

export const createWebPayServerClient: WebPayServerClientFactory = Object.assign(
  (options: WebPayServerClientInput = {}) => createResolvedWebPayServerClient(options),
  {
    default: (options: WebPayServerClientInput = {}) => createResolvedWebPayServerClient(options)
  }
);
