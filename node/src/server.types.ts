export type SignType = "MD5" | "HMAC-SHA256";

export type WebPayCurrency = "USD" | "KHR" | (string & {});
export type WebPayDateString = string;
export type WebPayDateTimeString = string;
export type WebPayEncryptedHex = string;

export interface WebPaySignableRequest {
  sign_type?: SignType;
  sign?: string;
}

export interface WebPaySellerScopedRequest extends WebPaySignableRequest {
  seller_code?: string;
}

export interface WebPayStoreLinks {
  ios: string | null;
  android: string | null;
}

export interface WebPayPaymentMethod {
  id: number;
  title: string;
  img_url?: string;
  bic?: string;
  storelink?: WebPayStoreLinks;
  instruction_text?: string | null;
  type?: string | null;
  img?: string | null;
  app_name?: string | null;
  app_logo?: string | null;
  brand_logo?: string | null;
  swift_code?: string | null;
  payment_type?: string | null;
  sort_level?: string | number | null;
  emv_enabled?: number | boolean | null;
  native_pay_enabled?: number | boolean | null;
  ios_deeplink?: string | null;
  android_deeplink?: string | null;
  activated?: number | boolean | null;
  created_at?: WebPayDateTimeString | null;
  updated_at?: WebPayDateTimeString | null;
  deleted_at?: WebPayDateTimeString | null;
  [key: string]: unknown;
}

export interface WebPaySetting {
  template?: string;
  enabled_payment_methods?: string[];
  payment_type?: "offline" | "online" | (string & {});
  background_color?: string;
  display_fee_amount?: number;
}

export interface WebPayCustomerPayload {
  phone_number: string;
  email: string;
  first_name: string;
  last_name: string;
  address?: string;
  city?: string;
  postcode?: string;
}

export interface WebPayTransactionRequestFields {
  out_trade_no: string;
  body: string;
  total_amount: number;
  currency: WebPayCurrency;
  schema_url?: string;
  notify_url?: string;
  redirect_url?: string;
  expires_in?: number;
}

export interface WebPayBankInfo {
  senderBank?: string | null;
  senderPartcode?: string | null;
  account_name?: string | null;
  account_number?: string | null;
  [key: string]: unknown;
}

export interface WebPayCardInfo {
  BIN?: string | null;
  scheme?: string | null;
  card_token?: string | null;
  swift_code?: string | null;
  card_hashed?: string | null;
  holder_name?: string | null;
  account_logo?: string | null;
  account_name?: string | null;
  account_number?: string | null;
  [key: string]: unknown;
}

export interface WebPayRefundHistory {
  amount: number;
  currency: WebPayCurrency;
  status: string;
  reason: string;
  transaction_id: string;
  rejected_reason?: string | null;
  out_trade_no?: string | null;
  merchant_reference?: string | null;
  [key: string]: unknown;
}

export interface WebPayErrorLog {
  code: string;
  message: string;
  created_at: WebPayDateTimeString;
}

export interface WebPayPaymentDetail {
  method_desc?: string | null;
  holder_name?: string | null;
  card_info?: WebPayCardInfo | null;
  bank_info?: WebPayBankInfo | null;
  created_at?: WebPayDateTimeString | null;
  payment_method_bic?: string | null;
  payment_method?: WebPayPaymentMethod | null;
  [key: string]: unknown;
}

export interface WebPaySellerInfo {
  code: string;
  display_name: string;
  [key: string]: unknown;
}

export interface WebPayWeChatAlipayInfo {
  openid?: string | null;
  service?: string | null;
  currency?: WebPayCurrency | null;
  total_amount?: number | string | null;
  total_amount_cny?: number | string | null;
  [key: string]: unknown;
}

export interface WebPayOrderInfo {
  token: string;
  out_trade_no: string;
  transaction_id?: string | null;
  body: string;
  total_amount: number;
  currency: WebPayCurrency;
  meta?: Record<string, unknown> | null;
  status: string;
  paid_at?: WebPayDateTimeString | null;
  settled_at?: WebPayDateTimeString | null;
  settlement_date?: WebPayDateTimeString | null;
  expired_at: WebPayDateTimeString;
  created_at: WebPayDateTimeString;
  detail?: unknown[];
  seller?: WebPaySellerInfo | null;
  payment_detail?: WebPayPaymentDetail | null;
  bank_info?: WebPayBankInfo | null;
  refund_histories?: WebPayRefundHistory[] | null;
  queue_number?: string | null;
  payment_link?: string;
  error_logs?: WebPayErrorLog[];
  card_info?: WebPayCardInfo | null;
  wechat_alipay_info?: WebPayWeChatAlipayInfo | null;
  [key: string]: unknown;
}

export interface WebPayPaginationInfo {
  current_page: number;
  last_page: number;
  per_page: number;
  total: number;
  from?: number;
  to?: number;
}

export interface WebPayPaginatedData<TItem> extends WebPayPaginationInfo {
  data: TItem[];
}

export interface WebPaySubscriptionInfo {
  subscription_code: string;
  out_trade_no: string;
  amount: number;
  currency: WebPayCurrency;
  status: string;
  interval: string;
  created_at: WebPayDateTimeString;
}

export interface WebPaySubscriptionTrxInfo {
  transaction_id: string;
  subscription_code: string;
  out_trade_no: string;
  amount: number;
  currency: WebPayCurrency;
  status: string;
  billing_date: WebPayDateTimeString;
  created_at: WebPayDateTimeString;
}

export interface WebPayListPaymentMethodsRequest extends WebPaySignableRequest {}

export interface WebPayGeneratePaymentLinkRequest extends WebPaySellerScopedRequest, WebPayTransactionRequestFields {
  login_type?: "ANONYMOUS" | "GENERAL" | "FACEBOOK" | (string & {});
  setting?: WebPaySetting;
  customer?: WebPayEncryptedHex;
  descriptor?: string;
}

export interface WebPayNativePayRequest extends WebPaySellerScopedRequest, WebPayTransactionRequestFields {
  only_deeplink?: boolean | 0 | 1;
  is_ios_device?: boolean | 0 | 1;
  service_code: string;
  descriptor?: string;
}

export interface WebPayQuickPayRequest extends WebPaySellerScopedRequest, WebPayTransactionRequestFields {
  auth_code: string | number;
  service_code: "WECHAT" | "ALIPAY" | (string & {});
}

export interface WebPayDirectPayRequest extends WebPaySellerScopedRequest, WebPayTransactionRequestFields {
  card?: WebPayEncryptedHex;
  setting?: WebPaySetting;
  customer?: WebPayEncryptedHex;
  ip_address?: string;
  ip_addess?: string;
  service_code?: "VISA_MASTER" | "GOOGLEPAY" | "UNIONPAY" | (string & {});
  descriptor?: string;
  holder_name?: string;
}

export interface WebPayCloseOrderRequest extends WebPaySellerScopedRequest {
  out_trade_no: string;
}

export interface WebPayQueryOrderRequest extends WebPaySellerScopedRequest {
  out_trade_no: string;
}

export type WebPayQueryRefundRequest =
  | (WebPaySellerScopedRequest & {
      transaction_id: string;
      merchant_reference?: string;
    })
  | (WebPaySellerScopedRequest & {
      merchant_reference: string;
      transaction_id?: string;
    });

export interface WebPayQueryOrderByDateRangeRequest extends WebPaySellerScopedRequest {
  start_date: WebPayDateString;
  end_date: WebPayDateString;
  per_page: number;
  page: number;
}

export interface WebPayRefundRequest extends WebPaySellerScopedRequest {
  out_trade_no: string;
  reason: string;
  partial_refund_amount?: number;
  partial_refund_amount_ccy?: WebPayCurrency;
  callback_url?: string;
  merchant_reference?: string;
}

export interface WebPaySaveCardRequest extends WebPaySellerScopedRequest {
  notify_url: string;
  redirect_url?: string;
}

export interface WebPaySubscriptionRequest extends WebPaySellerScopedRequest {
  pre_order_token: string;
  holder_name: string;
  card: WebPayEncryptedHex;
  interval: "daily" | "weekly" | "monthly" | (string & {});
}

export interface WebPayGenerateSubscriptionLinkRequest extends WebPaySellerScopedRequest {
  total_amount: number;
  currency: WebPayCurrency;
  interval: "daily" | "weekly" | "monthly" | (string & {});
  notify_url: string;
  redirect_url?: string;
  out_trade_no: string;
}

export interface WebPayCancelSubscriptionRequest extends WebPaySellerScopedRequest {
  code: string;
}

export interface WebPayReActiveSubscriptionRequest extends WebPaySellerScopedRequest {
  subscription_code: string;
}

export interface WebPayGetSubscriptionTrxsRequest extends WebPaySellerScopedRequest {
  subscription_code?: string;
  out_trade_no?: string;
  start_date?: WebPayDateString;
  end_date?: WebPayDateString;
}

export interface WebPayGetSubscriptionsRequest extends WebPaySellerScopedRequest {
  start_date?: WebPayDateString;
  end_date?: WebPayDateString;
}

export interface WebPayNativePayResponseData {
  qrcode?: string | null;
  qrcode_link?: string | null;
  deeplink?: string | null;
  expires_in: number;
  for_ios?: boolean | null;
  brand_logo?: string | null;
  app_name?: string | null;
  service_code?: string;
  order_info: WebPayOrderInfo;
}

export interface WebPayDirectPayResponseData {
  required_3ds: boolean;
  pre_card_input: boolean;
  html_confirm_payment?: string | null;
  order_info: WebPayOrderInfo;
}

export interface WebPaySubscriptionResponseData {
  code: string;
  status: string;
  html_confirm_payment?: string | null;
}

export interface WebPayGenerateSubscriptionLinkResponseData {
  link: string;
  total_amount: number;
  currency: WebPayCurrency;
  interval: string;
}

export interface WebPayMessageResponseData {
  message: string;
}

export interface WebPayQueryOrderByDateRangeResponseData extends WebPayPaginationInfo {
  items: WebPayOrderInfo[];
}

export interface WebPayGatewaySchema {
  "webpay.acquire.getpaymentmethods": {
    request: WebPayListPaymentMethodsRequest;
    response: WebPayPaymentMethod[];
  };
  "webpay.acquire.createorder": {
    request: WebPayGeneratePaymentLinkRequest;
    response: WebPayOrderInfo;
  };
  "webpay.acquire.nativePay": {
    request: WebPayNativePayRequest;
    response: WebPayNativePayResponseData;
  };
  "webpay.acquire.quickpay": {
    request: WebPayQuickPayRequest;
    response: WebPayOrderInfo;
  };
  "webpay.acquire.directPay": {
    request: WebPayDirectPayRequest;
    response: WebPayDirectPayResponseData;
  };
  "webpay.acquire.closeorder": {
    request: WebPayCloseOrderRequest;
    response: WebPayOrderInfo;
  };
  "webpay.acquire.queryOrder": {
    request: WebPayQueryOrderRequest;
    response: WebPayOrderInfo;
  };
  "webpay.acquire.queryRefund": {
    request: WebPayQueryRefundRequest;
    response: WebPayRefundHistory;
  };
  "webpay.acquire.queryorderbydaterange": {
    request: WebPayQueryOrderByDateRangeRequest;
    response: WebPayQueryOrderByDateRangeResponseData;
  };
  "webpay.acquire.v2Refund": {
    request: WebPayRefundRequest;
    response: WebPayRefundHistory;
  };
  "webpay.acquire.saveCard": {
    request: WebPaySaveCardRequest;
    response: {
      link: string;
    };
  };
  "webpay.acquire.subscription": {
    request: WebPaySubscriptionRequest;
    response: WebPaySubscriptionResponseData;
  };
  "webpay.acquire.generateSubscriptionLink": {
    request: WebPayGenerateSubscriptionLinkRequest;
    response: WebPayGenerateSubscriptionLinkResponseData;
  };
  "webpay.acquire.cancelSubscription": {
    request: WebPayCancelSubscriptionRequest;
    response: WebPayMessageResponseData;
  };
  "webpay.acquire.reActiveSubscription": {
    request: WebPayReActiveSubscriptionRequest;
    response: WebPayMessageResponseData;
  };
  "webpay.acquire.getSubscriptionTrxs": {
    request: WebPayGetSubscriptionTrxsRequest;
    response: WebPayPaginatedData<WebPaySubscriptionTrxInfo>;
  };
  "webpay.acquire.getSubscriptions": {
    request: WebPayGetSubscriptionsRequest;
    response: WebPayPaginatedData<WebPaySubscriptionInfo>;
  };
}

export type WebPayKnownServiceName = keyof WebPayGatewaySchema;
export type WebPayServiceName = WebPayKnownServiceName;
export type WebPayGatewayRequestByService<TService extends WebPayKnownServiceName> = WebPayGatewaySchema[TService]["request"];
export type WebPayGatewayResponseByService<TService extends WebPayKnownServiceName> = WebPayGatewaySchema[TService]["response"];

export interface WebPayOAuthPasswordCredentials {
  clientId: string;
  clientSecret: string;
  username: string;
  password: string;
}

export interface WebPayOAuthTokenResponse {
  token_type: "Bearer";
  expires_in: number | string;
  access_token: string;
  refresh_token: string;
}

export interface WebPayApiResponse<TData = unknown> {
  success: boolean;
  data: TData;
  message?: string;
  sign?: string;
  sign_type?: SignType;
  [key: string]: unknown;
}

export interface WebPayHttpErrorOptions {
  status: number;
  details: unknown;
  cause?: unknown;
}

export interface WebPayServerClientOptions {
  apiSecretKey: string;
  baseUrl?: string;
  signType?: SignType;
  accessToken?: string;
  sellerCode?: string;
  credentials?: WebPayOAuthPasswordCredentials;
  fetch?: (url: string, init?: Record<string, unknown>) => Promise<{
    ok: boolean;
    status: number;
    text(): Promise<string>;
  }>;
}

export type GatewayPayload = Record<string, unknown>;
export type WebPayServerClientInput = Partial<WebPayServerClientOptions>;
