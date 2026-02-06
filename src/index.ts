export interface WebPayOptions {
  baseUrl?: string;
  apiKey?: string;
}

export class WebPayClient {
  readonly baseUrl: string;

  constructor(options: WebPayOptions = {}) {
    this.baseUrl = options.baseUrl ?? "https://api.example.com";
  }

  ping(): string {
    return "webpay-package:ok";
  }
}

export function createWebPayClient(options: WebPayOptions = {}): WebPayClient {
  return new WebPayClient(options);
}
