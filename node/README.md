# webpay

TypeScript package for WebPay integration with server-side API requests.

## What is included

- ESM + CJS build output via `tsup`
- Type declarations (`.d.ts`)
- Runtime-neutral entrypoint in `src/index.ts`
- Server-side client in `src/server.ts` for OAuth + signed gateway requests
- Smoke tests for Node (`vitest`), Bun, and Deno
- Browser E2E test with Playwright

## Install dependencies

```bash
npm install
```

## Build

```bash
npm run build
```

## Test

```bash
npm test
```

```bash
npm run test:bun
```

```bash
npm run test:deno
```

```bash
npm run test:e2e
```

## Playwright setup

Install Chromium once before running E2E:

```bash
npx playwright install chromium
```

## Usage

### Basic package import

```ts
import { createWebPayClient } from "webpay";

const client = createWebPayClient();
console.log(client.ping());
```

### Deno (via npm specifier)

```ts
import { createWebPayClient } from "npm:webpay";

const client = createWebPayClient();
console.log(client.ping());
```

### Server-side WebPay API client (Node/Bun server)

```ts
import { createWebPayServerClient } from "webpay/server";

const client = createWebPayServerClient({
  baseUrl: "https://devwebpayment.kesspay.io",
  apiSecretKey: process.env.WEBPAY_API_SECRET_KEY!,
  sellerCode: process.env.WEBPAY_SELLER_CODE!,
  credentials: {
    clientId: process.env.WEBPAY_CLIENT_ID!,
    clientSecret: process.env.WEBPAY_CLIENT_SECRET!,
    username: process.env.WEBPAY_USERNAME!,
    password: process.env.WEBPAY_PASSWORD!
  }
});

const paymentLink = await client.generatePaymentLink({
  out_trade_no: "ORDER-1001",
  body: "Order #1001",
  total_amount: 10,
  currency: "USD",
  notify_url: "https://merchant.example.com/webpay/notify",
  redirect_url: "https://merchant.example.com/checkout/result"
});
```

Reference docs: `https://devwebpayment.kesspay.io/docs#introduction`
