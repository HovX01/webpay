# webpay (Node Package)

This `node/` directory is the npm package for WebPay client integration.
It ships a lightweight base client plus a server-side client for OAuth and
signed gateway requests.

## Scope

- Package name: `webpay`
- Runtime target: Node.js (primary), with smoke coverage for Bun and Deno
- Output: ESM + CJS + type declarations
- Exports:
  - `webpay` -> base client (`src/index.ts`)
  - `webpay/server` -> server client (`src/server.ts`)

## Requirements

- Node.js `>=18`
- npm

## Install

```bash
npm install
```

## Build and Quality Checks

```bash
npm run build
npm run typecheck
npm test
```

Extra runtime checks:

```bash
npm run test:bun
npm run test:deno
```

Sandbox sign check (uses `../credenail.txt` and `../sandbox-public.key` by default):

```bash
npm run test:sandbox-sign
```

Browser E2E:

```bash
npx playwright install chromium
npm run test:e2e
```

## Project Layout

- `src/index.ts`: Base `WebPayClient` (`ping()` smoke API)
- `src/server.ts`: `WebPayServerClient` for OAuth, signing, gateway calls
- `test/`: Vitest tests for signatures and server client behavior
- `bun/`, `deno/`: Cross-runtime smoke tests
- `e2e/`: Playwright browser smoke test and fixture page
- `scripts/e2e-server.mjs`: Static server used by Playwright

## Environment Variables (Server Client)

- Required:
  - `WEBPAY_API_SECRET_KEY`
- Required for OAuth authentication:
  - `WEBPAY_CLIENT_ID`
  - `WEBPAY_CLIENT_SECRET`
  - `WEBPAY_USERNAME`
  - `WEBPAY_PASSWORD`
- Optional:
  - `WEBPAY_BASE_URL` (default: `https://devwebpayment.kesspay.io`)
  - `WEBPAY_SELLER_CODE`
  - `WEBPAY_SIGN_TYPE` (`MD5` or `HMAC-SHA256`)

Note: request signing (`MD5` and `HMAC-SHA256`) uses `api_secret_key`.
The sandbox public key is for RSA encryption helpers (`encryptToHex`, `encryptObjectToHex`).
The server client authenticates via `POST /oauth/token` using `grant_type: "password"` and uses the returned `access_token` for gateway routes.
On `401`, it re-authenticates once and retries the gateway request.

## Usage

### Base client

```ts
import { createWebPayClient } from "webpay";

const client = createWebPayClient();
console.log(client.ping()); // webpay:ok
```

### Server client (env-driven)

```ts
import { createWebPayServerClient } from "webpay/server";

const client = createWebPayServerClient();
const result = await client.queryOrder({ out_trade_no: "ORDER-1001" });
console.log(result);
```

### Server client (explicit config)

```ts
import { createWebPayServerClient } from "webpay/server";

const client = createWebPayServerClient({
  baseUrl: "https://devwebpayment.kesspay.io",
  apiSecretKey: process.env.WEBPAY_API_SECRET_KEY!,
  signType: "MD5",
  credentials: {
    clientId: process.env.WEBPAY_CLIENT_ID!,
    clientSecret: process.env.WEBPAY_CLIENT_SECRET!,
    username: process.env.WEBPAY_USERNAME!,
    password: process.env.WEBPAY_PASSWORD!
  },
  sellerCode: process.env.WEBPAY_SELLER_CODE
});
```

### Signature helpers

```ts
import { makeSignature, verifySignature } from "webpay/server";

const payload = {
  service: "webpay.acquire.queryOrder",
  sign_type: "MD5",
  out_trade_no: "ORDER-1001"
};

const sign = makeSignature(payload, process.env.WEBPAY_API_SECRET_KEY!);
const valid = verifySignature({ ...payload, sign }, process.env.WEBPAY_API_SECRET_KEY!);
console.log(valid);
```

### DirectPay card encryption helper

Use the documented card shape (`number`, `securityCode`, `expiry.month`, `expiry.year`) and encrypt it to hex:

```ts
import { encryptDirectPayCardToHex } from "webpay/server";
import fs from "node:fs";

const publicKeyPem = fs.readFileSync("./sandbox-public.key", "utf8");

const card = encryptDirectPayCardToHex(
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

await client.directPay({
  out_trade_no: "TEST-1234567891",
  body: "iPhone 13 pro Case",
  total_amount: 10,
  currency: "USD",
  service_code: "VISA_MASTER",
  card,
  ip_address: "203.0.113.10"
});
```

## Error Types

- `WebPayHttpError`: non-2xx HTTP responses (inspect `error.status`, `error.response`, `error.details`)
- `WebPayApiError`: gateway response with `success: false` (inspect `error.response`, `error.details`, `error.code`)

Example:

```ts
import { WebPayApiError, WebPayHttpError } from "webpay/server";

try {
  await client.queryOrder({ out_trade_no: "ORDER-1001" });
} catch (error) {
  if (error instanceof WebPayHttpError || error instanceof WebPayApiError) {
    console.error(error.message);
    console.error("response:", error.response);
  }
}
```

## Self Spec Driving

Agent workflow for this package is documented in `AGENT.md`.
