# webpay-package

Cross-runtime TypeScript package scaffold that targets Node.js, Bun, and Deno.

## What is included

- ESM + CJS build output via `tsup`
- Type declarations (`.d.ts`)
- Runtime-neutral entrypoint in `src/index.ts`
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

### Node.js / Bun (npm package)

```ts
import { createWebPayClient } from "webpay-package";

const client = createWebPayClient();
console.log(client.ping());
```

### Deno (via npm specifier)

```ts
import { createWebPayClient } from "npm:webpay-package";

const client = createWebPayClient();
console.log(client.ping());
```
