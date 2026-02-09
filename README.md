# webpay

Multi-runtime WebPay client repository.

This root project is for all language SDKs.  
`node/` is the current implemented package.  
Additional SDKs will be added for PHP, Python, Java, and C#.

## Official API Reference

- Source documentation: `https://devwebpayment.kesspay.io/docs`
- Documented currency support in API fields: `USD`, `KHR` (2 currencies)

## Repository Goal

Provide a consistent WebPay integration experience across runtimes:

- same auth/signing behavior
- same gateway service coverage
- same error handling model
- language-native packaging and developer ergonomics

## Current Status

- Implemented: `node/` (TypeScript package: `webpay`)
- Planned: `php/`, `python/`, `java/`, `csharp/`

## Suggested Top-Level Layout

```txt
webpay/
  README.md
  AGENT.md
  node/
  php/
  python/
  java/
  csharp/
  specs/
```

## Runtime Packages

- `node/`: npm package, ESM/CJS build, Node/Bun/Deno smoke tests, Playwright e2e
- `php/`: planned Composer package
- `python/`: planned PyPI package
- `java/`: planned Maven/Gradle package
- `csharp/`: planned NuGet package

## Shared Specification Direction

Use a shared spec-first approach for cross-runtime parity:

- request/response data contract
- signing algorithms (`MD5`, `HMAC-SHA256`)
- OAuth token behavior
- error taxonomy (HTTP vs API/business errors)
- service method naming map

## Working in Node Package

```bash
cd node
npm install
npm run typecheck
npm test
```

See `node/README.md` for Node package details.

## Self Spec Driving

Repository-level agent workflow is documented in `AGENT.md`.
