import { readFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { dirname, join, resolve } from "node:path";
import { fileURLToPath } from "node:url";

import { createWebPayServerClient, encryptObjectToHex, WebPayApiError, WebPayHttpError } from "../dist/server.js";

const __filename = fileURLToPath(import.meta.url);
const __dirname = dirname(__filename);
const repoRoot = resolve(__dirname, "..", "..");

const credentialFile = process.env.WEBPAY_CREDENTIAL_FILE ?? join(repoRoot, "credenail.txt");
const publicKeyFile = process.env.WEBPAY_PUBLIC_KEY_FILE ?? join(repoRoot, "sandbox-public.key");

function parseCredentialFile(raw) {
  const output = {};

  for (const line of raw.split(/\r?\n/)) {
    const match = line.match(/^\s*([A-Za-z_]+)\s*:\s*(.+)\s*$/);
    if (!match) {
      continue;
    }

    output[match[1].toLowerCase()] = match[2];
  }

  return output;
}

function getRequired(data, key) {
  const value = data[key];
  if (!value || typeof value !== "string") {
    throw new Error(`Missing required field in credential file: ${key}`);
  }
  return value;
}

async function runGatewayCase({ label, signType, apiSecretKey, config }) {
  const client = createWebPayServerClient({
    baseUrl: config.host,
    signType,
    apiSecretKey,
    sellerCode: config.sellerCode,
    credentials: {
      clientId: config.clientId,
      clientSecret: config.clientSecret,
      username: config.username,
      password: config.password
    }
  });

  try {
    await client.authenticateWithPassword();
    const response = await client.listPaymentMethods({ seller_code: config.sellerCode });
    return {
      label,
      ok: true,
      detail: `gateway success=${String(response.success)}`
    };
  } catch (error) {
    if (error instanceof WebPayApiError) {
      return {
        label,
        ok: false,
        detail: `WebPayApiError: ${error.response?.message ?? error.message}`
      };
    }

    if (error instanceof WebPayHttpError) {
      return {
        label,
        ok: false,
        detail: `WebPayHttpError: status=${error.status}`
      };
    }

    return {
      label,
      ok: false,
      detail: error instanceof Error ? error.message : String(error)
    };
  }
}

async function main() {
  if (!existsSync(credentialFile)) {
    throw new Error(`Credential file not found: ${credentialFile}`);
  }

  if (!existsSync(publicKeyFile)) {
    throw new Error(`Public key file not found: ${publicKeyFile}`);
  }

  const credentialRaw = await readFile(credentialFile, "utf8");
  const publicKeyPem = await readFile(publicKeyFile, "utf8");
  const credentials = parseCredentialFile(credentialRaw);

  const host = getRequired(credentials, "host");
  const username = getRequired(credentials, "username");
  const password = getRequired(credentials, "password");
  const clientId = getRequired(credentials, "client_id");
  const clientSecret = getRequired(credentials, "client_secret");
  const sellerCode = getRequired(credentials, "seller_code");
  const apiSecretKey = getRequired(credentials, "api_secret_key");

  const config = {
    host,
    username,
    password,
    clientId,
    clientSecret,
    sellerCode
  };

  const md5Result = await runGatewayCase({
    label: "MD5 with api_secret_key",
    signType: "MD5",
    apiSecretKey,
    config
  });

  const hmacSecretResult = await runGatewayCase({
    label: "HMAC-SHA256 with api_secret_key",
    signType: "HMAC-SHA256",
    apiSecretKey,
    config
  });

  const hmacPublicKeyResult = await runGatewayCase({
    label: "HMAC-SHA256 with sandbox-public.key",
    signType: "HMAC-SHA256",
    apiSecretKey: publicKeyPem,
    config
  });

  const encryptedCustomer = encryptObjectToHex(
    {
      email: "sandbox@example.com",
      customer_id: "TEST-1001"
    },
    publicKeyPem
  );

  const results = [md5Result, hmacSecretResult, hmacPublicKeyResult];
  for (const result of results) {
    process.stdout.write(`[${result.ok ? "PASS" : "FAIL"}] ${result.label} -> ${result.detail}\n`);
  }
  process.stdout.write(`[PASS] RSA encrypt with sandbox-public.key -> hex length ${encryptedCustomer.length}\n`);

  if (!md5Result.ok || !hmacSecretResult.ok) {
    process.exitCode = 1;
    return;
  }

  if (hmacPublicKeyResult.ok) {
    process.stdout.write("[WARN] HMAC with public key unexpectedly succeeded.\n");
  } else {
    process.stdout.write("[INFO] HMAC with public key failed (expected). Public key is for RSA encryption, not HMAC.\n");
  }
}

main().catch((error) => {
  process.stderr.write(`${error instanceof Error ? error.message : String(error)}\n`);
  process.exit(1);
});
