import { expect, test } from "@playwright/test";

test("loads package in browser and returns health value", async ({ page }) => {
  await page.goto("/e2e/fixtures/index.html");
  await expect(page.locator('[data-testid="status"]')).toHaveText("webpay-package:ok");
});
