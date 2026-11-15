const { test, expect } = require('@playwright/test');

const localeCases = [
  { requested: 'ar', resolved: 'ar', direction: 'rtl', landmark: 'تسجيل الدخول' },
  { requested: 'ur', resolved: 'ur', direction: 'rtl', landmark: 'سائن ان کریں۔' },
  { requested: 'id', resolved: 'id', direction: 'ltr', landmark: 'Masuk' },
  { requested: 'tr', resolved: 'tr', direction: 'ltr', landmark: 'Giriş yapın' },
  { requested: 'fr-CA fr en', resolved: 'fr', direction: 'ltr', landmark: 'Se connecter' },
  { requested: 'ru', resolved: 'ru', direction: 'ltr', landmark: 'Войти' },
  { requested: 'de-DE', resolved: 'en', direction: 'ltr', landmark: 'Sign in' },
];

for (const locale of localeCases) {
  test(`${locale.requested} resolves to ${locale.resolved}`, async ({ page }) => {
    await page.goto(`/auth?ui_locales=${encodeURIComponent(locale.requested)}`);

    await expect(page.locator('html')).toHaveAttribute('lang', locale.resolved);
    await expect(page.locator('html')).toHaveAttribute('dir', locale.direction);
    await expect(
      page.locator('form').getByRole('button', { name: locale.landmark, exact: true }),
    ).toBeVisible();
  });
}

test('forwards the selected locale from the test UI dropdown', async ({ page }) => {
  await page.goto('/');

  await page.getByLabel('Hosted UI locale').selectOption('tr');
  await page.getByRole('button', { name: 'Continue with Quran.com' }).click();
  await expect(page.locator('html')).toHaveAttribute('lang', 'tr');
});

test('keeps Arabic password and back controls in the expected visual order', async ({ page }) => {
  await page.goto('/auth?ui_locales=ar');

  const password = await page.locator('input[name="password"]').boundingBox();
  const passwordToggle = await page
    .getByRole('button', { name: 'إظهار كلمة المرور' })
    .boundingBox();
  const backIcon = await page.locator('button img[src="/images/arrow-back-fill.svg"]').boundingBox();
  const backText = await page.getByRole('button', { name: 'رجوع' }).locator('span').boundingBox();

  expect(password).not.toBeNull();
  expect(passwordToggle).not.toBeNull();
  expect(backIcon).not.toBeNull();
  expect(backText).not.toBeNull();
  expect(passwordToggle.x).toBeLessThan(password.x + password.width / 2);
  expect(backIcon.x).toBeLessThan(backText.x);

  await page.locator('form').getByRole('button', { name: 'تسجيل الدخول', exact: true }).click();
  await expect(page.getByText('عنوان البريد الإلكتروني مطلوب')).toBeVisible();
  await expect(page.getByText('كلمة المرور مطلوب')).toBeVisible();
});

test('keeps the existing English directional spacing and control order', async ({ page }) => {
  await page.goto('/auth?ui_locales=en');

  const passwordInput = page.locator('input[name="password"]');
  const password = await passwordInput.boundingBox();
  const passwordToggle = await page.getByRole('button', { name: 'Show password' }).boundingBox();
  const backIcon = await page.locator('button img[src="/images/arrow-back-fill.svg"]').boundingBox();
  const backText = await page.getByRole('button', { name: 'Back' }).locator('span').boundingBox();
  const padding = await passwordInput.evaluate((input) => {
    const style = getComputedStyle(input);
    return { left: style.paddingLeft, right: style.paddingRight };
  });

  expect(password).not.toBeNull();
  expect(passwordToggle).not.toBeNull();
  expect(backIcon).not.toBeNull();
  expect(backText).not.toBeNull();
  expect(passwordToggle.x).toBeGreaterThan(password.x + password.width / 2);
  expect(backIcon.x).toBeLessThan(backText.x);
  expect(padding).toEqual({ left: '16px', right: '16px' });
});

test('completes login, consent, callback, and token exchange', async ({ page, context }) => {
  const email = process.env.OAUTH_E2E_EMAIL;
  const password = process.env.OAUTH_E2E_PASSWORD;
  test.skip(!email || !password, 'Set OAUTH_E2E_EMAIL and OAUTH_E2E_PASSWORD for the full flow');

  try {
    const authResponse = await page.request.get('/auth?ui_locales=en', { maxRedirects: 0 });
    expect(authResponse.status()).toBe(302);
    const authorizationUrl = new URL(authResponse.headers().location);
    authorizationUrl.searchParams.set('prompt', 'consent');
    await page.goto(authorizationUrl.toString());
    await page.locator('input[name="email"]').fill(email);
    await page.locator('input[name="password"]').fill(password);
    await page.locator('form').getByRole('button', { name: 'Sign in', exact: true }).click();

    await page.waitForURL(/\/consent\?consent_challenge=/);
    await expect(page.getByRole('button', { name: 'Allow', exact: true })).toBeVisible();
    await page.getByRole('button', { name: 'Allow', exact: true }).click();

    await page.waitForURL('/');
    await expect(page.getByRole('heading', { name: 'Welcome!' })).toBeVisible();
  } finally {
    await context.close();
  }
});
