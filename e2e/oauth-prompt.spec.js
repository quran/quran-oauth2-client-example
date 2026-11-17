const { test, expect } = require('@playwright/test');

test('forwards login prompts and rejects unsupported or ambiguous values', async ({ request }) => {
  const response = await request.get('/auth?prompt=login&ui_locales=ar', { maxRedirects: 0 });
  expect(response.status()).toBe(302);
  const authorizationUrl = new URL(response.headers().location);
  expect(authorizationUrl.searchParams.get('prompt')).toBe('login');
  expect(authorizationUrl.searchParams.get('ui_locales')).toBe('ar');

  for (const query of ['prompt=none', 'prompt=login&prompt=login', 'prompt[]=login']) {
    expect((await request.get(`/auth?${query}`, { maxRedirects: 0 })).status()).toBe(400);
  }
});

test('reuses normal SSO but requires credentials again with prompt=login', async ({ page, context, baseURL }) => {
  const email = process.env.OAUTH_E2E_EMAIL;
  const password = process.env.OAUTH_E2E_PASSWORD;
  test.skip(!email || !password, 'Set OAUTH_E2E_EMAIL and OAUTH_E2E_PASSWORD for the full flow');

  const signIn = async () => {
    await expect(page.locator('input[name="password"]')).toBeVisible();
    await page.locator('input[name="email"]').fill(email);
    await page.locator('input[name="password"]').fill(password);
    await page.locator('form').getByRole('button', { name: 'Sign in', exact: true }).click();
  };
  const finishAuthorization = async () => {
    await page.waitForURL((url) => url.pathname === '/consent' || url.href === `${baseURL}/`);
    if (new URL(page.url()).pathname === '/consent') {
      await page.getByRole('button', { name: 'Allow', exact: true }).click();
    }
    await page.waitForURL(`${baseURL}/`);
    await expect(page.getByRole('heading', { name: 'Welcome!' })).toBeVisible();
  };

  try {
    await page.goto('/');
    await page.getByLabel('Hosted UI locale').selectOption('en');
    await page.getByLabel('Require sign-in (prompt=login)').check();
    await page.getByRole('button', { name: 'Continue with Quran.com' }).click();
    await signIn();
    await finishAuthorization();

    await page.goto('/auth?ui_locales=en');
    await finishAuthorization();
    await expect(page.locator('input[name="password"]')).toHaveCount(0);

    await page.getByRole('link', { name: 'Sign in again', exact: true }).click();
    await expect(page).toHaveURL(/\/login\?login_challenge=/);
    await signIn();
    await finishAuthorization();
  } finally {
    await context.close();
  }
});
