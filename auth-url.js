const MAX_UI_LOCALES_LENGTH = 256;
const MAX_UI_LOCALES = 10;

function validateUiLocales(value) {
  if (value === undefined || value === "") return undefined;
  if (typeof value !== "string" || value.length > MAX_UI_LOCALES_LENGTH) return null;

  const locales = value.trim().split(/\s+/);
  if (!locales.length || locales.length > MAX_UI_LOCALES) return null;

  try {
    Intl.getCanonicalLocales(locales);
  } catch {
    return null;
  }

  return locales.join(" ");
}

function authorizationUrl(client, options, uiLocales) {
  return client.authorizeURL({
    redirect_uri: options.callbackUrl,
    scope: options.scope,
    state: options.state,
    ...(uiLocales && { ui_locales: uiLocales }),
  });
}

module.exports = { authorizationUrl, validateUiLocales };
