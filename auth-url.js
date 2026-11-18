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

function validatePrompt(value) {
  if (value === undefined || value === "") return undefined;
  if (typeof value !== "string") return null;

  const prompts = value.trim().split(/ +/);
  if (prompts.some((prompt) => !["none", "login", "consent"].includes(prompt))) return null;
  if (prompts.includes("none") && prompts.length > 1) return null;

  return [...new Set(prompts)].join(" ");
}

function authorizationUrl(client, options, uiLocales) {
  return client.authorizeURL({
    redirect_uri: options.callbackUrl,
    scope: options.scope,
    state: options.state,
    ...(options.prompt && { prompt: options.prompt }),
    ...(uiLocales && { ui_locales: uiLocales }),
  });
}

module.exports = { authorizationUrl, validateUiLocales, validatePrompt };
