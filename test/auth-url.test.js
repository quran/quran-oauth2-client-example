const test = require("node:test");
const assert = require("node:assert/strict");
const { authorizationUrl, validateUiLocales } = require("../auth-url");

test("accepts ordered BCP 47 locale preferences", () => {
  assert.equal(validateUiLocales("fr-CA fr en"), "fr-CA fr en");
  assert.equal(validateUiLocales("ar"), "ar");
  assert.equal(validateUiLocales("zz-ZZ"), "zz-ZZ");
});

test("rejects malformed and oversized locale preferences", () => {
  assert.equal(validateUiLocales("fr_CA"), null);
  assert.equal(validateUiLocales("en-1"), null);
  assert.equal(validateUiLocales("fr<script>"), null);
  assert.equal(validateUiLocales("a".repeat(257)), null);
  assert.equal(validateUiLocales("en ar ur id tr fr ru de es it pt"), null);
});

test("adds ui_locales only when supplied", () => {
  const client = { authorizeURL: (params) => new URLSearchParams(params).toString() };
  const options = { callbackUrl: "http://localhost:3005/callback", scope: "openid", state: "state" };

  assert.match(authorizationUrl(client, options, "fr-CA fr en"), /ui_locales=fr-CA\+fr\+en/);
  assert.doesNotMatch(authorizationUrl(client, options), /ui_locales=/);
});
