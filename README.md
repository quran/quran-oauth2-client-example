# OAuth2 Client Example

An example OAuth2 client that shows how to integrate a web app with Quran Foundation's OAuth2 server.

## Quick Start

1. Clone the repository:

   ```bash
   git clone https://github.com/quran/quran-oauth2-client-example.git
   cd quran-oauth2-client-example
   ```

2. Install dependencies:

   ```bash
   npm install
   ```

3. Create a `.env` file with the required environment variables:

   ```env
   PORT=3005
   BASE_PATH=http://localhost:3005
   CLIENT_ID=your_client_id
   CLIENT_SECRET=your_client_secret
   TOKEN_HOST=LOCAL_HYDRA (e.g. http://localhost:5444)
   SCOPES=openid profile email
   SESSION_SECRET=your_random_session_secret
   NODE_ENV=development
   ```

4. Start the server:

   ```bash
   npm start
   ```

5. Visit `http://localhost:3005` in your browser.

## Testing hosted UI locales

The signed-out page provides a locale dropdown. Its `ui_locales` value is sent to the authorization server with the OIDC authorization request.

- `http://localhost:3005/auth?ui_locales=ar`
- `http://localhost:3005/auth?ui_locales=fr-CA%20fr%20en`

The value is an ordered, space-separated locale preference. This example accepts well-formed unsupported tags too, so you can verify the authorization server's fallback behavior: it checks `Accept-Language`, then uses English.

Run the URL validation tests with:

```bash
npm test
```

For local browser checks, start the configured Hydra, auth backend on port 3001, and this client on port 3005, then run:

```bash
npx playwright install chromium
npm run test:e2e
```

The locale matrix runs without account credentials. To also complete login, consent, callback, and token exchange, provide a non-privileged local account only through the environment:

```bash
OAUTH_E2E_EMAIL='local-test@example.com' \
OAUTH_E2E_PASSWORD='local-test-password' \
npm run test:e2e
```

The browser suite disables screenshots, traces, and video so callback URLs and token-bearing pages are not retained as artifacts.

## Requiring a fresh sign-in

Check **Require sign-in (prompt=login)** on the signed-out page, or use **Sign in again** while signed in. Both send `prompt=login` to the authorization server, requiring authentication even when a Quran Foundation session already exists.

You can also open `http://localhost:3005/auth?prompt=login&ui_locales=en` directly. Omitting `prompt` keeps the normal SSO behavior. This example accepts only `login` or an omitted/empty prompt.

The browser suite checks normal session reuse followed by forced sign-in and a successful callback when `OAUTH_E2E_EMAIL` and `OAUTH_E2E_PASSWORD` are configured.

## Prerequisites

- Node.js 18.x or higher

## Documentation

For a detailed walkthrough, check out our [tutorial](https://api-docs.quran.foundation/docs/tutorials/oidc/example-integration).

## License

ISC
