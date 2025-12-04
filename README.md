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
   PORT=3000
   BASE_PATH=http://localhost:3000
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

5. Visit `http://localhost:3000` in your browser.

## Prerequisites

- Node.js 18.x or higher

## Documentation

For a detailed walkthrough, check out our [tutorial](https://api-docs.quran.foundation/docs/tutorials/oidc/example-integration).

## License

ISC
