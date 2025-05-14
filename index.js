const { AuthorizationCode } = require("simple-oauth2");
const path = require("path");
const app = require("express")();
const dotenv = require("dotenv");
const session = require("express-session");
const jwt = require("jsonwebtoken");
dotenv.config();

const PORT = process.env.PORT;
const BASE_PATH = process.env.BASE_PATH;
const isProduction = process.env.NODE_ENV === 'production';

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "pug");

// Configure trust proxy if in production
if (isProduction) {
  app.set('trust proxy', 1);
}

// Add session middleware
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: false,
  cookie: {
    secure: isProduction,
    sameSite: 'lax',
    httpOnly: true,
    maxAge: 24 * 60 * 60 * 1000, // 24 hours
  },
  proxy: true // Always enable proxy for Fly.io deployments
}));

const createApplication = (cb) => {
  const callbackUrl = BASE_PATH + "/callback";
  app.listen(PORT, (err) => {
    if (err) return console.error(err);
    console.log(`Express server listening at ${BASE_PATH}`);
    return cb({
      app,
      callbackUrl,
    });
  });
};

createApplication(({ app, callbackUrl }) => {
  const client = new AuthorizationCode({
    client: {
      id: process.env.CLIENT_ID,
      secret: process.env.CLIENT_SECRET,
    },
    auth: {
      tokenHost: process.env.TOKEN_HOST,
      tokenPath: "/oauth2/token",
      authorizePath: "/oauth2/auth",
    },
  });

  // Authorization uri definition
  const authorizationUri = client.authorizeURL({
    redirect_uri: callbackUrl,
    scope: process.env.SCOPES,
    state: "veimvfgqexjicockrwsgcb333o3a",
  });

  // Initial page redirecting to Quran.com
  app.get("/auth", (req, res) => {
    console.log(authorizationUri);
    res.redirect(authorizationUri);
  });

  // Callback service parsing the authorization token and asking for the access token
  app.get("/callback", async (req, res) => {
    const { code } = req.query;
    console.log(code, "this is the code");
    console.log("Session before token storage:", req.session.id);
    const options = {
      code,
      redirect_uri: callbackUrl,
    };

    try {
      const data = await client.getToken(options);
      // Log the token data structure
      console.log("Token data received:", JSON.stringify({
        token_type: data.token.token_type,
        access_token: data.token.access_token ? "exists" : "missing",
        id_token: data.token.id_token ? "exists" : "missing",
        refresh_token: data.token.refresh_token ? "exists" : "missing",
        expires_at: data.token.expires_at
      }, null, 2));

      // Store the token in session
      req.session.token = data.token;
      console.log("Token stored in session:", req.session.id, "Session exists:", !!req.session);

      // Save the session explicitly and wait for it to complete
      req.session.save((err) => {
        if (err) {
          console.error("Error saving session:", err);
          return res.status(500).json("Session storage failed");
        }

        console.log("Session successfully saved");
        return res.redirect("/");
      });
    } catch (error) {
      console.error("Access Token Error", error);
      return res.status(500).json("Authentication failed");
    }
  });

  // Logout endpoint
  app.get("/logout", (req, res) => {
    // Clear the local session first
    req.session.destroy((err) => {
      if (err) {
        console.error("Error destroying session:", err);
      }

      // Redirect to the OAuth2 provider's logout endpoint
      const logoutUrl = `${process.env.TOKEN_HOST}/oauth2/sessions/logout?client_id=${process.env.CLIENT_ID}&redirect_uri=${encodeURIComponent(BASE_PATH)}`;
      res.redirect(logoutUrl);
    });
  });

  app.get("/", (req, res) => {
    console.log("Root route - Session exists:", !!req.session, "Session ID:", req.session.id, "Token exists:", !!req.session.token);
    let userDetails = null;

    // Check if token exists and is a proper object
    if (req.session.token && typeof req.session.token === 'object') {
      try {
        // Add debug information about token structure
        console.log("Token structure:", JSON.stringify({
          token_type: req.session.token.token_type || "missing",
          access_token: req.session.token.access_token ? "exists" : "missing",
          id_token: req.session.token.id_token ? "exists" : "missing",
          refresh_token: req.session.token.refresh_token ? "exists" : "missing",
          expires_at: req.session.token.expires_at
        }, null, 2));

        // Check if id_token exists before decoding
        if (!req.session.token.id_token) {
          console.error("id_token is missing in the session token");
          res.render("index", {
            isLoggedIn: true,
            userDetails: { name: "Unknown (Token incomplete)", email: "N/A" },
            token: JSON.stringify(req.session.token)
          });
          return;
        }

        // Decode the ID token to get user information
        const decodedToken = jwt.decode(req.session.token.id_token);
        console.log("Decoded token structure:", JSON.stringify(decodedToken, null, 2));

        if (!decodedToken) {
          console.error("Decoded token is null");
        } else {
          // Safely extract user details with fallbacks
          userDetails = {
            name: decodedToken.name || `${decodedToken.first_name || ''} ${decodedToken.last_name || ''}`.trim() || 'Unknown',
            email: decodedToken.email || 'No email provided',
            sub: decodedToken.sub || 'Unknown',
            auth_time: decodedToken.auth_time ? new Date(decodedToken.auth_time * 1000).toLocaleString() : 'Unknown',
            issued_at: decodedToken.iat ? new Date(decodedToken.iat * 1000).toLocaleString() : 'Unknown',
            expires_at: decodedToken.exp ? new Date(decodedToken.exp * 1000).toLocaleString() : 'Unknown',
            session_id: decodedToken.sid || 'Unknown',
            issuer: decodedToken.iss || 'Unknown',
            audience: Array.isArray(decodedToken.aud) ? decodedToken.aud.join(', ') : (decodedToken.aud || 'Unknown'),
            jti: decodedToken.jti || 'Unknown'
          };
        }
      } catch (error) {
        console.error("Error decoding token:", error);
        console.error("Token that failed to decode:", req.session.token.id_token);
      }
    }
    res.render("index", {
      isLoggedIn: !!req.session.token,
      userDetails,
      token: !req.session.token ? null : JSON.stringify(req.session.token)
    });
  });
});
