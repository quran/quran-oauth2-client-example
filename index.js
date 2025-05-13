const { AuthorizationCode } = require("simple-oauth2");
const path = require("path");
const app = require("express")();
const dotenv = require("dotenv");
const session = require("express-session");
const jwt = require("jsonwebtoken");
dotenv.config();

const PORT = process.env.PORT;
const BASE_PATH = process.env.BASE_PATH;

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "pug");

// Add session middleware
app.use(session({
  secret: process.env.SESSION_SECRET || 'your-secret-key',
  resave: false,
  saveUninitialized: true,
  cookie: { secure: process.env.NODE_ENV === 'production' }
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
    const options = {
      code,
      redirect_uri: callbackUrl,
    };

    try {
      const data = await client.getToken(options);
      // Store the token in session
      req.session.token = data.token;
      return res.redirect("/");
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
    let userDetails = null;
    if (req.session.token) {
      try {
        // Decode the ID token to get user information
        const decodedToken = jwt.decode(req.session.token.id_token);
        userDetails = {
          name: `${decodedToken.first_name} ${decodedToken.last_name}`,
          email: decodedToken.email,
          sub: decodedToken.sub,
          auth_time: new Date(decodedToken.auth_time * 1000).toLocaleString(),
          issued_at: new Date(decodedToken.iat * 1000).toLocaleString(),
          expires_at: new Date(decodedToken.exp * 1000).toLocaleString(),
          session_id: decodedToken.sid,
          issuer: decodedToken.iss,
          audience: decodedToken.aud.join(', '),
          jti: decodedToken.jti
        };
      } catch (error) {
        console.error("Error decoding token:", error);
      }
    }
    res.render("index", {
      isLoggedIn: !!req.session.token,
      userDetails,
      token: !req.session.token ? null : JSON.stringify(req.session.token)
    });
  });
});
