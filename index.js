const { AuthorizationCode } = require("simple-oauth2");
const path = require("path");
const app = require("express")();
const dotenv = require("dotenv");
dotenv.config();

const PORT = process.env.PORT;

const BASE_PATH = process.env.BASE_PATH;

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "pug");

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
      console.log(data);

      console.log("The resulting token: ", data.token);

      return res.status(200).json(data.token);
    } catch (error) {
      console.error("Access Token Error", error);
      return res.status(500).json("Authentication failed");
    }
  });

  app.get("/", (req, res) => {
    res.render("index");
  });
});
