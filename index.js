const { AuthorizationCode } = require('simple-oauth2')
const app = require('express')()
const port = 3000

const BASE_PATH = 'https://quran-oauth2-example.fly.dev'
const createApplication = (cb) => {
  const callbackUrl = BASE_PATH + '/callback'
  app.listen(port, (err) => {
    if (err) return console.error(err)
    console.log(`Express server listening at ${BASE_PATH}`)
    return cb({
      app,
      callbackUrl,
    })
  })
}

createApplication(({ app, callbackUrl }) => {
  const client = new AuthorizationCode({
    client: {
      id: 'quran-demo',
      secret: 'secret',
    },
    auth: {
      tokenHost: 'https://oauth2.quran.com',
      tokenPath: '/oauth2/token',
      authorizePath: '/oauth2/auth',
    },
  })

  // Authorization uri definition
  const authorizationUri = client.authorizeURL({
    redirect_uri: callbackUrl,
    scope: 'openid offline collection.read',
    state: 'veimvfgqexjicockrwsgcb333o3a',
  })

  // Initial page redirecting to Github
  app.get('/auth', (req, res) => {
    console.log(authorizationUri)
    res.redirect(authorizationUri)
  })

  // Callback service parsing the authorization token and asking for the access token
  app.get('/callback', async (req, res) => {
    const { code } = req.query
    console.log(code, 'this is the code')
    const options = {
      code,
      redirect_uri: callbackUrl,
    }

    try {
      const data = await client.getToken(options)
      console.log(data)

      console.log('The resulting token: ', data.token)

      return res.status(200).json(data.token)
    } catch (error) {
      console.error('Access Token Error', error)
      return res.status(500).json('Authentication failed')
    }
  })

  app.get('/', (req, res) => {
    res.send('Hello<br><a href="/auth">Continue with Quran.com</a>')
  })
})
