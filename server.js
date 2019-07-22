const fs = require("fs");
const Koa = require("koa");
const Router = require("koa-router");
const https = require("https");
const jwt = require("jsonwebtoken");

// KOA Specific General Middleware
const serve = require("koa-static");
const helmet = require("koa-helmet");
const bodyParser = require("koa-bodyparser");
const multer = require("koa-multer");

// Defaults
const HTTP_PORT = process.env.HTTP_PORT ? process.env.HTTP_PORT : 3000;
const DEFAULT_HTTP_SCHEME = "http";
const HTTP_SCHEME = process.env.HTTP_SCHEME
  ? process.env.HTTP_SCHEME
  : DEFAULT_HTTP_SCHEME;
const HTTP_SSL_CERT = process.env.HTTP_SSL_CERT;
const HTTP_SSL_KEY = process.env.HTTP_SSL_KEY;

const app = new Koa();
const router = new Router();
let server = null;

/**
 * Global error handler
 */
app.use(async (ctx, next) => {
  try {
    await next();
  } catch (err) {
    const status =
      typeof err === "number" ? err : err.status ? err.status : 500;
    const msg =
      err instanceof Error || typeof err === "object"
        ? err.message
        : typeof err === "string"
        ? err.toString()
        : err;
    ctx.status = status;
    ctx.body = { error: { status: status, message: msg } };
    console.error("error (status=%s) (message=%s)", status, msg);
    if (status === 500) {
      console.error("stack trace: %o", err);
    }
  }
});

/*
 * Global Debug Logging
 */
app.use(async (ctx, next) => {
  console.debug("[", ctx.method, "] ", ctx.originalUrl);
  await next();
});

/**
 * Apply common best practice security headers using Helmet
 */
app.use(helmet());
console.debug("Configured common security headers");

/**
 * Add Rate limiting to prevent simple DOS issues
 */
//app.use(ratelimit());

/**
 * Add a body parser for JSON based Api
 */
app.use(bodyParser());

/**
 * Simple Health Endpoint
 */
router.get("/health", async ctx => {
  ctx.body = { status: "running" };
});

/**
 * -----------------------------------------------------------------------
 * Built in DEMO App with JWT based auth via authenticationProvider Module
 * -----------------------------------------------------------------------
 */
// Add a Multipart body parser for the login page
app.use(
  multer().fields([
    { name: "username", maxCount: 1 },
    { name: "password", maxCount: 1 }
  ])
);

// Mount the static HTML for the Demo
app.use(serve(__dirname + "/static"));

// Add some Hardcoded Demo Users
const validDemoUsers = {
  user: {
    password: "user",
    token: null,
    roles: ["DASHBOARD_VIEW"]
  },
  admin: {
    password: "admin",
    token: null,
    roles: ["DASHBOARD_VIEW", "DASHBOARD_ADMIN"]
  }
};

// Provide the AuthenticationProvider endpoint
router.post("/identity_check", async ctx => {
  // See if there is a JWT Token with the admin user in it
  // If no token redirect
  await new Promise((resolve, reject) => {
    const authToken = ctx.request.body.cookies["X-Demo-Auth"];
    jwt.verify(authToken, "thisIsNotAVeryGoodSecret", (err, authorizedData) => {
      if (err) {
        // If no token or is token but error here, send 301 to log in
        ctx.status = 301;
        ctx.body = {
          status: 301,
          url: "/app/dashboard/login",
          message: "Login Required"
        };
        console.debug(
          "No Token or Token Verify failure, send redirect to login page"
        );
        return resolve();
      } else {
        // If token is successfully verified, we can send the autorized data
        ctx.status = 200;
        ctx.body = {
          status: 200,
          message: "Success",
          headers: { Authorization: authToken },
          principle: authorizedData.username
        };
        console.debug("JWT Verified ok, user is (%s)", authorizedData);
        return resolve();
      }
    });
  });
});

// Provide the Backing Controller for the Login form
router.post("login.action", async ctx => {
  // get login details
  const { username, password } = ctx.request.body;
  console.debug("User logged in as %s:%s", username, password);
  // check they match our demo users
  if (
    (username === "user" && password === "user") ||
    (username === "admin" && password === "admin")
  ) {
    // User logged in with a valid user
    console.debug("Signing a freshly minted JWT Token");
    let self = this;
    try {
      await new Promise((resolve, reject) => {
        jwt.sign(
          { username },
          "thisIsNotAVeryGoodSecret",
          { expiresIn: "1h" },
          (err, token) => {
            if (err) {
              console.error("Error Signing JWT, error = %s", err);
              return reject(err);
            }
            console.debug("Setting cookies");
            validDemoUsers[username].token = token;
            let futureDate = new Date();
            ctx.cookies.set(
              encodeURIComponent("X-Demo-Auth"),
              encodeURIComponent(token),
              {
                maxAge: 604800,
                expires: futureDate.setDate(futureDate.getDate() + 100),
                httpOnly: false,
                secure: false
              }
            );
            console.debug("Cookies: %o", ctx.headers.cookie);
            console.debug(
              "Token created as: %s",
              validDemoUsers[username].token
            );
            resolve();
          }
        );
      });
    } catch (e) {
      return console.error("Error Signing JWT, error = %s", e);
    }
  }
  // send a redirect to the location in the then query param
  console.debug("Redirecting to %s", ctx.query.then);
  ctx.redirect(ctx.query.then);
});

// Provide the endpoint for the AuthorizationProvider
router.post("/permission_check", async ctx => {
  // Check the passed IDAM info and check the requested principle
  const { principle, target, policy, action } = ctx.request.body;
  const user = validDemoUsers[principle];
  const userRoles = user ? user.roles : [];
  // Are there any types of Role?
  if (policy && policy.length) {
    // if so for each one
    for (var i = 0; i < policy.length; i++) {
      // Check the type is a role one that we are interested in
      if (policy[i].type.toLowerCase() === "role") {
        // and if it is check if the current action is specified
        if (policy[i].action.includes(action)) {
          // and if it is check the user has the associated Role - if not send 403 - Forbidden
          if (userRoles.includes(policy[i].role)) {
            // nice  - user has the role so continue
            console.debug(
              "User (%s) has required Role (%s) to access restricted target (%s)",
              user,
              policy[i].role,
              target
            );
          } else {
            return ctx.throw(
              403,
              "User (" +
                principle +
                ") doesnt have sufficient role (" +
                policy[i].role +
                ") to access this resource (" +
                target +
                ")"
            );
          }
        }
      }
    }
  }
  ctx.status = 200;
  ctx.body = { user: user };
});

// Add a few example users
router.get("/rest/api/1.0/users", async ctx => {
  ctx.body = [
    { name: "dave", skill: "winning" },
    { name: "bob", skill: "losing" },
    { name: "ruby", skill: "standing" },
    { name: "tyrone", skill: "staring" }
  ];
});
console.debug("Configured DEMO App Routes");
/**
 * -----------------------------------------------------------------------
 * End of DEMO - TODO: Move this to seperate project
 * -----------------------------------------------------------------------
 */

app.use(router.routes());
app.use(router.allowedMethods());

/**
 * At this point all routes have been exhausted, so must be a 404
 **/
app.use(ctx => {
  ctx.throw(404); // throw 404s after all routers try to route this request
});

/**
 * Start the server
 **/
(async () => {
  try {
    if (HTTP_SCHEME == "https") {
      const cert = HTTP_SSL_CERT;
      const key = HTTP_SSL_KEY;
      if (!cert || !key) {
        throw new Error(
          "Cannot start webservice on https, Missing cert and key"
        );
      }
      server = await https
        .createServer(
          {
            cert: fs.readFileSync(cert),
            key: fs.readFileSync(key),
            ciphers: [
              "ECDHE-RSA-AES128-SHA256",
              "DHE-RSA-AES128-SHA256",
              "AES128-GCM-SHA256",
              "RC4",
              "HIGH",
              "!MD5",
              "!aNULL"
            ].join(":")
          },
          app.callback()
        )
        .listen(HTTP_PORT);
    } else {
      server = await app.listen(HTTP_PORT);
    }
    // Add error event handler
    server.on("error", err => {
      console.error("Web Service encountered an error: ", err);
    });

    console.info(
      `Web Service has started at ${HTTP_SCHEME}://localhost:${HTTP_PORT}/`
    );
  } catch (e) {
    console.error("Web Service didnt start: ", e);
  }
})();
