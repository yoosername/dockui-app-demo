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
const HTTP_PORT = process.env.HTTP_PORT ? process.env.HTTP_PORT : 3333;
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

// Mount the static HTML for the Demo
app.use(serve(__dirname + "/static"));
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
