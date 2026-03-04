require("dotenv").config();

const http = require("http");
const { URL } = require("url");
const readline = require("readline");
const { google } = require("googleapis");

const CLIENT_ID = process.env.GOOGLE_OAUTH_CLIENT_ID || "";
const CLIENT_SECRET = process.env.GOOGLE_OAUTH_CLIENT_SECRET || "";
const REDIRECT_URI = process.env.GOOGLE_OAUTH_REDIRECT_URI || "http://localhost:53682/oauth2callback";
const SCOPE = process.env.GOOGLE_OAUTH_SCOPE || "https://www.googleapis.com/auth/drive";

if (!CLIENT_ID || !CLIENT_SECRET) {
  console.error(
    "Missing OAuth client credentials. Set GOOGLE_OAUTH_CLIENT_ID and GOOGLE_OAUTH_CLIENT_SECRET in backend/.env"
  );
  process.exit(1);
}

const oauth2Client = new google.auth.OAuth2({
  clientId: CLIENT_ID,
  clientSecret: CLIENT_SECRET,
  redirectUri: REDIRECT_URI,
});

const authUrl = oauth2Client.generateAuthUrl({
  access_type: "offline",
  prompt: "consent",
  scope: [SCOPE],
});

console.log("\nOpen this URL in your browser and allow access:\n");
console.log(authUrl);
console.log("\nRedirect URI:", REDIRECT_URI);

const MANUAL_MODE = process.argv.includes("--manual");
if (MANUAL_MODE) {
  console.log("\nManual mode is ON. After Google redirects, copy full redirected URL and paste below.\n");
}

const redirect = new URL(REDIRECT_URI);
const callbackPath = redirect.pathname;
const callbackPort = Number(redirect.port || 80);

async function printRefreshTokenFromCode(code) {
  const { tokens } = await oauth2Client.getToken(code);
  const refreshToken = tokens.refresh_token || "";

  if (!refreshToken) {
    console.error("No refresh token received. Revoke app access and retry with prompt=consent.");
    process.exit(1);
  }

  console.log("\nGOOGLE_OAUTH_REFRESH_TOKEN=");
  console.log(refreshToken);
  console.log("\nAdd this value in backend/.env and restart backend.\n");
  process.exit(0);
}

if (MANUAL_MODE) {
  const rl = readline.createInterface({ input: process.stdin, output: process.stdout });
  rl.question("Paste redirected URL here: ", async (input) => {
    try {
      const pasted = new URL(String(input || "").trim());
      const code = pasted.searchParams.get("code");
      const error = pasted.searchParams.get("error");

      if (error) {
        console.error("Authorization failed:", error);
        process.exit(1);
      }

      if (!code) {
        console.error("No authorization code found in pasted URL.");
        process.exit(1);
      }

      await printRefreshTokenFromCode(code);
    } catch (err) {
      console.error("Invalid URL pasted:", err.message);
      process.exit(1);
    } finally {
      rl.close();
    }
  });
  return;
}

console.log("\nWaiting for Google callback on:", REDIRECT_URI, "\n");

const server = http.createServer(async (req, res) => {
  try {
    const reqUrl = new URL(req.url, `http://${req.headers.host}`);
    if (reqUrl.pathname !== callbackPath) {
      res.writeHead(404, { "Content-Type": "text/plain" });
      res.end("Not found");
      return;
    }

    const code = reqUrl.searchParams.get("code");
    const error = reqUrl.searchParams.get("error");

    if (error) {
      res.writeHead(400, { "Content-Type": "text/plain" });
      res.end(`Authorization failed: ${error}`);
      console.error("Authorization failed:", error);
      server.close(() => process.exit(1));
      return;
    }

    if (!code) {
      res.writeHead(400, { "Content-Type": "text/plain" });
      res.end("No authorization code found");
      console.error("No authorization code found in callback");
      server.close(() => process.exit(1));
      return;
    }

    res.writeHead(200, { "Content-Type": "text/plain" });
    res.end("OAuth success. You can close this tab.");
    await printRefreshTokenFromCode(code);
  } catch (err) {
    res.writeHead(500, { "Content-Type": "text/plain" });
    res.end("Internal error during OAuth callback");
    console.error("OAuth callback error:", err.message);
    server.close(() => process.exit(1));
  }
});

server.listen(callbackPort, () => {
  // no-op
});
