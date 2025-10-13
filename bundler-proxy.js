#!/usr/bin/env node

/**
 * Simple CORS proxy for Alto bundler
 * Listens on port 4337 and forwards requests to Alto on port 4338
 */

// eslint-disable-next-line @typescript-eslint/no-require-imports
const http = require("http");

const PROXY_PORT = 4337;
const ALTO_PORT = 4338;
const ALTO_HOST = "localhost";

const server = http.createServer((req, res) => {
  // Set CORS headers
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type, Authorization");
  res.setHeader("Access-Control-Max-Age", "86400"); // 24 hours

  // Handle preflight requests
  if (req.method === "OPTIONS") {
    res.writeHead(200);
    res.end();
    return;
  }

  // Collect request body
  let body = "";
  req.on("data", (chunk) => {
    body += chunk.toString();
  });

  req.on("end", () => {
    // Forward request to Alto
    const options = {
      hostname: ALTO_HOST,
      port: ALTO_PORT,
      path: req.url,
      method: req.method,
      headers: {
        "Content-Type": "application/json",
        "Content-Length": Buffer.byteLength(body),
      },
    };

    const proxyReq = http.request(options, (proxyRes) => {
      // Forward status code
      res.writeHead(proxyRes.statusCode, proxyRes.headers);

      // Forward response body
      proxyRes.pipe(res);
    });

    proxyReq.on("error", (error) => {
      console.error("Proxy error:", error);
      res.writeHead(502);
      res.end(JSON.stringify({ error: "Bad Gateway", message: error.message }));
    });

    // Send request body to Alto
    if (body) {
      proxyReq.write(body);
    }
    proxyReq.end();
  });
});

server.listen(PROXY_PORT, () => {
  console.log(`CORS proxy listening on port ${PROXY_PORT}`);

  console.log(`Forwarding requests to Alto at ${ALTO_HOST}:${ALTO_PORT}`);

  console.log(`CORS enabled for all origins (*)`);
});

server.on("error", (error) => {
  if (error.code === "EADDRINUSE") {
    console.error(`Port ${PROXY_PORT} is already in use. Please stop the other service first.`);
  } else {
    console.error("Server error:", error);
  }
  process.exit(1);
});
