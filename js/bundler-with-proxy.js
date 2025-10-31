#!/usr/bin/env node

/**
 * Runs Alto bundler on port 4338 and CORS proxy on port 4337
 * This allows browser-based applications to interact with Alto without CORS issues
 */

// eslint-disable-next-line @typescript-eslint/no-require-imports
const { spawn } = require("child_process");
// eslint-disable-next-line @typescript-eslint/no-require-imports
const path = require("path");
// eslint-disable-next-line @typescript-eslint/no-require-imports
const net = require("net");

const ALTO_CONFIG = path.join(__dirname, "..", "alto-with-proxy.json");
const PROXY_SCRIPT = path.join(__dirname, "bundler-proxy.js");

// ANSI color codes
const colors = {
  reset: "\x1b[0m",
  cyan: "\x1b[36m",
  green: "\x1b[32m",
  yellow: "\x1b[33m",
  red: "\x1b[31m",
};

function log(prefix, message, color = colors.reset) {
  console.log(`${color}[${prefix}]${colors.reset} ${message}`);
}

/**
 * Check if a port is listening
 * @param {number} port - The port to check
 * @param {number} maxAttempts - Maximum number of attempts
 * @param {number} delayMs - Delay between attempts in milliseconds
 * @returns {Promise<boolean>} - True if port is listening, false otherwise
 */
async function waitForPort(port, maxAttempts = 30, delayMs = 1000) {
  for (let attempt = 1; attempt <= maxAttempts; attempt++) {
    const isListening = await new Promise((resolve) => {
      const client = new net.Socket();

      client.once("connect", () => {
        client.destroy();
        resolve(true);
      });

      client.once("error", () => {
        client.destroy();
        resolve(false);
      });

      client.connect(port, "localhost");
    });

    if (isListening) {
      return true;
    }

    if (attempt < maxAttempts) {
      await new Promise((resolve) => setTimeout(resolve, delayMs));
    }
  }

  return false;
}

let proxy;

// Start Alto bundler
log("SETUP", "Starting Alto bundler on port 4338...", colors.cyan);
const alto = spawn("alto", ["--config", ALTO_CONFIG], {
  stdio: "inherit",
  shell: true,
});

alto.on("error", (error) => {
  log("ALTO", `Failed to start: ${error.message}`, colors.red);
  process.exit(1);
});

alto.on("exit", (code) => {
  log("ALTO", `Exited with code ${code}`, colors.yellow);
  // Kill proxy if alto exits
  if (proxy) {
    proxy.kill();
  }
  process.exit(code);
});

// Handle cleanup on exit - register handlers early to avoid race condition
process.on("SIGINT", () => {
  log("SETUP", "Shutting down...", colors.yellow);
  alto.kill();
  if (proxy) {
    proxy.kill();
  }
  process.exit(0);
});

process.on("SIGTERM", () => {
  log("SETUP", "Shutting down...", colors.yellow);
  alto.kill();
  if (proxy) {
    proxy.kill();
  }
  process.exit(0);
});

// Wait for Alto to be ready before starting proxy
(async () => {
  log("SETUP", "Waiting for Alto bundler to be ready on port 4338...", colors.cyan);

  const altoReady = await waitForPort(4338);
  if (!altoReady) {
    log("ALTO", "Failed to start - port 4338 not listening after 30 seconds", colors.red);
    alto.kill();
    process.exit(1);
  }

  log("ALTO", "Ready and listening on port 4338", colors.green);
  log("SETUP", "Starting CORS proxy on port 4337...", colors.cyan);

  proxy = spawn("node", [PROXY_SCRIPT], {
    stdio: "inherit",
    shell: true,
  });

  proxy.on("error", (error) => {
    log("PROXY", `Failed to start: ${error.message}`, colors.red);
    alto.kill();
    process.exit(1);
  });

  proxy.on("exit", (code) => {
    log("PROXY", `Exited with code ${code}`, colors.yellow);
    // Kill alto if proxy exits
    alto.kill();
    process.exit(code);
  });

  // Wait for proxy to be ready
  log("SETUP", "Waiting for CORS proxy to be ready on port 4337...", colors.cyan);
  const proxyReady = await waitForPort(4337);
  if (!proxyReady) {
    log("PROXY", "Failed to start - port 4337 not listening after 30 seconds", colors.red);
    alto.kill();
    proxy.kill();
    process.exit(1);
  }

  log("PROXY", "Ready and listening on port 4337", colors.green);
  log("SETUP", "Both services started successfully!", colors.green);
  log("SETUP", "Alto bundler: http://localhost:4338", colors.green);
  log("SETUP", "CORS proxy: http://localhost:4337", colors.green);
})();
