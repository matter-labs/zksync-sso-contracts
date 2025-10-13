#!/usr/bin/env node

/**
 * Runs Alto bundler on port 4338 and CORS proxy on port 4337
 * This allows browser-based applications to interact with Alto without CORS issues
 */

// eslint-disable-next-line @typescript-eslint/no-require-imports
const { spawn } = require("child_process");
// eslint-disable-next-line @typescript-eslint/no-require-imports
const path = require("path");

const ALTO_CONFIG = path.join(__dirname, "alto-with-proxy.json");
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

// Wait a bit for Alto to start before starting proxy
setTimeout(() => {
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

  // Handle cleanup on exit
  process.on("SIGINT", () => {
    log("SETUP", "Shutting down...", colors.yellow);
    alto.kill();
    proxy.kill();
    process.exit(0);
  });

  process.on("SIGTERM", () => {
    log("SETUP", "Shutting down...", colors.yellow);
    alto.kill();
    proxy.kill();
    process.exit(0);
  });

  log("SETUP", "Both services started successfully!", colors.green);
  log("SETUP", "Alto bundler: http://localhost:4338", colors.green);
  log("SETUP", "CORS proxy: http://localhost:4337", colors.green);
}, 2000);
