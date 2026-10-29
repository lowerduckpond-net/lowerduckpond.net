"use strict";

const { spawn } = require("node:child_process");

// Exactly the existing private bootstrap crosses stdin, never logs/artifacts.
function main() {
  let input;
  try {
    input = JSON.stringify({
      bootstrap: JSON.parse(process.env.M3_11_CONNECT_BOOTSTRAP),
      manifest: JSON.parse(process.env.M3_11_PUBLIC_CA_MANIFEST),
      operation: process.env.M3_11_PUBLIC_CA_OPERATION,
    });
    if (Buffer.byteLength(input) > 256 * 1024) throw new Error();
  } catch {
    console.error("Diagnostic input is incomplete; no credential was created.");
    process.exitCode = 1;
    return;
  }
  const environment = { ...process.env };
  for (const name of ["M3_11_CONNECT_BOOTSTRAP", "M3_11_PUBLIC_CA_MANIFEST", "ACTIONS_RUNTIME_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"]) {
    delete environment[name];
    delete process.env[name];
  }
  const child = spawn(".venv/bin/python", ["-m", "scripts.m3_11_isolation_action"], {
    env: environment,
    stdio: ["pipe", "ignore", "ignore"],
  });
  child.stdin.on("error", () => {});
  child.stdin.end(input);
  input = undefined;
  for (const signal of ["SIGINT", "SIGTERM"]) process.on(signal, () => child.kill(signal));
  child.on("error", () => {
    console.error("Diagnostic operation could not start; obligations remain owned.");
    process.exitCode = 1;
  });
  child.on("close", (code) => {
    process.exitCode = code === 0 ? 0 : 1;
    console.log(code === 0 ? "Diagnostic operation completed; see its receipt." : "Diagnostic operation remains unresolved; preserve its receipts.");
  });
}

main();
