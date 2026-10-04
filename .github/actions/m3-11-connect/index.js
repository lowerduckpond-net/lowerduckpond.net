"use strict";

const { spawn } = require("node:child_process");

// A JavaScript action receives the artifact runtime token. Ordinary shell steps
// do not. Retain it only in this private cleanup process and its pinned uploader.
function main() {
  let input;
  try {
    input = JSON.stringify({
      bootstrap: JSON.parse(process.env.M3_11_CONNECT_BOOTSTRAP),
      selection: JSON.parse(process.env.M3_11_CONNECT_CONFIGURATION),
      operation: process.env.M3_11_CONNECT_OPERATION,
      run_sha256: process.env.M3_11_CONNECT_RUN_SHA256 || "",
    });
    if (Buffer.byteLength(input) > 128 * 1024) throw new Error();
  } catch {
    console.error("Independent cleanup input is incomplete; no credential was created.");
    process.exitCode = 1;
    return;
  }
  const environment = { ...process.env, M3_11_ACTION_NODE: process.execPath };
  for (const name of ["M3_11_CONNECT_BOOTSTRAP", "M3_11_CONNECT_CONFIGURATION"]) {
    delete environment[name];
    delete process.env[name];
  }
  const child = spawn(".venv/bin/python", ["-m", "scripts.m3_11_unattended.connect_action"], {
    env: environment,
    stdio: ["pipe", "ignore", "ignore"],
  });
  child.stdin.on("error", () => {}); // A failed receiver must not echo its private input.
  child.stdin.end(input);
  input = undefined;
  for (const signal of ["SIGINT", "SIGTERM"]) {
    process.on(signal, () => child.kill(signal));
  }
  child.on("error", () => {
    console.error("Independent cleanup could not start; obligations remain unresolved.");
    process.exitCode = 1;
  });
  child.on("close", (code) => {
    process.exitCode = code === 0 ? 0 : 1;
    console.log(code === 0
      ? "Independent cleanup completed; see the sanitized receipt."
      : "Independent cleanup remains unresolved; retain obligations and retry.");
  });
}

main();
