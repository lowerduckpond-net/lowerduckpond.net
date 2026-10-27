"use strict";

const { spawn } = require("node:child_process");

// Keep the versioned private bundle on stdin and suppress raw child output.
function main() {
  let input;
  try {
    input = JSON.stringify({
      bootstrap: JSON.parse(process.env.M3_11_CONNECT_BOOTSTRAP),
      operation: process.env.M3_11_CONNECT_OPERATION,
      ...(process.env.M3_11_CONNECT_PROFILE
        ? { profile: JSON.parse(process.env.M3_11_CONNECT_PROFILE) } : {}),
    });
    if (Buffer.byteLength(input) > 128 * 1024) throw new Error();
  } catch {
    console.error("Independent cleanup input is incomplete; no credential was created.");
    process.exitCode = 1;
    return;
  }
  const environment = { ...process.env };
  for (const name of ["M3_11_CONNECT_BOOTSTRAP", "M3_11_CONNECT_PROFILE", "ACTIONS_RUNTIME_TOKEN", "GH_TOKEN", "GITHUB_TOKEN"]) {
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
