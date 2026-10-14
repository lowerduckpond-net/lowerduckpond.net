"use strict";

const { spawn } = require("node:child_process");
const path = require("node:path");

// A JavaScript action receives the artifact runtime token. Ordinary shell steps
// do not. Retain it only in this private cleanup process and its pinned uploader.
function main() {
  let input;
  let root;
  let arguments_;
  try {
    root = process.env.M3_11_LEGACY_ROOT;
    const vault = process.env.M3_11_BRIDGE_VAULT;
    const migration = process.env.M3_11_BRIDGE_MIGRATION;
    if (typeof root !== "string" || !path.isAbsolute(root)
        || !/^[a-z0-9]{26}$/.test(vault || "")
        || !/^[a-f0-9]{64}$/.test(migration || "")
        || process.env.M3_11_HELPER_REVISION !== "0b5b198bf06443e61f01b1f7259fea827f79fc23"
        || process.env.M3_11_CONNECT_OPERATION !== "reconcile") throw new Error();
    arguments_ = [path.resolve(__dirname, "../../../scripts/m3_11_unattended/legacy_import_reader.py"),
      "--legacy-root", root, "--journal-vault", vault, "--migration-sha256", migration,
      "--actor", "github", "--receipt", path.join(process.env.RUNNER_TEMP, "m3-11-import-reader/observation.json")];
    input = JSON.stringify({
      bootstrap: JSON.parse(process.env.M3_11_CONNECT_BOOTSTRAP),
      selection: JSON.parse(process.env.M3_11_CONNECT_CONFIGURATION),
      operation: process.env.M3_11_CONNECT_OPERATION,
      run_sha256: process.env.M3_11_CONNECT_RUN_SHA256 || "",
      dispatch_id: process.env.M3_11_CONNECT_DISPATCH_ID || "",
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
  const child = spawn(path.join(root, ".venv/bin/python"), arguments_, {
    cwd: root,
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
