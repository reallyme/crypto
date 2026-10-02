// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { spawn } from "node:child_process";
import { existsSync, mkdtempSync, rmSync } from "node:fs";
import { homedir, tmpdir } from "node:os";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { startStaticServer } from "./browser-test-server.mjs";
import { readDevToolsActivePort, readDevToolsListeningPort } from "./chrome-devtools-port.mjs";

const scriptDirectory = dirname(fileURLToPath(import.meta.url));
const packageDirectory = resolve(scriptDirectory, "..");
const browserResultPrefix = "__REALLYME_CRYPTO_BROWSER_WASM_RESULT__";
const browserTestTimeoutMs = 45_000;
const chromeStartupTimeoutMs = 30_000;
const chromeLaunchAttempts = 2;
const chromeStderrLimit = 4_096;
const chromeDiagnosticLimit = 1_024;

const chromeCandidates = [
  process.env.REALLYME_CRYPTO_CHROME_PATH,
  "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
  "/Applications/Chromium.app/Contents/MacOS/Chromium",
  "/usr/bin/google-chrome",
  "/usr/bin/google-chrome-stable",
  "/usr/bin/chromium",
  "/usr/bin/chromium-browser",
].filter((candidate) => typeof candidate === "string" && candidate.length > 0);

const fail = (message) => {
  process.stderr.write(`${message}\n`);
  process.exit(1);
};

const chromeExecutable = chromeCandidates.find((candidate) => existsSync(candidate));
if (chromeExecutable === undefined) {
  fail("Chrome or Chromium is required for the browser WASM release gate.");
}

if (typeof WebSocket !== "function") {
  fail("Node.js with a global WebSocket implementation is required.");
}

const browserTestPage = () => `<!doctype html>
<meta charset="utf-8">
<script type="module">
const resultPrefix = ${JSON.stringify(browserResultPrefix)};
const report = (result) => {
  console.log(resultPrefix + JSON.stringify(result));
};
const assert = (condition, code) => {
  if (!condition) {
    throw new Error(code);
  }
};
const toHex = (bytes) => Array.from(bytes, (byte) => byte.toString(16).padStart(2, "0")).join("");

try {
  const wasm = await import("/dist/wasm/reallyme_crypto_wasm.js");
  const { ReallyMeAead } = await import("/dist/aead.js");
  const { installReallyMeWasmProvider } = await import("/dist/wasmProvider.js");
  const { ReallyMeCryptoError } = await import("/dist/errors.js");
  await wasm.default();
  installReallyMeWasmProvider(wasm);

  // NIST SP 800-38D AES-GCM test case 2 crosses the package facade and the
  // generated WASM module under the browser's real fetch and module loader.
  const key = new Uint8Array(16);
  const nonce = new Uint8Array(12);
  const aad = new Uint8Array(0);
  const plaintext = new Uint8Array(16);
  const sealed = ReallyMeAead.seal("AES-128-GCM", key, nonce, aad, plaintext);
  assert(toHex(sealed) ===
    "0388dace60b6a392f328c2b971b2fe78ab6e47d42cec13bdf53a67b21257bddf",
    "aes-gcm-browser-vector");
  const opened = ReallyMeAead.open("AES-128-GCM", key, nonce, aad, sealed);
  assert(toHex(opened) === toHex(plaintext), "aes-gcm-browser-open");

  const tampered = sealed.slice();
  tampered[0] ^= 1;
  let rejected = false;
  try {
    ReallyMeAead.open("AES-128-GCM", key, nonce, aad, tampered);
  } catch (error) {
    rejected = error instanceof ReallyMeCryptoError &&
      error.code === "authentication-failed";
  }
  assert(rejected, "aes-gcm-browser-tamper-rejection");
  key.fill(0);
  nonce.fill(0);
  plaintext.fill(0);
  tampered.fill(0);
  sealed.fill(0);
  opened.fill(0);

  report({ ok: true });
} catch (error) {
  report({
    ok: false,
    message: error instanceof Error ? error.message : "browser wasm test failed",
  });
}
</script>`;

const fetchJson = async (url) => {
  const response = await fetch(url);
  if (!response.ok) {
    throw new Error("Chrome DevTools endpoint was not ready");
  }
  return response.json();
};

const waitForPageDebuggerUrl = async (port) => {
  const deadline = Date.now() + chromeStartupTimeoutMs;
  while (Date.now() < deadline) {
    try {
      const targets = await fetchJson(`http://127.0.0.1:${port}/json/list`);
      if (Array.isArray(targets)) {
        const page = targets.find(
          (target) =>
            target?.type === "page" &&
            typeof target.webSocketDebuggerUrl === "string",
        );
        if (page !== undefined) {
          return page.webSocketDebuggerUrl;
        }
      }
    } catch {
      await new Promise((resolveTimer) => setTimeout(resolveTimer, 100));
    }
  }
  throw new Error("Chrome page DevTools endpoint did not become ready");
};

class ChromeSession {
  constructor(socket) {
    this.nextId = 1;
    this.pending = new Map();
    this.handlers = new Map();
    this.socket = socket;
    this.socket.addEventListener("message", (event) => this.handleMessage(event));
  }

  command(method, params = {}) {
    const id = this.nextId;
    this.nextId += 1;
    const message = JSON.stringify({ id, method, params });
    return new Promise((resolveCommand, rejectCommand) => {
      this.pending.set(id, { resolveCommand, rejectCommand });
      this.socket.send(message);
    });
  }

  on(method, handler) {
    this.handlers.set(method, handler);
  }

  handleMessage(event) {
    const message = JSON.parse(event.data);
    if (typeof message.id === "number") {
      const pending = this.pending.get(message.id);
      if (pending !== undefined) {
        this.pending.delete(message.id);
        if (message.error !== undefined) {
          pending.rejectCommand(new Error(message.error.message));
        } else {
          pending.resolveCommand(message.result);
        }
      }
      return;
    }
    const handler = this.handlers.get(message.method);
    if (handler !== undefined) {
      handler(message.params);
    }
  }
}

const connectChrome = (url) =>
  new Promise((resolveSocket, rejectSocket) => {
    const socket = new WebSocket(url);
    socket.addEventListener("open", () => resolveSocket(socket), { once: true });
    socket.addEventListener(
      "error",
      () => rejectSocket(new Error("Chrome DevTools WebSocket failed")),
      { once: true },
    );
  });

const waitForChromeExit = (chrome) =>
  new Promise((resolveClose) => {
    if (chrome.exitCode !== null || chrome.signalCode !== null) {
      resolveClose();
      return;
    }
    const timeout = setTimeout(resolveClose, 2_000);
    chrome.once("close", () => {
      clearTimeout(timeout);
      resolveClose();
    });
  });

const runBrowserTest = async ({ serverPort, debuggerPort }) => {
  const debuggerUrl = await waitForPageDebuggerUrl(debuggerPort);
  const socket = await connectChrome(debuggerUrl);
  const session = new ChromeSession(socket);
  const failures = [];
  let browserResult;

  session.on("Runtime.consoleAPICalled", (event) => {
    const text = event.args
      .map((argument) => argument.value)
      .filter((value) => typeof value === "string")
      .join(" ");
    if (text.startsWith(browserResultPrefix)) {
      browserResult = JSON.parse(text.slice(browserResultPrefix.length));
    }
    if (event.type === "error") {
      failures.push(text);
    }
  });
  session.on("Runtime.exceptionThrown", (event) => {
    failures.push(event.exceptionDetails?.text ?? "browser exception");
  });

  await session.command("Runtime.enable");
  await session.command("Page.enable");
  await session.command("Page.navigate", {
    url: `http://127.0.0.1:${serverPort}/browser-wasm-test.html`,
  });

  const deadline = Date.now() + browserTestTimeoutMs;
  while (browserResult === undefined && Date.now() < deadline) {
    await new Promise((resolveTimer) => setTimeout(resolveTimer, 100));
  }
  socket.close();

  if (browserResult === undefined) {
    throw new Error("browser WASM test timed out");
  }
  if (browserResult.ok !== true) {
    throw new Error(browserResult.message ?? "browser WASM test failed");
  }
  if (failures.length > 0) {
    throw new Error("browser console reported an error");
  }
};

const sanitizedChromeDiagnostics = (stderr, userDataDir) => {
  const home = homedir();
  const redactedHome = home.length === 0 ? stderr : stderr.replaceAll(home, "<home>");
  return redactedHome
    .replaceAll(userDataDir, "<profile>")
    .replace(/ws:\/\/\S+/gu, "<devtools-endpoint>")
    .replace(/[^\x20-\x7e\n]/gu, " ")
    .slice(-chromeDiagnosticLimit)
    .trim() || "no Chrome startup diagnostics";
};

const run = async () => {
  const { server, port: serverPort } = await startStaticServer({ packageDirectory, testPage: browserTestPage });
  const startupFailures = [];
  try {
    for (let attempt = 0; attempt < chromeLaunchAttempts; attempt += 1) {
      // A fresh profile makes a retry independent of a stalled first launch.
      const userDataDir = mkdtempSync(resolve(tmpdir(), "reallyme-crypto-chrome-"));
      const chrome = spawn(chromeExecutable, [
        "--headless=new",
        "--disable-gpu",
        "--disable-dev-shm-usage",
        "--no-first-run",
        "--no-default-browser-check",
        "--no-sandbox",
        "--remote-debugging-port=0",
        `--user-data-dir=${userDataDir}`,
        "about:blank",
      ], {
        stdio: ["ignore", "ignore", "pipe"],
      });
      let chromeStderr = "";
      chrome.stderr.setEncoding("utf8");
      chrome.stderr.on("data", (chunk) => {
        // Retain only bounded startup output. The result is redacted before
        // reporting and never includes the test page's application data.
        chromeStderr = (chromeStderr + chunk).slice(-chromeStderrLimit);
      });
      let launchFailed = false;
      chrome.once("error", () => { launchFailed = true; });

      try {
        const deadline = Date.now() + chromeStartupTimeoutMs;
        const devToolsPortFile = resolve(userDataDir, "DevToolsActivePort");
        let debuggerPort;
        let startupReason = "timeout";
        while (debuggerPort === undefined && Date.now() < deadline) {
          // Chrome normally writes this file when DevTools is ready. Its
          // stderr announcement is a fallback for browser builds that omit it.
          debuggerPort = readDevToolsActivePort(devToolsPortFile) ??
            readDevToolsListeningPort(chromeStderr);
          if (debuggerPort !== undefined) {
            break;
          }
          if (launchFailed || chrome.exitCode !== null || chrome.signalCode !== null) {
            startupReason = "process exited";
            break;
          }
          await new Promise((resolveTimer) => setTimeout(resolveTimer, 100));
        }
        if (debuggerPort === undefined) {
          startupFailures.push(`${startupReason}: ${sanitizedChromeDiagnostics(chromeStderr, userDataDir)}`);
          continue;
        }
        await runBrowserTest({ serverPort, debuggerPort });
        return;
      } finally {
        chrome.kill();
        await waitForChromeExit(chrome);
        rmSync(userDataDir, {
          force: true,
          maxRetries: 5,
          recursive: true,
          retryDelay: 100,
        });
      }
    }
    throw new Error(`Chrome did not start DevTools: ${startupFailures.join(" | ")}`);
  } finally {
    server.close();
  }
};

try {
  await run();
  process.stdout.write("browser WASM release gate passed\n");
} catch (error) {
  fail(error instanceof Error ? error.message : "browser WASM release gate failed");
}
