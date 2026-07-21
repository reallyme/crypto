#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { accessSync, constants } from "node:fs";
import { delimiter, resolve } from "node:path";
import { spawnSync } from "node:child_process";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));
const wasmBrowserCrates = [
  "crates/aes256-gcm",
  "crates/ed25519",
  "crates/secp256k1",
  "crates/x25519",
];
const allowedBrowsers = new Set(["chrome", "firefox", "all"]);

const options = {
  browser: "chrome",
  dryRun: false,
};

for (const arg of process.argv.slice(2)) {
  if (arg === "--dry-run") {
    options.dryRun = true;
  } else if (arg.startsWith("--browser=")) {
    options.browser = arg.slice("--browser=".length);
  } else {
    fail(`unknown argument: ${arg}`);
  }
}

if (!allowedBrowsers.has(options.browser)) {
  fail("--browser must be chrome, firefox, or all");
}

const selectedBrowsers =
  options.browser === "all" ? ["chrome", "firefox"] : [options.browser];

for (const browser of selectedBrowsers) {
  const driver = browser === "chrome" ? requireChromeDriver() : requireGeckoDriver();
  for (const cratePath of wasmBrowserCrates) {
    runWasmPack(browser, driver, cratePath);
  }
}

function requireChromeDriver() {
  const chrome = findChrome();
  const chromedriver = findExecutable("CHROMEDRIVER", "chromedriver", []);
  if (!chrome) {
    fail("Chrome browser tests require Google Chrome. Set CHROME_BIN to the Chrome executable.");
  }
  if (!chromedriver) {
    fail("Chrome browser tests require chromedriver on PATH or CHROMEDRIVER.");
  }

  const chromeVersion = versionOf(chrome, ["--version"]);
  const driverVersion = versionOf(chromedriver, ["--version"]);
  const chromeMajor = parseMajorVersion(chromeVersion);
  const driverMajor = parseMajorVersion(driverVersion);
  if (chromeMajor !== driverMajor) {
    fail(
      `Chrome/ChromeDriver major versions differ: Chrome ${chromeVersion}, ChromeDriver ${driverVersion}. ` +
        "Install a matching chromedriver or update Chrome before running the Chrome wasm browser lane.",
    );
  }

  return { flag: "--chromedriver", path: chromedriver };
}

function requireGeckoDriver() {
  const firefox = findFirefox();
  const geckodriver = findExecutable("GECKODRIVER", "geckodriver", []);
  if (!firefox) {
    fail("Firefox browser tests require Firefox. Set FIREFOX_BIN to the Firefox executable.");
  }
  if (!geckodriver) {
    fail("Firefox browser tests require geckodriver on PATH or GECKODRIVER.");
  }

  return { flag: "--geckodriver", path: geckodriver };
}

function runWasmPack(browser, driver, cratePath) {
  const browserFlag = browser === "chrome" ? "--chrome" : "--firefox";
  const args = [
    "test",
    browserFlag,
    "--headless",
    driver.flag,
    driver.path,
    cratePath,
    "--no-default-features",
    "--features",
    "wasm",
  ];

  if (options.dryRun) {
    process.stdout.write(`wasm-pack ${args.join(" ")}\n`);
    return;
  }

  const result = spawnSync("wasm-pack", args, {
    cwd: root,
    stdio: "inherit",
  });
  if (result.error) {
    fail(`wasm-pack could not start for ${cratePath}`);
  }
  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}

function versionOf(executable, args) {
  const result = spawnSync(executable, args, {
    cwd: root,
    encoding: "utf8",
  });
  if (result.error || result.status !== 0) {
    fail(`could not read version from ${executable}`);
  }
  return `${result.stdout}${result.stderr}`.trim();
}

function parseMajorVersion(versionText) {
  const match = versionText.match(/\b([0-9]+)[.][0-9]+[.][0-9]+(?:[.][0-9]+)?\b/u);
  if (!match) {
    fail(`could not parse browser major version from: ${versionText}`);
  }
  return Number.parseInt(match[1], 10);
}

function findChrome() {
  return findExecutable("CHROME_BIN", "google-chrome", [
    "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome",
    "/Applications/Google Chrome Canary.app/Contents/MacOS/Google Chrome Canary",
  ]);
}

function findFirefox() {
  return findExecutable("FIREFOX_BIN", "firefox", [
    "/Applications/Firefox.app/Contents/MacOS/firefox",
  ]);
}

function findExecutable(envName, executableName, fallbackPaths) {
  const envValue = process.env[envName];
  if (envValue && isExecutable(envValue)) {
    return envValue;
  }
  for (const directory of process.env.PATH?.split(delimiter) ?? []) {
    const candidate = resolve(directory, executableName);
    if (isExecutable(candidate)) {
      return candidate;
    }
  }
  for (const candidate of fallbackPaths) {
    if (isExecutable(candidate)) {
      return candidate;
    }
  }
  return null;
}

function isExecutable(path) {
  try {
    accessSync(path, constants.X_OK);
    return true;
  } catch {
    return false;
  }
}

function fail(message) {
  process.stderr.write(`${message}\n`);
  process.exit(1);
}
