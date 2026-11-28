// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { createHash, timingSafeEqual } from "node:crypto";
import { registerHooks } from "node:module";
import { readBoundedFile } from "./read_bounded_file.mjs";

const MAX_CORE_BYTES = 262_144;
const CORE_SHA256 = "56ae3823215f5bca908d2fce3c9304d4ea6bab0334038f37ebe33023dadb8594";

export class ReadinessCoreError extends Error {
  constructor() {
    super("release readiness core does not match the reviewed bytes");
    this.name = "ReadinessCoreError";
    this.code = "unreviewed-core";
  }
}

export async function loadReleaseReadinessCore(managedCoreUrl) {
  try {
    const localCore = new URL("./release-readiness/core.mjs", import.meta.url);
    const reviewed = readBoundedFile(localCore, MAX_CORE_BYTES);
    const digest = createHash("sha256").update(reviewed).digest();
    if (!timingSafeEqual(digest, Buffer.from(CORE_SHA256, "hex"))) throw new ReadinessCoreError();
    const selected = managedCoreUrl === undefined ? localCore : new URL(managedCoreUrl);
    if (selected.protocol !== "file:" || selected.search !== "" || selected.hash !== "" ||
        (managedCoreUrl !== undefined && !reviewed.equals(readBoundedFile(selected, MAX_CORE_BYTES)))) {
      throw new ReadinessCoreError();
    }

    // Keep the file URL used by the upstream provenance checks, but execute
    // the captured, authenticated bytes rather than reopening that path.
    const hooks = registerHooks({
      resolve(specifier, context, nextResolve) {
        if (specifier === selected.href) return { url: selected.href, shortCircuit: true };
        return nextResolve(specifier, context);
      },
      load(url, context, nextLoad) {
        if (url === selected.href) return { format: "module", source: reviewed, shortCircuit: true };
        return nextLoad(url, context);
      },
    });
    try {
      return await import(selected.href);
    } finally {
      hooks.deregister();
    }
  } catch {
    throw new ReadinessCoreError();
  }
}
