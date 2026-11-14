// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { readFileSync, writeFileSync } from "node:fs";
import { join } from "node:path";

export class BuffaViewHandlePolicyError extends Error {
  constructor() { super("unexpected Buffa owned view trait binding"); this.name = "BuffaViewHandlePolicyError"; }
}

/** Buffa 0.1 exposes the raw handle via a public associated type. */
export function restrictViewHandles(source, names) {
  let result = source;
  for (const name of names) {
    if (!/^[A-Za-z_][A-Za-z0-9_]*$/u.test(name)) throw new BuffaViewHandlePolicyError();
    const declaration = new RegExp(`^impl ::buffa::HasMessageView\\s+for super::super::${name}\\s+\\{\\s+type View<'a> = ${name}View<'a>;\\s+type ViewHandle = ${name}OwnedView;\\s+\\}\\n`, "gmu");
    const matches = [...result.matchAll(declaration)];
    if (matches.length !== 1) throw new BuffaViewHandlePolicyError();
    // Remove only the trait route to the raw owned handle. MessageView and
    // lifetime reborrowing remain native; production code uses the guarded
    // owner instead. No generated field or cleanup implementation is edited.
    result = result.replace(declaration, "");
  }
  return result;
}

export function restrictBuffaViewHandles(root, policy) {
  const byFile = new Map();
  for (const message of policy.messages) {
    if (!policy.privateNames.has(message.name)) continue;
    const basename = message.file.split("/").at(-1).replace(/\.proto$/u, "");
    if (!/^[a-z_]+$/u.test(basename)) throw new BuffaViewHandlePolicyError();
    const path = join(root, `crates/proto/src/generated/buffa/${policy.package}.${basename}.__view.rs`);
    if (!byFile.has(path)) byFile.set(path, []);
    byFile.get(path).push(message.name);
  }
  const outputs = [...byFile].map(([path, names]) => {
    const before = readFileSync(path, "utf8");
    return [path, restrictViewHandles(before, names)];
  });
  for (const [path, source] of outputs) writeFileSync(path, source);
}
