#!/usr/bin/env node
// SPDX-FileCopyrightText: Copyright © 2026 ReallyMe LLC. All rights reserved
//
// SPDX-License-Identifier: Apache-2.0

import { spawnSync } from "node:child_process";
import { resolve } from "node:path";
import { fileURLToPath } from "node:url";

const root = resolve(fileURLToPath(new URL("..", import.meta.url)));

const commands = [
  {
    label: "CCTV ML-DSA accumulated 10,000-iteration audit",
    program: "cargo",
    args: [
      "test",
      "-p",
      "external-vector-audit",
      "--no-default-features",
      "--features",
      "native",
      "--test",
      "cctv_ml_dsa",
      "cctv_ml_dsa_accumulated_10k_vectors_match_public_api",
      "--",
      "--ignored",
    ],
  },
  {
    label: "CCTV ML-KEM full modulus corpus audit",
    program: "cargo",
    args: [
      "test",
      "-p",
      "external-vector-audit",
      "--no-default-features",
      "--features",
      "native",
      "--test",
      "cctv_ml_kem_modulus",
      "--",
      "--ignored",
    ],
  },
];

for (const command of commands) {
  process.stderr.write(`\n==> ${command.label}\n`);
  const result = spawnSync(command.program, command.args, {
    cwd: root,
    stdio: "inherit",
  });

  if (result.error) {
    process.stderr.write(`${command.label} could not start\n`);
    process.exit(1);
  }

  if (result.status !== 0) {
    process.exit(result.status ?? 1);
  }
}
