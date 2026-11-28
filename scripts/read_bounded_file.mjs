// SPDX-FileCopyrightText: 2026 ReallyMe Technologies Limited
//
// SPDX-License-Identifier: MIT OR Apache-2.0

import { createHash } from "node:crypto";
import { closeSync, constants, fstatSync, openSync, readSync } from "node:fs";

const CHUNK_BYTES = 65_536;

export class FileInputError extends Error {
  constructor(code) {
    super("file input rejected");
    this.name = "FileInputError";
    this.code = code;
  }
}

const fail = (code) => { throw new FileInputError(code); };

function consume(path, maximumBytes, collect) {
  if (!Number.isSafeInteger(maximumBytes) || maximumBytes < 1 || maximumBytes >= Number.MAX_SAFE_INTEGER) {
    fail("invalid-boundary");
  }
  if (!Number.isInteger(constants.O_NOFOLLOW)) fail("no-follow-unavailable");
  let descriptor;
  try {
    descriptor = openSync(path, constants.O_RDONLY | constants.O_NOFOLLOW | constants.O_NONBLOCK);
    const before = fstatSync(descriptor, { bigint: true });
    if (!before.isFile()) fail("not-regular");
    if (before.size < 1n || before.size > BigInt(maximumBytes)) fail("invalid-size");
    const size = Number(before.size);
    const output = collect ? Buffer.alloc(size) : undefined;
    const hash = collect ? undefined : createHash("sha256");
    const chunk = Buffer.alloc(Math.min(CHUNK_BYTES, size + 1));
    let total = 0;
    while (true) {
      // Probe one byte beyond the original size, without reading an unbounded
      // file if another process appends to the open inode.
      const count = readSync(descriptor, chunk, 0, Math.min(chunk.length, size - total + 1), null);
      if (count === 0) break;
      if (count > size - total) fail("changed-during-read");
      const bytes = chunk.subarray(0, count);
      if (collect) output.set(bytes, total);
      else hash.update(bytes);
      total += count;
    }
    const after = fstatSync(descriptor, { bigint: true });
    if (total !== size || before.size !== after.size || before.mtimeNs !== after.mtimeNs || before.ctimeNs !== after.ctimeNs) {
      fail("changed-during-read");
    }
    return collect ? output : { size, sha256: hash.digest("hex") };
  } catch (error) {
    if (error instanceof FileInputError) throw error;
    fail("unreadable");
  } finally {
    if (descriptor !== undefined) closeSync(descriptor);
  }
}

// Type, size and content all come from one descriptor. Replacing the path
// after open cannot substitute bytes between validation and consumption.
export const readBoundedFile = (path, maximumBytes) => consume(path, maximumBytes, true);
export const hashBoundedFile = (path, maximumBytes) => consume(path, maximumBytes, false);
