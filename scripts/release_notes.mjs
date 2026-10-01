// SPDX-FileCopyrightText: 2026 ReallyMe LLC
//
// SPDX-License-Identifier: MIT OR Apache-2.0

const VERSION_PATTERN = /^(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)$/u;
const HEADING_PATTERN = /^## ([^\r\n]+)$/gmu;

export class ReleaseNotesError extends Error {
  constructor(code) {
    super(code);
    this.name = "ReleaseNotesError";
    this.code = code;
  }
}

/** Selects exactly one release section; duplicate or empty sections fail closed. */
export function extractReleaseNotes(source, version) {
  if (!VERSION_PATTERN.test(version)) {
    throw new ReleaseNotesError("InvalidVersion");
  }
  const headings = [...source.matchAll(HEADING_PATTERN)];
  const matching = headings.filter((heading) => heading[1] === version);
  if (matching.length !== 1) {
    throw new ReleaseNotesError("MissingOrDuplicateVersion");
  }
  const heading = matching[0];
  const following = headings.find((candidate) => candidate.index > heading.index);
  const end = following?.index ?? source.length;
  const notes = source.slice(heading.index, end).trimEnd();
  if (notes.slice(heading[0].length).trim().length === 0) {
    throw new ReleaseNotesError("EmptyReleaseNotes");
  }
  return notes;
}
