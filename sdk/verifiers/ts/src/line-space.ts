// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

// Exact code points accepted by Go unicode.IsSpace for evidence JSONL lines.
export const goSpaceCodePoints = [
  0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x85, 0xa0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004,
  0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000,
] as const;

const goSpace = new Set<number>(goSpaceCodePoints);
const isGoSpace = (ch: string): boolean => goSpace.has(ch.codePointAt(0) ?? -1);

export function blankAfterGoTrim(value: string): boolean {
  return [...value].every(isGoSpace);
}

export function trimGoSpace(value: string): string {
  const chars = [...value];
  let start = 0;
  let end = chars.length;
  while (start < end && isGoSpace(chars[start]!)) start++;
  while (end > start && isGoSpace(chars[end - 1]!)) end--;
  return chars.slice(start, end).join("");
}
