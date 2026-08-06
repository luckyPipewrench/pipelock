// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

import { existsSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

export function findPackageRoot(moduleURL: string): string {
  let current = dirname(fileURLToPath(moduleURL));
  for (;;) {
    if (existsSync(resolve(current, "package.json"))) return current;
    const parent = dirname(current);
    if (parent === current) throw new Error("TypeScript verifier package root not found");
    current = parent;
  }
}
