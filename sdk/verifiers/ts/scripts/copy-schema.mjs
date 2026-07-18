import { copyFileSync, mkdirSync } from "node:fs";
import { dirname, resolve } from "node:path";
import { fileURLToPath } from "node:url";

const here = dirname(fileURLToPath(import.meta.url));
const packageDir = resolve(here, "..");
const repoRoot = resolve(packageDir, "../../..");
const source = resolve(repoRoot, "sdk/audit-packet/v0.json");
const target = resolve(packageDir, "dist/src/v0.schema.json");

mkdirSync(dirname(target), { recursive: true });
copyFileSync(source, target);
// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0
