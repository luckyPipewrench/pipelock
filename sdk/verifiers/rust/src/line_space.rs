// Copyright 2026 Pipelock contributors
// SPDX-License-Identifier: Apache-2.0

/// Exact code points accepted by Go unicode.IsSpace for evidence lines.
pub const GO_SPACE_CODEPOINTS: &[u32] = &[
    0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x20, 0x85, 0xa0, 0x1680, 0x2000, 0x2001, 0x2002, 0x2003, 0x2004,
    0x2005, 0x2006, 0x2007, 0x2008, 0x2009, 0x200a, 0x2028, 0x2029, 0x202f, 0x205f, 0x3000,
];

pub fn is_go_space(ch: char) -> bool {
    GO_SPACE_CODEPOINTS.contains(&(ch as u32))
}

pub fn trim_go_space(line: &str) -> &str {
    line.trim_matches(is_go_space)
}
