# Software release downloads

Pipelock's path-entropy heuristic checks URL path segments for opaque data. Software release filenames can exceed its threshold when they combine an application name, version, platform and archive suffix.

A final filename may repeat the semantic version in the immediately preceding path segment. In `/download/v1.2.3-beta.1/App-1.2.3-beta.1-linux-x64.tar.gz`, one literal copy of `1.2.3-beta.1` is left out of the filename's entropy score. The entire preceding segment must be a SemVer 2.0.0 value, optionally prefixed by one lower-case `v`; the filename match is a literal substring. If the full tag occurs in the filename, that copy takes precedence over the bare version. Only one copy is removed, and the remaining filename is scored normally.

The preceding segment is still scored. A filename that already passes keeps its allowance, since removing text can increase entropy. Other path segments and query values retain their checks. The same scorer handles URLs nested in query values after their existing decoding. Credential detection still checks the original URL; this changes only the path-entropy heuristic. It does not verify a publisher or an artifact's integrity.

For recurring software downloads that still trigger path entropy, an operator-reviewed publisher-specific prefix in `fetch_proxy.monitoring.path_entropy_exclusions` can cover successive releases without another filename entry. Every request under that prefix loses path-entropy checking, including names not published by that source. Review whether an agent can send chosen data there and read it back before adding the exclusion; a familiar publisher name alone is not sufficient. An exact artifact prefix remains appropriate for an incident limited to one download.

Path entropy exclusions retain subdomain entropy, query entropy, query-key entropy, credential detection and SSRF checks. See [path entropy exclusions](../configuration.md#fetch-proxy) for configuration details. Use `pipelock explain --json https://assets.vendor.example/download/v1.2.3/App-1.2.3-linux-x64.tar.gz` to inspect a verdict before changing policy.
