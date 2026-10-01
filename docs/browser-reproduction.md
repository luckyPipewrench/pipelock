# Portable synthetic browser reproduction

This is a diagnostic harness for the shipped Pipelock proxy and sandbox. It
uses a generated application, generated JavaScript, synthetic login values,
and new disposable browser profiles. It never visits a production site or
reads an existing profile. No third-party bundle is checked in.

## Repository mechanisms and ownership

- `pipelock sandbox --strict` uses the existing user/network namespace, Unix
  proxy bridge, Landlock, seccomp and descendant cleanup. It does not require
  root, nftables or systemd. See [sandbox launch posture](guides/sandbox.md).
- Managed `pipelock contain` is a different deployment: dedicated identities,
  systemd namespace/doorway units, nftables, proxy/CA environment and managed
  Xauthority. See [contain CLI](contain-cli.md). This harness does not provision,
  change or substitute for that host boundary.
- Exact `dns.host_overrides` plus `trusted_domains` is the documented synthetic
  fixture route. The strict proxy allowlist contains only the fixture hostname.
  The raw loopback address and a second forbidden hostname remain blocked.
- The repository viewer is a Unix-socket RFB relay, with peer identity checks,
  view/input separation, a viewer cap and a renewable control lease. noVNC
  assets and the `agent-browser` daemon are not shipped here. CDP tests below
  cannot establish their behavior or the managed viewer's behavior.
- `scripts/ci_process_supervisor.py` owns/reaps runner child processes. Both
  stdout and stderr are continuously drained with bounded retained tails.
  TERM/INT to the runner requests orderly teardown at safe checkpoints;
  interrupted runs remain failed. SIGKILL cannot run Python cleanup handlers.

The default command requires the real strict sandbox. A failed launch remains
failed/refused. The runner never retries with best-effort, disables Chromium's
sandbox, changes host policy, installs dependencies or loads credentials.

## Prerequisites and fresh setup

Use a clean public-repository checkout and an explicitly built candidate binary.
Requirements are Linux, Python 3.10+, Node 22+ with no npm dependencies, and a
system Chromium executable. Record exact versions rather than using unpinned
`latest` installs. Go 1.26+ is required to build Pipelock. The cloud environment
setup should install pinned versions from official distribution/vendor sources;
the harness intentionally performs no installation itself.

A saved coding environment must contain only this public repository and these
public dependencies. It needs no production secrets, workstation mounts,
existing browser profiles or private operational directories. Run capability
checks again in each environment: matching packages do not establish matching
kernel permissions. Strict runtime additionally needs Landlock, unprivileged
user/network/mount namespaces, permitted Unix sockets, seccomp and subreaping. The repository process
supervisor also needs `/proc/self/task/<pid>/children`; the harness refuses
long-lived child launch if that cleanup facility is absent.

```bash
make build
python3 -m unittest discover -s scripts/e2e/browser_repro -p 'test_*.py'
node --check scripts/e2e/browser_repro/driver.mjs
python3 scripts/e2e/browser_repro/run.py \
  --pipelock ./pipelock --output /tmp/browser-repro-strict
```

The output directory must not already exist. `--node` and `--chromium` accept
explicit executable paths. The selected Node executable is copied into the
already granted disposable workspace; no extra host directory read grant is
added. It must use system libraries available under the normal sandbox policy.
A runtime needing additional private dependencies is unsupported rather than a
reason to broaden access. The browser profile and synthetic state are created
in that fresh workspace and removed after cleanup.

When strict launch is unavailable, an operator may explicitly run the separate
proxy diagnostic below. This is **not Pipelock kernel containment**, even when
Chromium itself starts successfully. It does not satisfy strict acceptance.

```bash
python3 scripts/e2e/browser_repro/run.py --mode proxy-only \
  --pipelock ./pipelock --output /tmp/browser-repro-proxy
```

The proxy-only mode leaves Chromium's own sandbox enabled and does not claim
that raw direct egress is blocked. It binds a temporary proxy and fixture only
to loopback. A dynamically selected proxy port has a short bind/rebind race;
startup failure is a failed run, not permission to reuse an existing daemon.

## What the runner observes

The generated app loads roughly 2 MB of readable, deterministic JavaScript,
then a delayed script and API. The visible `ready` state requires all three and
rendered data. `--bundle-bytes` controls the target size (4 KiB–8 MB); size
policy can legitimately refuse a large response and is never relaxed by the
runner. `generated_bundle(size, marker=True)` appends the inert literal
`BROWSER_REPRO_RESPONSE_MARKER` for scanner-owner custom-rule benchmarks.

The matrix includes:

- Fresh-profile cold navigation, verified browser-cache warm navigation,
  a separate reload, and a deliberately delayed API
- Visible data completion, actual CDP keyboard/pointer input, count state,
  viewport/screen dimensions, bounded requestAnimationFrame samples and PNGs
- Intended HTTP 503, truncated API and deliberately pending API; the latter
  remains `expected_pending` after its observation window, never application PASS
- Synthetic login, redirect, persistent cookie and independently seeded storage
  across an actual browser process restart, plus a cleared-cookie redirect back to login
- Exact-host mediated positive control, forbidden-host and literal-loopback
  refusal, outbound synthetic canary refusal, and a benign response marker
  matched by the shipped System Override rule
- In strict mode only: distinct network namespace and direct failure against
  the parent's witnessed, owned loopback endpoint. No outside target is probed

The parent fixture counts corroborate that outbound refusals never arrived,
that the response marker did arrive before response scanning, and that each
intended error/pending endpoint was actually requested. A refused connection
without a parent witness and a namespace observation is not containment proof.

## Evidence and interpretation

`summary.json` identifies the binary hash, checkout SHA, individual harness
and supervisor hashes, tracked diff hash and dirty status, generated fixture
hash, config hash, versions, scope and cleanup
witnesses. The checkout SHA does not cryptographically prove the supplied binary
was built from it; retain the separate build log and commit identity.

`browser.json` separates request TTFB/body completion, navigation-to-ready,
application readiness, input round-trip and render frame samples. Request
latency includes proxy and origin work; it is not scanner-only CPU time. Run
scanner profiling/benchmarks separately under an uncontended CPU window.
`fixture.json` contains bounded route timing tails and arrival counts. Request
URLs, cookies and submitted values are not logged by the fixture.

## Scanner-only baseline and candidate comparison

Freeze the generated fixture once and keep its manifest with the run outputs:

```bash
python3 scripts/e2e/browser_repro/fixture.py --output /tmp/browser-repro-fixtures
PIPELOCK_BROWSER_REPRO_BENCH_DIR=/tmp/browser-repro-fixtures GOMAXPROCS=4 \
  go test ./internal/scanner -run '^$' \
  -bench '^BenchmarkResponseBrowserFixture$' -benchmem -benchtime=1x -count=5 \
  -cpuprofile=/tmp/browser-repro-candidate.cpu
```

Run the same benchmark source on the baseline and candidate, with the same
fixture directory and Go version, sequentially on an uncontended CPU. If the
baseline predates this benchmark, copy only
`internal/scanner/response_browser_bench_test.go` into a separate clean baseline
worktree; record that benchmark-only delta and its hash. Record both source
revisions, binary/build identity, fixture hashes, CPU limit and raw samples
outside the checkout. Generated logs, profiles, screenshots and run outputs are
diagnostic evidence, not source files to commit.

The clean cold case uses a new target for every scan, including repeated
benchmark runs, so it cannot accidentally measure the existing verdict cache.
The warm case deliberately primes that cache. The marked file adds only the
inert `BROWSER_REPRO_RESPONSE_MARKER`, with a dedicated configured rule; its
verdict must contain exactly that finding. Marked results are not cached.

The request-local large-response memo reuses only empty raw pattern results for
identical text and matching semantics. It never shares positive findings,
suppression, observations, attribution or span data. Its bounds and fallback
paths are separate from the existing cross-request clean-verdict cache. The
canary control is also independent of `dlp.scan_env` and a secrets file: a
configured canary must be checked even when both discovered secret lists are
empty. That intentional detection repair is distinct from response-result
parity checks.

`status: complete` means the planned assertions completed. Expected application
errors/pending states stay individually labelled; completion does not establish
production usability. `fail` means an assertion or lifecycle failed. `refused`
is reserved for a recognized strict-launch refusal. Missing, ambiguous or
incomplete evidence never becomes a pass. The harness verifies PNG structure
and dimensions; visually inspect captured pixels before making display claims.

The standalone sandbox currently uses a no-op structured audit logger. Its
configured logging settings do not create structured proxy audit evidence;
use the launch stderr, observed responses and fixture counts. Retained process
logs are capped at 64 KiB per stream with total byte counts and truncation
flags. Browser request histories are bounded per route and retain no bodies.

## Known coverage limits and pre-merge local acceptance

No cloud proxy-only result is a managed-host, agent-browser, viewer, TLS,
third-party authentication or production acceptance claim. In particular, this
harness does not reproduce externally observed daemon DISPLAY/Xauthority
inheritance, undrained Chromium stderr, noVNC startup/CSS, controller conflicts,
viewer reconnect or connected/disconnected rendering differences.

Before merging a browser/response candidate, the user's local agent should:

1. Check out the reviewed exact commit; build it and run the repository-required
   applicable lint/tests, plus this harness's unit tests and strict run. Preserve
   failed/refused stages alongside successful stages
2. On the separately authorized disposable managed host, run the existing
   `pipelock contain verify`, `pipelock contain doctor`, and documented
   `scripts/test-contain-network-namespace.sh` acceptance. These require that
   host's existing administrative authorization; do not run them on a shared
   cloud host or interpret this document as approval to install/change policy
3. Use only generated fixture data and a fresh agent-browser profile/session.
   Through the already configured contained route, confirm login completion,
   cookie/storage restart, delayed/error/pending states and actual rendered input
4. For the installed viewer, compare connected/disconnected frame samples,
   viewport versus display size, view-only input refusal, one-controller
   ownership, competing-controller refusal, release/reconnect and repeated
   start/stop. Record versions and bounded logs. Do not attribute an external
   noVNC/agent-browser failure to a Pipelock product defect without that boundary
5. Verify the same configuration's outbound and response negative controls and
   direct-egress boundary. Do not add script exemptions or disable a detector
   merely to improve timing
6. Have an independent reviewer assess the exact candidate and evidence before
   merge, including the process-cancellation regression on a capable host

A fresh independent review should answer ten questions: Are build identities
bound? Are all inputs generated? Is route enforcement preserved? Is containment
observed rather than inferred? Are negative controls attributed? Can errors or
pending work appear ready? Are profiles truly fresh/persistent as claimed? Are
logs and cleanup bounded/verified? Are scanner/network/render/input timings
separate? Are unsupported integrations and local acceptance gaps explicit?
