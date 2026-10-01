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

### Current strict Chromium compatibility limit

The standalone `sandbox --strict` launch is currently unsupported for Chromium
with Chromium's own sandbox enabled. It maps the workload to UID 0 in its user
namespace, which Chromium rejects, and its unchanged seccomp policy denies the
nested namespace operations Chromium's sandbox needs. A host satisfying the
kernel prerequisites below does not remove these conflicts. Native Node thread
compatibility does not establish Chromium compatibility. Do not disable either
sandbox or relax namespace policy to make this diagnostic pass.

The existing managed `contain run` path uses a dedicated nonroot identity and
managed network namespace. The separate managed adapter below targets only an
explicitly prepared synthetic-only VM. Its temporary fixture/configuration must
not be redirected to an existing production proxy. The default strict run remains
a failure diagnostic, not a supported browser acceptance command.

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
PIPELOCK_BROWSER_TEST_BIN="$PWD/pipelock" \
  python3 -m unittest discover -s scripts/e2e/browser_repro -p 'test_*.py'
node --check scripts/e2e/browser_repro/driver.mjs
node --test scripts/e2e/browser_repro/test_contracts.mjs
```

These commands validate the build and harness components, including real CLI
startup and refusal of an occupied healthy listener. Without
`PIPELOCK_BROWSER_TEST_BIN`, those CLI integration tests report an explicit skip.
They do not establish browser or containment acceptance. The default browser
run (`python3 scripts/e2e/browser_repro/run.py --pipelock ./pipelock --output
/tmp/browser-repro-strict`) currently encounters the strict compatibility limit
above and must not be requested as a passing acceptance rerun.

The output directory must not already exist. `--node` and `--chromium` accept
explicit executable paths. The selected Node command is queried for its actual
`process.execPath` in the isolated environment, so a version-manager launcher
is not mistaken for the runtime. Node 22+ and a native Linux executable are
required. That runtime is copied into the already granted disposable workspace;
its content hash and copied executable identity are checked. No extra host
directory read grant is added. A launcher that cannot resolve Node without its
usual home/configuration must be replaced with an explicit native `--node` path.
The runtime must use system libraries available under the normal sandbox policy.
A runtime needing additional private dependencies is unsupported rather than a
reason to broaden access. The browser profile and synthetic state are created
in that fresh workspace. Removal requires verified local process cleanup and
successful evidence saves. Incomplete cleanup or an evidence-save failure keeps
the workspace and reports its path. An incomplete summary is saved before removal;
the terminal summary can claim completion only after required cleanup succeeds.
The executable identity probes run before containment; they do not establish
strict Node or browser compatibility. The unchanged strict launch and cleanup
assertions must still complete on the acceptance host.

When strict launch is unavailable, an operator may explicitly run the separate
proxy diagnostic below. This is **not Pipelock kernel containment**, even when
Chromium itself starts successfully. It does not satisfy managed containment acceptance.

```bash
python3 scripts/e2e/browser_repro/run.py --mode proxy-only \
  --pipelock ./pipelock --output /tmp/browser-repro-proxy
```

The proxy-only mode leaves Chromium's own sandbox enabled and does not claim
that raw direct egress is blocked. It binds a temporary proxy and fixture only
to loopback. The runner selects a random nonzero high port without probing or
prebinding it, because file-backed CLI configuration rejects port zero. Only
the candidate proxy binds that port. The runner requires its exact requested
address in that invocation's complete JSON startup record before checking
health. An occupied port fails the run; randomness is not proof of availability
or ownership. Missing, mismatched, ambiguous or truncated startup evidence also
fails; an existing daemon's healthy endpoint cannot substitute for it.

## Managed-contained browser adapter

The privileged adapter must be launched from a separately verified, root-owned
harness copy whose files and parent directories cannot be changed by nonroot
users. Use a trusted Python interpreter and import environment, outside all
agent-writable scratch. Establish this prerequisite before invoking Python;
do not run the root adapter directly from an agent/operator-writable checkout.
The manifest's source hashes detect source drift after Python starts. They do
not authenticate the entry point, imported helpers or interpreter already
executing with root privileges. The runner does not install a trusted copy or
change source ownership for you.

`scripts/e2e/browser_repro/managed.py` reuses the same generated application and
CDP scenarios through the existing `contain run` launch. It does not wrap
Chromium in the incompatible standalone strict sandbox, and leaves Chromium's
own sandbox enabled. The managed topology supplies its existing dedicated
nonroot user, network namespace, proxy doorway, nftables rules, private temporary
directories and mandatory launch preflight. This is a distinct containment mode,
not a claim that the two sandbox implementations are identical.

### Prepare artifacts, then authorize a disposable host

Prepare against the exact built candidate and explicitly selected **native**
Linux executables. The example executable paths depend on the distribution;
launchers and shell wrappers are rejected rather than copied as runtimes.

```bash
python3 scripts/e2e/browser_repro/managed.py prepare \
  --pipelock ./pipelock --node /usr/bin/node \
  --chromium /usr/lib/chromium/chromium \
  --output /tmp/browser-repro-managed-setup
```

Preparation only writes a synthetic JSON configuration and manifest. It creates
no users, services, signing keys, grants, firewall rules or persistent access.
The manifest pins the candidate, runtime files and harness sources and names one
new workspace under `/srv/pipelock-browser-repro/`. It is not an installation or
a successful runtime test.

A local operator must separately authorize and prepare a **fresh, disposable,
synthetic-only Linux VM**, using the existing [contain installation
instructions](contain-cli.md). Never reuse a production installation or
an account/profile carrying real credentials. The fixed managed service/socket
names do not support a parallel isolated test instance on a shared host.
Prerequisites for the adapter are:

- systemd 254+, `systemctl`, `busctl`, cgroup v2 and the complete existing contain
  installation prerequisites, with the normal network/user/proxy checks passing
- The exact candidate installed at `/usr/local/bin/pipelock`, pinned by the
  ordinary installer, and running as `pipelock.service`
- The exact generated JSON policy installed at `/etc/pipelock/pipelock.yaml`;
  no extra destinations, overrides or detection exceptions. The proxy must have
  started after that file was installed; a stale running process is refused
- The installed config, tool registry, workspace inventory and integrity pin,
  including all parent directories, must be root-owned and not group- or
  world-writable. Ordinary root-owned `0644` policy files are accepted
- The operator-authorized synthetic signing key at the generated configuration's
  path. Existing contain setup owns key provisioning; this adapter never creates,
  reads or transmits private key material
- Root-owned native Node/Chromium binaries under root-controlled, nonwritable
  runtime directories, with no setuid/setgid bits or file capabilities; an
  agent/operator-writable version-manager installation
  is not suitable for the privileged managed identity probe
- One explicit `browser-repro-node` registration targeting the manifest's native
  Node binary, using the existing `contain add-tool --target` mechanism. Duplicate
  or PATH-fallback entries are refused
- Exactly one nonlegacy `pipelock-agent` read-write workspace grant: the empty
  directory named in the manifest. Use the existing `contain grant-workspace`
  mechanism after reviewing that scope. Extra/ambiguous grants are refused
- A root-owned, owner-only copy of the prepared manifest under a root-controlled
  directory, and a new root-private evidence output outside the agent workspace
- No existing process running as `pipelock-agent`. The adapter is exclusive to
  this disposable diagnostic VM, not a concurrent agent session

The adapter does not automate these host changes. A manifest acknowledgment is
an operator declaration of fresh-host provenance, not independent proof that a
machine never held secrets. Exact config, registry, workspace and runtime checks
reject mismatches before the browser launch. A refused setup must be corrected
through the authorized installation procedure, never by skipping preflight.
The unchanged contain preflight includes an operator HTTPS reachability control
to `example.com` and a denied TEST-NET-1 direct-egress control; browser traffic
itself only targets the owned generated fixture.

### Run and interpret the managed diagnostic

Once the operator has approved and verified that setup, run on that VM:

```bash
sudo python3 scripts/e2e/browser_repro/managed.py run \
  --pipelock /usr/local/bin/pipelock \
  --manifest /var/lib/pipelock-browser-repro/manifest.json \
  --output /var/lib/pipelock-browser-repro/run-001 \
  --acknowledge-disposable-synthetic-host
```

The manifest/config/runtime hashes must match. Each invocation creates a new
synthetic profile and results directory in the sole granted scratch workspace;
only those newly created files are made accessible to the contained identity.
Root evidence remains outside that workspace. The runtime checks the actual
native Node identity, nonzero UID/GID, exact installed proxy route, different
network namespace and inability to contact the parent's witnessed endpoint
directly. Fixture counts corroborate all mediated/blocked controls and the
original login `303`, authenticated data, restart and cookie-clearing recovery.

Managed launch requests the optional `contain run --lifecycle-output` report.
That report binds a random transient-unit identity, systemd InvocationID, launch
arguments, binary/config/policy and signed posture capsule. Success additionally
requires terminal service state and an empty/absent admitted cgroup. A successful
`systemd-run` client or reaped local child alone cannot establish this. The
existing process supervisor still owns the local client; its managed-only
20-second graceful cancellation budget accommodates bounded service cleanup.
No unknown or unrelated unit is stopped. Missing identity, changed invocation,
incomplete cleanup or any failed browser scenario leaves the run failed.

The producer marks failed or cancelled commands `incomplete` even when their
owned service and cgroup have been cleaned up. The adapter records independently
bound cleanup as `lifecycle_cleanup` so it can preserve diagnostics and remove
only that invocation's scratch. This does not establish successful execution:
acceptance still requires a complete, non-cancelled lifecycle without a failure,
a zero driver exit and the remaining browser/fixture checks.

When service cleanup is verified, the adapter removes its synthetic profile and
workspace subtree, including after a failed browser command. Before removal,
it preserves a valid bounded `browser.json` failure report and supported PNGs in
the evidence directory. Missing or rejected reports and screenshot errors are
identified in the summary; a nonzero command exit remains a failure even if the
child report says complete. The adapter saves an incomplete summary before removing
scratch, then writes the terminal result. If a valid report, screenshot or the
pre-removal summary cannot be saved, its workspace is retained. If service cleanup
cannot be established, generated scratch
is retained for the operator rather than deleted underneath a possibly live
browser. `cleanup_complete`
establishes that the owned service/cgroup is stopped and empty; failed transient
unit records may remain after that cleanup. Root-private logs remain bounded.
Keep failure evidence and use the exact owned-unit report when investigating;
do not apply broad service-kill or sandbox-disable workarounds.

If the local process supervisor misses its cleanup deadline, the runner saves
bounded output snapshots and a failed process record where the evidence directory
remains writable, retains scratch, and reports cleanup as unproven. It does not
kill the sole descendant owner or interpret a stale cleanup file as success.
Recovery from a stalled supervisor requires a separate ownership design and is
outside this harness's acceptance claim. Failed transient units are likewise
retained: the manager's name-addressed reset operation cannot atomically verify
the recorded InvocationID, so the adapter does not issue `reset-failed`.

The managed adapter's filesystem/identity/policy/lifecycle contracts have
lightweight regression tests in the existing Example verification job. Actual
systemd/nftables/Chromium sandbox behavior, rendered pixels and interrupted
service cleanup still require the capable VM run; mocks are not that acceptance.
No managed viewer, agent-browser daemon, TLS or production-authentication claim
follows from the synthetic CDP diagnostic.

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
- In standalone strict and managed-contain modes: distinct network namespace
  and direct failure against the parent's witnessed, owned loopback endpoint.
  This direct-endpoint check probes no outside target

The parent fixture counts corroborate that outbound refusals never arrived,
that the response marker did arrive before response scanning, and that each
intended error/pending endpoint was actually requested. A refused connection
without a parent witness and a namespace observation is not containment proof.

## Evidence and interpretation

Both runner summaries identify candidate/harness, generated fixture and
configuration hashes, scope and cleanup witnesses. The standalone runner also
records checkout SHA, tracked diff hash and dirty status; the managed adapter
records installation/runtime/service identity and its lifecycle report instead.
The checkout SHA does not cryptographically prove the supplied binary was built
from it; retain the separate build log and commit identity.

A failed or interrupted run reports containment as `not_established`, even if
earlier namespace or lifecycle observations succeeded. Those observations stay
in the report for diagnosis; a later fixture, cleanup or cancellation failure
cannot leave an aggregate success claim. Proxy-only runs retain their explicit
`not_tested_proxy_only` label and never establish containment.

JSON publication prepares a private temporary file in the same directory,
completes its write, flush and close, then atomically replaces the destination.
A preparation or replacement failure preserves the prior incomplete summary.
Cancellation is checked after workspace cleanup and again before the terminal
publication, so an interruption during cleanup or file preparation remains failed.

Both runners read child artifacts through bounded, descriptor-relative opens
that refuse symlinks in any path component, nonregular files, multiple hard
links and unexpected file owners. A valid `browser.json` is at most 2 MiB and is
preserved byte-for-byte. Screenshot collection reads only `cold.png`, `warm.png`,
`reload.png` and `delayed.png`, at most 8 MiB each, and checks the PNG signature.
Other workspace files cannot expand the retained artifact set. These checks
protect artifact ingestion; they do not establish rendered-pixel acceptance.

`browser.json` separates request TTFB/body completion, navigation-to-ready,
application readiness, input round-trip and render frame samples. Request
latency includes proxy and origin work; it is not scanner-only CPU time. Run
scanner profiling/benchmarks separately under an uncontended CPU window.
`fixture.json` contains bounded route timing tails and arrival counts. Request
URLs, cookies and submitted values are not logged by the fixture.
After a driver launch attempt, both runners try to save these counts even when
local process cleanup fails. The summary keeps driver wait errors and reports
secondary fixture-save errors separately; failed evidence saving retains scratch.
Earlier setup failures may not produce `fixture.json`.
Anonymous authentication counts separately witness one accepted login,
authenticated account requests before and after restart, and unauthenticated
account requests before login and after cookie clearing. Those witnesses are
required alongside the browser's form/data assertions.

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

The truncated API control expects Pipelock's HTTP 403 `parse_error` refusal,
corroborated by browser response metadata and the fixture's arrival witness.
A generic 403 or an unrelated fetch failure does not satisfy it. Unexpected
application-scenario failures are retained while later independent scenarios
continue; any retained failure prevents overall completion. Login readiness
checks the actual synthetic form and its origin rather than inferring state
from a URL alone. Forward-proxy redirects are returned to the browser, which
owns the fixture's original `303` login flow and session cookie. Authenticated
account data, profile restart and cleared-cookie recovery must all be observed;
a login form or a successful submission alone is not authentication acceptance.

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

The following is the acceptance specification, not a claim that the current
standalone harness can satisfy it. Use the managed-contain adapter on its
separately authorized capable VM for a contained-browser rerun; the standalone
strict Chromium path remains unsupported. Before merging a browser/response candidate, the
user's local agent should:

1. Check out the reviewed exact commit; build it and run the repository-required
   applicable lint/tests, plus this harness's unit tests and supported contained
   browser run. Preserve
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
