# Scanner preprocessing measurements

These are same-host measurements of the unchanged scanner/MCP benchmarks with Go 1.26.8 on Linux/amd64, an Intel Xeon Platinum 8573C, and GOMAXPROCS=4. The v3.5.0 reference is `ca05ed06`; the main reference is `b738cec9`. The optimized snapshot is code tree `4639f779` on that main revision. The optimization patch was later rebased onto `4ac406d4` byte for byte. The timing files identify the measured snapshot rather than relabeling it as a different binary.

Each revision ran through `scripts/check-bench-regression.sh --update-baseline` six times with `BENCH_COUNT=1` and `BENCH_TIME=100ms`. Revision order alternated between old/main/optimized and optimized/main/old. Task builds and tests were kept separate from timed runs. The old revision has 37 benchmark names and 222 samples; main and the optimized snapshot have 56 names and 336 samples each. No benchmark bodies or the checked-in moving baseline were changed.

A Go test execution wrapper gave every test process the same minimal environment: PATH, HOME, TMPDIR and GOMAXPROCS. This keeps ambient environment values from adding different secret-matching work to the fragment benchmark. The scanner's environment-secret detection feature stayed unchanged on every revision.

[summary.csv](summary.csv) contains all measured names, with minimum, median and maximum time plus median bytes and allocations. The repository's regression script uses the minimum of six samples. On that statistic, 14 of the 15 target rows are within 20% of v3.5.0. Median comparisons put nine below v3.5.0 and all 15 below main. These samples have visible scheduling noise; a minimum isn't a general latency guarantee.

The clean-canary row still exceeds the 20% target. It retains broader encoding and partial-value coverage than v3.5.0. Separate decoding measurements establish extra work, but don't establish that its entire remaining gap is unavoidable or attributable to one coverage change.

The `-focused.txt` files retain a separate six-sample check at one second per sample for clean canary, text extraction and the serial/parallel blocklist paths. This check followed a noisy parallel-blocklist result in the full run. It measured a 13.4% lower parallel-blocklist median than main, versus a 21.1% higher median in the short run. Text extraction's focused median was 4.2% below v3.5.0; the short-run median was 25.9% above it. Clean canary remained above v3.5.0 in both runs. Both datasets are retained.

To repeat the repository benchmark command in a prepared checkout with the same compiler and controlled test-process environment:

```sh
results=$(mktemp -d)
mkdir "$results/home" "$results/tmp"
cat > "$results/exec-benchmark" <<'SH'
#!/bin/sh
exec env -i PATH=/usr/bin:/bin HOME="$BENCH_HOME" TMPDIR="$BENCH_TMP" GOMAXPROCS=4 "$@"
SH
chmod 700 "$results/exec-benchmark"
BENCH_HOME="$results/home" BENCH_TMP="$results/tmp" GOMAXPROCS=4 \
  GOFLAGS="-p=1 -exec=$results/exec-benchmark" \
  BENCH_BASELINE="$results/scanner.txt" BENCH_COUNT=6 BENCH_TIME=100ms \
  bash scripts/check-bench-regression.sh --update-baseline
```

For a comparison across checkouts, use one sample per invocation and alternate their order as above. Record the test-process environment and all samples. Use `BENCH_TIME=1s` with `BENCH_PATTERN='^(BenchmarkParallel_Blocklist|BenchmarkScan_BlockedByBlocklist|BenchmarkExtractText|BenchmarkScanCanaryText_Clean)$'` for the focused check.
