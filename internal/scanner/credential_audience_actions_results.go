// Copyright 2026 Josh Waldrep
// SPDX-License-Identifier: Apache-2.0

package scanner

import (
	"net/url"
	"path"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/luckyPipewrench/pipelock/internal/destination"
)

// githubActionsResultsHosts are the storage accounts that serve GitHub
// Actions job logs and workflow artifacts: `gh run view --log`, the job-log
// API and artifact downloads answer with a 303 to one of them carrying an
// Azure user-delegation SAS and no release grant. GitHub publishes the list in
// its meta API under domains.actions: productionresultssa0 through
// productionresultssa19. Each entry is one account. *.blob.core.windows.net is
// not an audience, because any Azure customer can create an account on that
// suffix.
// Source: GET https://api.github.com/meta, read 2026-10-06.
var githubActionsResultsHosts = func() []string {
	const accounts = 20
	hosts := make([]string, 0, accounts)
	for i := range accounts {
		hosts = append(hosts, "productionresultssa"+strconv.Itoa(i)+".blob.core.windows.net")
	}
	return hosts
}()

const actionsResultsGUID = `[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}`

// actionsResultsPathPattern is the blob path GitHub issues for a job log
// (.../logs/job/job-logs.txt) and a workflow artifact
// (.../artifacts/<sha256>.zip), both observed from live redirects on
// 2026-10-06. The container and run segments are fixed and the rest is a clean
// path of plain file-name characters, so an encoded slash, a traversal segment
// or a free-form value cannot ride the allowance.
var actionsResultsPathPattern = regexp.MustCompile(
	`^/actions-results/` + actionsResultsGUID + `/workflow-job-run-` + actionsResultsGUID +
		`/(?:logs|artifacts)/[A-Za-z0-9._-]+(?:/[A-Za-z0-9._-]+)*$`)

// actionsResultsOverrideFormats pins the two response-header overrides an
// Actions artifact redirect carries (rscd and rsct) to the shape observed on
// 2026-10-06: `attachment; filename="<artifact name>"` with the name in quotes,
// and a plain media type. An artifact name is chosen by the workflow author,
// so it can score above the entropy threshold; the pin admits only letters,
// digits, space and `.`, `_`, `+`, `-`, up to 255 bytes, and it applies only on
// a valid results SAS at one of the published accounts.
var actionsResultsOverrideFormats = map[string]*regexp.Regexp{
	"rscd": regexp.MustCompile(`^attachment; filename="[A-Za-z0-9._+ -]{1,` + strconv.Itoa(releaseGrantResponseOverrideMaxFilename) + `}"$`),
	"rsct": regexp.MustCompile(`^[a-z]{1,32}/[a-z0-9][a-z0-9.+-]{0,63}$`),
}

func actionsResultsPath(u *url.URL) bool {
	p := u.EscapedPath()
	if p == "" || strings.Contains(p, "%") || path.Clean(p) != p {
		return false
	}
	return actionsResultsPathPattern.MatchString(p)
}

// actionsResultsSASAllowed grants the Azure SAS in a GitHub Actions results
// redirect. It is the attestation bundle predicate on a different set of
// accounts and paths: exact published account, https, a results blob path, and
// the same read-only blob user-delegation SAS with every signed field once in
// its documented format, start time included, inside the attestation lifetime
// cap. There is no co-located JWT. The proxy cannot verify the HMAC, so the
// bound is the destination: the value this allow releases is the signature
// itself, and it can only reach GitHub's own storage account. Every other
// credential in the URL is still scanned.
func actionsResultsSASAllowed(host, target string, now time.Time) bool {
	if !destination.MatchesDomainList(host, githubActionsResultsHosts) {
		return false
	}
	parsed, err := url.Parse(target)
	if err != nil || !strings.EqualFold(parsed.Scheme, "https") {
		return false
	}
	return actionsResultsPath(parsed) && attestationBundleSASQueryValid(parsed, now)
}

// githubBlobSASAllowed is the one predicate for a SAS GitHub itself issues on
// its own storage accounts without a release grant: the attestation bundle
// accounts and the Actions results accounts. The DLP candidate decision, the
// url_query surface decision and the query-entropy exemption all answer
// through it, so none can decide a different SAS than the others.
func githubBlobSASAllowed(host, target string, now time.Time) bool {
	return attestationBundleSASAllowed(host, target, now) || actionsResultsSASAllowed(host, target, now)
}
