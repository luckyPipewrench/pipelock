//go:build enterprise

// Licensed under the Elastic License 2.0. See enterprise/LICENSE.

package licenseservice

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"html/template"
	"io"
	"net/http"
	"time"
)

const (
	resendAPIURL = "https://api.resend.com/emails"
	// hoursPerDay converts token lifetimes to whole days for email copy.
	hoursPerDay = 24
)

// licenseEmailData is the render context for the license delivery email.
type licenseEmailData struct {
	DisplayName      string
	Token            string
	IntermediateCert string
	ValidityDays     int
	IsTrial          bool
	IsEval           bool
}

// licenseEmailTmpl renders the license delivery email. html/template auto-escapes
// all interpolated values (notably the token), preventing HTML/script injection
// even though the token is opaque base64url today.
var licenseEmailTmpl = template.Must(template.New("license").Parse(
	`<h2>Your Pipelock License</h2>
<p>Thanks for choosing Pipelock {{.DisplayName}}!</p>
<p>Your license token (add this to your pipelock config as <code>license_key</code>):</p>
<pre style="background:#f4f4f4;padding:16px;border-radius:4px;overflow-x:auto;font-size:13px;">{{.Token}}</pre>
<p>Your intermediate certificate (save as a file and set <code>license_intermediate_file</code> to that path):</p>
<pre style="background:#f4f4f4;padding:16px;border-radius:4px;overflow-x:auto;font-size:13px;">{{.IntermediateCert}}</pre>
{{- if .IsTrial}}
<p>This token is valid for {{.ValidityDays}} days. To continue using Pro features after the trial, subscribe at <a href="https://pipelab.org/pricing/">pipelab.org/pricing</a>.</p>
{{- else if .IsEval}}
<p>This token is valid for {{.ValidityDays}} days. Enterprise Eval is a one-time evaluation license and is not automatically refreshed. To continue with Enterprise after the evaluation, see <a href="https://pipelab.org/pricing/">pipelab.org/pricing</a>.</p>
{{- else}}
<p>This token is valid for {{.ValidityDays}} days and will be automatically refreshed before expiration.</p>
{{- end}}
<p>Setup guide: <a href="https://pipelab.org/pipelock/guides/license-setup/">pipelab.org/pipelock/guides/license-setup</a></p>
<p>Questions? Reply to this email.</p>`))

// EmailSender handles sending license delivery and lifecycle emails
// via the Resend API.
type EmailSender struct {
	apiKey    string
	fromEmail string
	client    *http.Client
	apiURL    string // defaults to resendAPIURL; override in tests
}

// NewEmailSender creates an email sender configured with the Resend API key
// and sender address.
func NewEmailSender(apiKey, fromEmail string) *EmailSender {
	return &EmailSender{
		apiKey:    apiKey,
		fromEmail: fromEmail,
		apiURL:    resendAPIURL,
		client: &http.Client{
			Timeout: 10 * time.Second, // 10s: sufficient for Resend API
		},
	}
}

// resendRequest is the payload sent to the Resend API.
type resendRequest struct {
	From    string   `json:"from"`
	To      []string `json:"to"`
	Subject string   `json:"subject"`
	HTML    string   `json:"html"`
}

// resendResponse is the response from the Resend API.
type resendResponse struct {
	ID string `json:"id"`
}

// tierDisplayName returns a human-readable display name for a tier.
func tierDisplayName(tier string) string {
	switch tier {
	case tierFoundingPro:
		return "Founding Pro"
	case tierTrial:
		return "Pro Trial"
	case tierPro:
		return "Pro"
	case tierEnterprise:
		return "Enterprise"
	case tierEnterpriseEval:
		return "Enterprise Eval"
	default:
		return tier
	}
}

// SendLicenseDelivery sends the license token to the customer via email.
// Returns the Resend message ID on success.
func (e *EmailSender) SendLicenseDelivery(ctx context.Context, to, licenseToken, tier, intermediateCert string) (string, error) {
	displayName := tierDisplayName(tier)
	subject := fmt.Sprintf("Your Pipelock %s License", displayName)

	// Validity days are derived from the same lifetime constants the issuer uses,
	// so the email copy can never drift from the actual token lifetime.
	data := licenseEmailData{DisplayName: displayName, Token: licenseToken, IntermediateCert: intermediateCert}
	switch tier {
	case tierTrial:
		data.IsTrial = true
		data.ValidityDays = int(trialTokenLifetime.Hours()) / hoursPerDay
	case tierEnterpriseEval:
		data.IsEval = true
		data.ValidityDays = int(evalTokenLifetime.Hours()) / hoursPerDay
	default:
		data.ValidityDays = int(tokenLifetime.Hours()) / hoursPerDay
	}

	var buf bytes.Buffer
	if err := licenseEmailTmpl.Execute(&buf, data); err != nil {
		return "", fmt.Errorf("render license email: %w", err)
	}

	return e.send(ctx, to, subject, buf.String())
}

// SendSubscriptionEnded notifies the customer that their subscription
// has ended and their license will expire at the given time.
func (e *EmailSender) SendSubscriptionEnded(ctx context.Context, to string, expiresAt time.Time) (string, error) {
	subject := "Pipelock Subscription Ended"
	html := fmt.Sprintf(`<h2>Subscription Ended</h2>
<p>Your Pipelock subscription has been canceled or expired.</p>
<p>Your current license token remains valid until <strong>%s</strong>.
After that date, enterprise features will be disabled but Pipelock's
core security scanning continues to work.</p>
<p>To resubscribe: <a href="https://pipelab.org/pricing/">pipelab.org/pricing</a></p>`,
		expiresAt.UTC().Format("January 2, 2006"))

	return e.send(ctx, to, subject, html)
}

// send performs the actual Resend API call.
func (e *EmailSender) send(ctx context.Context, to, subject, html string) (string, error) {
	reqBody := resendRequest{
		From:    e.fromEmail,
		To:      []string{to},
		Subject: subject,
		HTML:    html,
	}

	payload, err := json.Marshal(reqBody)
	if err != nil {
		return "", fmt.Errorf("marshal email request: %w", err)
	}

	apiURL := e.apiURL
	if apiURL == "" {
		apiURL = resendAPIURL
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, apiURL, bytes.NewReader(payload))
	if err != nil {
		return "", fmt.Errorf("create email request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+e.apiKey)
	req.Header.Set("Content-Type", "application/json")

	resp, err := e.client.Do(req)
	if err != nil {
		return "", fmt.Errorf("send email: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	// Cap response body to prevent memory exhaustion.
	const maxResponseBody = 64 * 1024 // 64 KiB: generous for Resend response
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBody+1))
	if err != nil {
		return "", fmt.Errorf("read email response: %w", err)
	}
	if len(body) > maxResponseBody {
		return "", fmt.Errorf("read email response: exceeds %d bytes", maxResponseBody)
	}

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("resend API returned %d: %s", resp.StatusCode, string(body))
	}

	var result resendResponse
	if err := decodeVendorJSON(body, &result); err != nil {
		return "", fmt.Errorf("parse email response: %w", err)
	}

	return result.ID, nil
}
