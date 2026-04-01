package challenge

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Captcha provider verify URLs.
const (
	TurnstileVerifyURL = "https://challenges.cloudflare.com/turnstile/v0/siteverify"
	HCaptchaVerifyURL  = "https://api.hcaptcha.com/siteverify"
)

// Verifier handles server-side captcha token verification.
// Works with any provider that uses the standard siteverify API (Turnstile, hCaptcha).
type Verifier struct {
	verifyURL string
	client    *http.Client
}

// NewVerifier creates a new captcha verifier with the given verify URL and timeout.
func NewVerifier(verifyURL string, timeout time.Duration) *Verifier {
	return &Verifier{
		verifyURL: verifyURL,
		client:    &http.Client{Timeout: timeout},
	}
}

// Verify validates a Turnstile token server-side.
func (v *Verifier) Verify(ctx context.Context, token, remoteIP, secret string) (bool, error) {
	if token == "" || secret == "" {
		return false, nil
	}

	form := url.Values{
		"secret":   {secret},
		"response": {token},
	}

	if remoteIP != "" {
		form.Set("remoteip", remoteIP)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, v.verifyURL, strings.NewReader(form.Encode()))
	if err != nil {
		return false, fmt.Errorf("challenge: %w", err)
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")

	resp, err := v.client.Do(req)
	if err != nil {
		return false, fmt.Errorf("challenge: turnstile verify: %w", err)
	}
	defer resp.Body.Close()

	var result struct {
		Success bool `json:"success"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return false, fmt.Errorf("challenge: turnstile decode: %w", err)
	}

	return result.Success, nil
}
