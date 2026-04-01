package alerting

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"
)

// Event types — used in webhook Events filter and Event.Type field.
const (
	EventHardBlock   = "hard_block"
	EventSoftBlock   = "soft_block"
	EventIPBlocked   = "ip_blocked"
	EventUnderAttack = "under_attack"
	EventAttackOff   = "attack_off"
	EventCaptchaFail = "captcha_fail"
	EventAdaptive    = "adaptive"
)

const (
	retryDelay      = 5 * time.Second
	maxBurstPerHook = 10 // max alerts per MinInterval per webhook (burst protection)
)

// Event represents an alerting event.
type Event struct {
	Type      string  `json:"type"`
	Message   string  `json:"message"`
	Service   string  `json:"service,omitempty"`
	Instance  string  `json:"instance,omitempty"`
	IP        string  `json:"ip,omitempty"`
	Country   string  `json:"country,omitempty"`
	ASN       string  `json:"asn,omitempty"`
	Score     float64 `json:"score,omitempty"`
	Rule      string  `json:"rule,omitempty"`
	RequestID string  `json:"requestId,omitempty"`
	Time      string  `json:"time"`
}

// Sender is the interface for sending alerts. Used by other packages to avoid import cycles.
type Sender interface {
	Send(ctx context.Context, event Event)
}

// Webhook defines a webhook endpoint.
type Webhook struct {
	URL         string
	Events      []string
	MinInterval time.Duration
}

// Alerter dispatches events to configured webhooks.
type Alerter struct {
	webhooks    []Webhook
	serviceName string
	instance    string
	logger      *slog.Logger
	client      *http.Client

	mu       sync.Mutex
	lastSent map[string]time.Time
	burstCnt map[string]int
	wg       sync.WaitGroup
}

// New creates a new Alerter.
func New(webhooks []Webhook, serviceName string, logger *slog.Logger) *Alerter {
	hostname, _ := os.Hostname()

	return &Alerter{
		webhooks:    webhooks,
		serviceName: serviceName,
		instance:    hostname,
		logger:      logger,
		client:      &http.Client{Timeout: 10 * time.Second},
		lastSent:    make(map[string]time.Time),
		burstCnt:    make(map[string]int),
	}
}

// Send dispatches an event to matching webhooks.
func (a *Alerter) Send(ctx context.Context, event Event) {
	if event.Time == "" {
		event.Time = time.Now().Format(time.RFC3339)
	}

	if event.Service == "" {
		event.Service = a.serviceName
	}

	if event.Instance == "" {
		event.Instance = a.instance
	}

	for i := range a.webhooks {
		wh := &a.webhooks[i]

		if !a.matchesEvent(wh, event.Type) {
			continue
		}

		if !a.shouldSend(wh, event.Type) {
			continue
		}

		a.wg.Add(1)

		go func() {
			defer a.wg.Done()
			a.dispatch(context.Background(), wh, event)
		}()
	}
}

func (a *Alerter) matchesEvent(wh *Webhook, eventType string) bool {
	if len(wh.Events) == 0 {
		return true // no filter = all events
	}

	for _, e := range wh.Events {
		if e == eventType {
			return true
		}
	}

	return false
}

func (a *Alerter) shouldSend(wh *Webhook, eventType string) bool {
	key := wh.URL + ":" + eventType

	a.mu.Lock()
	defer a.mu.Unlock()

	now := time.Now()

	if last, ok := a.lastSent[key]; ok {
		if now.Sub(last) < wh.MinInterval {
			// burst protection
			if a.burstCnt[key] >= maxBurstPerHook {
				return false
			}

			a.burstCnt[key]++

			return true
		}

		// interval passed — reset burst counter
		a.burstCnt[key] = 0
	}

	a.lastSent[key] = now
	a.burstCnt[key] = 1

	// cleanup old entries (keep map bounded)
	if len(a.lastSent) > 1000 {
		for k, t := range a.lastSent {
			if now.Sub(t) > time.Hour {
				delete(a.lastSent, k)
				delete(a.burstCnt, k)
			}
		}
	}

	return true
}

func (a *Alerter) dispatch(ctx context.Context, wh *Webhook, event Event) {
	if err := a.doPost(ctx, wh.URL, event); err != nil {
		a.logger.WarnContext(ctx, "alerting: send failed, retrying",
			"url", wh.URL, "event", event.Type, "err", err)

		// single retry after delay
		time.Sleep(retryDelay)

		if err := a.doPost(ctx, wh.URL, event); err != nil {
			a.logger.ErrorContext(ctx, "alerting: send failed after retry",
				"url", wh.URL, "event", event.Type, "err", err)
		}
	}
}

var eventEmoji = map[string]string{
	EventHardBlock:   "\xf0\x9f\x9b\x91",         // 🛑
	EventSoftBlock:   "\xe2\x9a\xa0\xef\xb8\x8f", // ⚠️
	EventIPBlocked:   "\xf0\x9f\x9a\xab",         // 🚫
	EventUnderAttack: "\xf0\x9f\x94\xa5",         // 🔥
	EventAttackOff:   "\xe2\x9c\x85",             // ✅
	EventCaptchaFail: "\xf0\x9f\xa4\x96",         // 🤖
	EventAdaptive:    "\xf0\x9f\x93\x8a",         // 📊
}

// formatPayload returns Slack/Mattermost-compatible {"text": "..."} JSON.
func formatPayload(event Event) ([]byte, error) {
	emoji := eventEmoji[event.Type]
	if emoji == "" {
		emoji = "\xe2\x84\xb9\xef\xb8\x8f" // ℹ️
	}

	// line 1: emoji + type + message
	title := fmt.Sprintf("%s **%s** — %s", emoji, event.Type, event.Message)

	// line 2: details
	var details []string

	if event.IP != "" {
		details = append(details, "IP: "+event.IP+formatGeo(event.Country, event.ASN))
	}

	if event.Score > 0 {
		details = append(details, fmt.Sprintf("Score: %.0f", event.Score))
	}

	if event.Service != "" {
		svc := event.Service
		if event.Instance != "" {
			svc += "/" + event.Instance
		}
		details = append(details, svc)
	}

	text := title
	if len(details) > 0 {
		text += "\n> " + strings.Join(details, " · ")
	}

	payload := struct {
		Text string `json:"text"`
	}{Text: text}

	return json.Marshal(payload)
}

func formatGeo(country, asn string) string {
	if country == "" && asn == "" {
		return ""
	}

	geo := country
	if asn != "" {
		if geo != "" {
			geo += ", "
		}

		geo += asn
	}

	return " (" + geo + ")"
}

func (a *Alerter) doPost(ctx context.Context, url string, event Event) error {
	body, err := formatPayload(event)
	if err != nil {
		return fmt.Errorf("alerting: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	if err != nil {
		return fmt.Errorf("alerting: request: %w", err)
	}

	req.Header.Set("Content-Type", "application/json")

	resp, err := a.client.Do(req)
	if err != nil {
		return fmt.Errorf("alerting: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode >= http.StatusInternalServerError {
		return fmt.Errorf("alerting: server error %d", resp.StatusCode)
	}

	if resp.StatusCode >= http.StatusBadRequest {
		a.logger.WarnContext(ctx, "alerting: client error", "url", url, "status", resp.StatusCode)
	}

	return nil
}

// Shutdown waits for all pending webhook dispatches to complete.
func (a *Alerter) Shutdown() {
	a.wg.Wait()
}
