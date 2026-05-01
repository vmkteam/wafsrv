package alerting

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestFormatPayload(t *testing.T) {
	tests := []struct {
		name     string
		event    Event
		expected string
	}{
		{
			name: "soft_block with IP and service",
			event: Event{
				Type:     EventSoftBlock,
				Message:  "escalation: 3 captcha failures -> soft block 5m0s",
				IP:       "127.0.0.1::ba2a9c87",
				Service:  "pgdesigner",
				Instance: "VMKTEAM10-3.local",
			},
			expected: "\xe2\x9a\xa0\xef\xb8\x8f **soft_block** — escalation: 3 captcha failures -> soft block 5m0s · IP: 127.0.0.1::ba2a9c87 · pgdesigner/VMKTEAM10-3.local",
		},
		{
			name: "hard_block with full details",
			event: Event{
				Type:    EventHardBlock,
				Message: "WAF score exceeded",
				IP:      "1.2.3.4",
				Country: "CN",
				ASN:     "AS4134",
				Score:   10,
				Service: "api",
			},
			expected: "\xf0\x9f\x9b\x91 **hard_block** — WAF score exceeded · IP: 1.2.3.4 (CN, AS4134) · Score: 10 · api",
		},
		{
			name: "hard_block with country only",
			event: Event{
				Type:    EventHardBlock,
				Message: "blocked",
				IP:      "1.2.3.4",
				Country: "RU",
				Score:   8,
			},
			expected: "\xf0\x9f\x9b\x91 **hard_block** — blocked · IP: 1.2.3.4 (RU) · Score: 8",
		},
		{
			name: "under_attack no IP",
			event: Event{
				Type:     EventUnderAttack,
				Message:  "RPS threshold exceeded",
				Service:  "api",
				Instance: "node1",
			},
			expected: "\xf0\x9f\x94\xa5 **under_attack** — RPS threshold exceeded · api/node1",
		},
		{
			name: "attack_off minimal",
			event: Event{
				Type:    EventAttackOff,
				Message: "attack ended",
			},
			expected: "\xe2\x9c\x85 **attack_off** — attack ended",
		},
		{
			name: "unknown type uses info emoji",
			event: Event{
				Type:    "custom",
				Message: "something happened",
			},
			expected: "\xe2\x84\xb9\xef\xb8\x8f **custom** — something happened",
		},
		{
			name: "ip_blocked with ASN only",
			event: Event{
				Type:    EventIPBlocked,
				Message: "manual block",
				IP:      "10.0.0.1",
				ASN:     "AS13335",
			},
			expected: "\xf0\x9f\x9a\xab **ip_blocked** — manual block · IP: 10.0.0.1 (AS13335)",
		},
		{
			name: "service without instance",
			event: Event{
				Type:    EventCaptchaFail,
				Message: "captcha failed",
				Service: "myapi",
			},
			expected: "\xf0\x9f\xa4\x96 **captcha_fail** — captcha failed · myapi",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			body, err := formatPayload(tt.event)
			require.NoError(t, err)

			var payload struct {
				Text string `json:"text"`
			}
			require.NoError(t, json.Unmarshal(body, &payload))
			assert.Equal(t, tt.expected, payload.Text)
		})
	}
}

func TestFormatGeo(t *testing.T) {
	tests := []struct {
		country, asn string
		expected     string
	}{
		{"", "", ""},
		{"RU", "", " (RU)"},
		{"", "AS4134", " (AS4134)"},
		{"CN", "AS4134", " (CN, AS4134)"},
	}

	for _, tt := range tests {
		t.Run(tt.country+"_"+tt.asn, func(t *testing.T) {
			assert.Equal(t, tt.expected, formatGeo(tt.country, tt.asn))
		})
	}
}
