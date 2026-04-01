package ip

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/netip"
	"sync"
	"time"

	"github.com/vmkteam/embedlog"
)

// BotRanges stores IP CIDR ranges for known bots, refreshed periodically.
type BotRanges struct {
	mu     sync.RWMutex
	ranges map[string][]netip.Prefix // botName → CIDRs
	client *http.Client
	logger embedlog.Logger
}

// NewBotRanges creates a new BotRanges store.
func NewBotRanges(logger embedlog.Logger) *BotRanges {
	return &BotRanges{
		ranges: make(map[string][]netip.Prefix),
		client: &http.Client{Timeout: 30 * time.Second},
		logger: logger,
	}
}

// Start loads ranges immediately and refreshes them on the given interval.
// Blocks until ctx is cancelled.
func (r *BotRanges) Start(ctx context.Context, bots []KnownBot, refresh time.Duration) {
	r.refreshAll(bots)

	ticker := time.NewTicker(refresh)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.refreshAll(bots)
		}
	}
}

// Contains checks if ip belongs to any known bot's IP ranges.
func (r *BotRanges) Contains(ip netip.Addr) (botName string, ok bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	for name, prefixes := range r.ranges {
		for _, p := range prefixes {
			if p.Contains(ip) {
				return name, true
			}
		}
	}

	return "", false
}

func (r *BotRanges) refreshAll(bots []KnownBot) {
	for _, bot := range bots {
		if bot.RangesURL == "" {
			continue
		}

		prefixes, err := r.fetchRanges(bot.RangesURL)
		if err != nil {
			r.logger.Print(context.Background(), "bot_ranges_refresh",
				"bot", bot.Name,
				"error", err.Error(),
				"status", "error",
			)

			continue
		}

		r.mu.Lock()
		r.ranges[bot.Name] = prefixes
		r.mu.Unlock()

		r.logger.Print(context.Background(), "bot_ranges_refresh",
			"bot", bot.Name,
			"prefixes", len(prefixes),
			"status", "success",
		)
	}
}

type rangesResponse struct {
	Prefixes []rangesPrefix `json:"prefixes"`
}

type rangesPrefix struct {
	IPv4 string `json:"ipv4Prefix"`
	IPv6 string `json:"ipv6Prefix"`
}

func (r *BotRanges) fetchRanges(url string) ([]netip.Prefix, error) {
	resp, err := r.client.Get(url) //nolint:noctx // background refresh, no request context
	if err != nil {
		return nil, fmt.Errorf("botranges: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("botranges: fetch %s: status %d", url, resp.StatusCode)
	}

	var data rangesResponse
	if err := json.NewDecoder(resp.Body).Decode(&data); err != nil {
		return nil, fmt.Errorf("botranges: decode %s: %w", url, err)
	}

	prefixes := make([]netip.Prefix, 0, len(data.Prefixes))
	for _, p := range data.Prefixes {
		cidr := p.IPv4
		if cidr == "" {
			cidr = p.IPv6
		}

		if cidr == "" {
			continue
		}

		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			continue
		}

		prefixes = append(prefixes, prefix)
	}

	return prefixes, nil
}
