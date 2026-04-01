package ip

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"sync"
	"time"

	"github.com/vmkteam/embedlog"
)

const (
	feedFireHOLLevel1 = "firehol_l1"
	feedFireHOLLevel2 = "firehol_l2"
	feedTorExits      = "tor_exits"

	maxFeedBodySize        = 10 << 20 // 10MB
	reputationCaptchaScore = 5.0

	// Actions for reputation feeds.
	FeedActionScore   = "score"
	FeedActionCaptcha = "captcha"
	FeedActionBlock   = "block"
)

// FireHOL aggregated blacklists (GitHub raw).
var fireHOLURLs = map[int]string{
	1: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level1.netset",
	2: "https://raw.githubusercontent.com/firehol/blocklist-ipsets/master/firehol_level2.netset",
}

// Tor exit node list (official Tor Project bulk exit list).
var torExitNodeURL = "https://check.torproject.org/torbulkexitlist?ip=1.1.1.1"

// defaultDatacenterASNs contains ASNs of major hosting/cloud providers.
var defaultDatacenterASNs = map[uint32]struct{}{
	// AWS
	14618: {}, 16509: {}, 8987: {},
	// Google Cloud
	15169: {}, 396982: {},
	// Azure
	8075: {}, 8068: {},
	// DigitalOcean
	14061: {},
	// Hetzner
	24940: {},
	// OVH
	16276: {},
	// Vultr
	20473: {},
	// Linode (Akamai)
	63949: {},
	// Scaleway
	12876: {},
	// Contabo
	40021: {},
	// Oracle Cloud
	31898: {},
	// Alibaba Cloud
	45102: {},
	// Tencent Cloud
	132203: {},
	// Yandex Cloud
	200350: {},
	// Selectel
	49505: {},
	// Kamatera
	36007: {},
	// HostGator / Endurance
	46606: {},
	// GoDaddy
	26496: {},
	// Cloudflare (workers/pages can be abused)
	13335: {},
}

// ReputationResult holds the result of an IP reputation check.
type ReputationResult struct {
	Listed bool     // IP found in at least one feed
	Feeds  []string // which feeds matched
	Action string   // most severe action: "block" > "captcha" > "score"
	Score  float64  // total score adjustment
}

// FeedStats holds statistics for a single feed.
type FeedStats struct {
	Name    string
	Count   int
	Updated time.Time
}

// Reputation manages dynamic IP reputation feeds.
type Reputation struct {
	embedlog.Logger
	cfg    ReputationConfig
	mu     sync.RWMutex
	feeds  map[string]*feedData
	dcASNs map[uint32]struct{}
	client *http.Client
}

// feedData holds parsed IP addresses from a single feed.
type feedData struct {
	name     string
	action   string  // "score" | "captcha" | "block"
	score    float64 // score adjustment for "score" action
	addrs    map[netip.Addr]struct{}
	prefixes []netip.Prefix
	updated  time.Time
}

// NewReputation creates a new reputation service.
func NewReputation(cfg ReputationConfig, sl embedlog.Logger) *Reputation {
	r := &Reputation{
		Logger: sl,
		cfg:    cfg,
		feeds:  make(map[string]*feedData),
		dcASNs: make(map[uint32]struct{}, len(defaultDatacenterASNs)+len(cfg.Datacenter.ExtraASNs)),
		client: &http.Client{Timeout: 30 * time.Second},
	}

	// populate datacenter ASNs
	if cfg.Datacenter.Enabled {
		for asn := range defaultDatacenterASNs {
			r.dcASNs[asn] = struct{}{}
		}

		for _, asn := range cfg.Datacenter.ExtraASNs {
			r.dcASNs[asn] = struct{}{}
		}
	}

	return r
}

// Start loads all feeds immediately and refreshes on UpdateInterval.
// Blocks until ctx is cancelled.
func (r *Reputation) Start(ctx context.Context) {
	r.refreshAll(ctx)

	ticker := time.NewTicker(r.cfg.UpdateInterval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			r.refreshAll(ctx)
		}
	}
}

// Check returns reputation result for an IP address.
func (r *Reputation) Check(addr netip.Addr) ReputationResult {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var result ReputationResult

	for _, fd := range r.feeds {
		if !fd.contains(addr) {
			continue
		}

		result.Listed = true
		result.Feeds = append(result.Feeds, fd.name)
		result.Score += fd.score
		result.Action = moreSevereAction(result.Action, fd.action)
	}

	return result
}

// CheckASN returns whether ASN belongs to a known datacenter/hosting provider.
func (r *Reputation) CheckASN(asn uint32) bool {
	if asn == 0 {
		return false
	}

	_, ok := r.dcASNs[asn]
	return ok
}

// Stats returns feed statistics.
func (r *Reputation) Stats() []FeedStats {
	r.mu.RLock()
	defer r.mu.RUnlock()

	stats := make([]FeedStats, 0, len(r.feeds))
	for _, fd := range r.feeds {
		stats = append(stats, FeedStats{
			Name:    fd.name,
			Count:   len(fd.addrs) + len(fd.prefixes),
			Updated: fd.updated,
		})
	}

	return stats
}

// refreshAll downloads and parses all configured feeds concurrently.
func (r *Reputation) refreshAll(ctx context.Context) {
	type feedJob struct {
		name, url, action string
		score             float64
	}

	var jobs []feedJob

	if r.cfg.FireHOL.Enabled {
		if url, ok := fireHOLURLs[r.cfg.FireHOL.Level]; ok {
			name := feedFireHOLLevel1
			if r.cfg.FireHOL.Level == 2 {
				name = feedFireHOLLevel2
			}

			jobs = append(jobs, feedJob{name, url, FeedActionScore, r.cfg.ScoreAdjustment})
		}
	}

	if r.cfg.Tor.Enabled {
		jobs = append(jobs, feedJob{feedTorExits, torExitNodeURL, r.cfg.Tor.Action, r.cfg.ScoreAdjustment})
	}

	for _, f := range r.cfg.Feeds {
		name := f.Name
		if name == "" {
			name = f.URL
		}

		jobs = append(jobs, feedJob{name, f.URL, f.Action, r.cfg.ScoreAdjustment})
	}

	var wg sync.WaitGroup
	wg.Add(len(jobs))

	for _, j := range jobs {
		go func() {
			defer wg.Done()
			r.loadFeed(ctx, j.name, j.url, j.action, j.score)
		}()
	}

	wg.Wait()
}

func (r *Reputation) loadFeed(ctx context.Context, name, url, action string, score float64) {
	start := time.Now()

	addrs, prefixes, err := parseFeed(ctx, r.client, url)
	if err != nil {
		r.Print(ctx, "reputation_fetch_error", "feed", name, "error", err.Error())
		return
	}

	fd := &feedData{
		name:     name,
		action:   action,
		score:    score,
		addrs:    addrs,
		prefixes: prefixes,
		updated:  time.Now(),
	}

	r.mu.Lock()
	r.feeds[name] = fd
	r.mu.Unlock()

	r.Print(ctx, "reputation_loaded",
		"feed", name,
		"count", len(fd.addrs)+len(fd.prefixes),
		"durationMs", time.Since(start).Milliseconds(),
	)
}

// parseFeed downloads and parses an IP list from URL.
// Supports: one IP/CIDR per line, # comments, ; comments, empty lines.
func parseFeed(ctx context.Context, client *http.Client, url string) (map[netip.Addr]struct{}, []netip.Prefix, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil, nil, fmt.Errorf("reputation: %w", err)
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, fmt.Errorf("reputation: fetch %s: %w", url, err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, nil, fmt.Errorf("reputation: fetch %s: status %d", url, resp.StatusCode)
	}

	body := io.LimitReader(resp.Body, maxFeedBodySize)

	addrs := make(map[netip.Addr]struct{})
	var prefixes []netip.Prefix

	scanner := bufio.NewScanner(body)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || line[0] == '#' || line[0] == ';' {
			continue
		}

		// try CIDR
		if strings.Contains(line, "/") {
			if prefix, err := netip.ParsePrefix(line); err == nil {
				prefixes = append(prefixes, prefix)
			}

			continue
		}

		// try single IP
		if addr, err := netip.ParseAddr(line); err == nil {
			addrs[addr] = struct{}{}
		}
	}

	if err := scanner.Err(); err != nil {
		return nil, nil, fmt.Errorf("reputation: scan %s: %w", url, err)
	}

	return addrs, prefixes, nil
}

func (fd *feedData) contains(addr netip.Addr) bool {
	if _, ok := fd.addrs[addr]; ok {
		return true
	}

	for _, p := range fd.prefixes {
		if p.Contains(addr) {
			return true
		}
	}

	return false
}

// actionSeverity returns severity rank (higher = more severe).
func actionSeverity(action string) int {
	switch action {
	case FeedActionBlock:
		return 3
	case FeedActionCaptcha:
		return 2
	case FeedActionScore:
		return 1
	default:
		return 0
	}
}

func moreSevereAction(a, b string) string {
	if actionSeverity(b) > actionSeverity(a) {
		return b
	}

	return a
}
