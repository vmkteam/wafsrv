package event

import (
	"sync"
	"sync/atomic"
	"time"
)

// Point represents metrics for a single time interval.
type Point struct {
	Time         int64 `json:"time"`     // unix timestamp
	Incoming     int64 `json:"incoming"` // total requests entering pipeline
	Requests     int64 `json:"requests"` // requests reaching backend
	Blocked      int64 `json:"blocked"`
	Filtered     int64 `json:"filtered"`
	RateLimited  int64 `json:"rateLimited"`
	Captcha      int64 `json:"captcha"`
	CaptchaPass  int64 `json:"captchaPass"`
	WAFMatches   int64 `json:"wafMatches"`
	SignInvalid  int64 `json:"signInvalid"`
	Errors5xx    int64 `json:"errors5xx"`
	LatencyUs    int64 `json:"latencyUs"`    // sum of response latencies (microseconds)
	LatencyCount int64 `json:"latencyCount"` // number of responses
	LatencyMaxUs int64 `json:"latencyMaxUs"` // max response latency (microseconds)
	BytesSent    int64 `json:"bytesSent"`    // total response bytes
}

// Series stores time series metrics in a ring buffer with fixed intervals.
type Series struct {
	mu       sync.Mutex
	points   []Point
	size     int
	pos      int
	full     bool
	interval time.Duration
	lastTick int64 // unix timestamp of current slot

	// atomic counters for current interval (hot path, no mutex)
	curIncoming     atomic.Int64
	curRequests     atomic.Int64
	curBlocked      atomic.Int64
	curFiltered     atomic.Int64
	curRateLimited  atomic.Int64
	curCaptcha      atomic.Int64
	curCaptchaPass  atomic.Int64
	curWAFMatches   atomic.Int64
	curSignInvalid  atomic.Int64
	curErrors5xx    atomic.Int64
	curLatencyUs    atomic.Int64
	curLatencyCount atomic.Int64
	curLatencyMaxUs atomic.Int64
	curBytesSent    atomic.Int64
}

// NewSeries creates a new time series with the given interval and capacity.
// interval=5s, size=360 → 30 minutes of history.
func NewSeries(interval time.Duration, size int) *Series {
	if size <= 0 {
		size = 360
	}

	if interval <= 0 {
		interval = 5 * time.Second
	}

	return &Series{
		points:   make([]Point, size),
		size:     size,
		interval: interval,
	}
}

// RecordIncoming records an incoming request before any blocking middleware.
func (s *Series) RecordIncoming() {
	s.tick()
	s.curIncoming.Add(1)
}

// RecordRequest records a proxied request that reached the backend.
func (s *Series) RecordRequest(is5xx bool) {
	s.tick()
	s.curRequests.Add(1)

	if is5xx {
		s.curErrors5xx.Add(1)
	}
}

// RecordBlocked records a blocked request (IP blacklist, country).
func (s *Series) RecordBlocked() {
	s.tick()
	s.curBlocked.Add(1)
}

// RecordRateLimited records a rate-limited request.
func (s *Series) RecordRateLimited() {
	s.tick()
	s.curRateLimited.Add(1)
}

// RecordCaptcha records a captcha decision.
func (s *Series) RecordCaptcha() {
	s.tick()
	s.curCaptcha.Add(1)
}

// RecordFiltered records a traffic filter match.
func (s *Series) RecordFiltered() {
	s.tick()
	s.curFiltered.Add(1)
}

// RecordCaptchaPass records a successful captcha verification.
func (s *Series) RecordCaptchaPass() {
	s.tick()
	s.curCaptchaPass.Add(1)
}

// RecordLatency records a response latency.
func (s *Series) RecordLatency(d time.Duration) {
	us := d.Microseconds()
	s.curLatencyUs.Add(us)
	s.curLatencyCount.Add(1)

	for {
		old := s.curLatencyMaxUs.Load()
		if us <= old || s.curLatencyMaxUs.CompareAndSwap(old, us) {
			break
		}
	}
}

// RecordSignInvalid records an invalid/expired/replay signing attempt.
func (s *Series) RecordSignInvalid() {
	s.curSignInvalid.Add(1)
}

// RecordBytesSent records response bytes sent.
func (s *Series) RecordBytesSent(n int) {
	s.curBytesSent.Add(int64(n))
}

// RecordWAFMatch records a WAF rule match.
func (s *Series) RecordWAFMatch() {
	s.tick()
	s.curWAFMatches.Add(1)
}

// History returns the last n points, oldest first.
func (s *Series) History(n int) []Point {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tickLocked()

	total := s.pos
	if s.full {
		total = s.size
	}

	if n <= 0 || n > total {
		n = total
	}

	result := make([]Point, n)

	// oldest first: start from (pos - n)
	for i := range n {
		idx := (s.pos - n + i + s.size) % s.size
		result[i] = s.points[idx]
	}

	return result
}

// RPS returns the current requests per second (from last completed interval).
func (s *Series) RPS() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tickLocked()

	// use the last completed point
	if s.pos == 0 && !s.full {
		return 0
	}

	lastIdx := (s.pos - 1 + s.size) % s.size
	p := s.points[lastIdx]

	return float64(p.Requests) / s.interval.Seconds()
}

// SeriesSnapshot holds aggregated metrics for a time window.
type SeriesSnapshot struct {
	Incoming     int64
	Requests     int64
	Errors5xx    int64
	Blocked      int64
	AvgLatencyMs float64
	RPS          float64
	ErrorRate    float64 // Errors5xx / Incoming * 100
	BlockedRate  float64 // Blocked / Incoming * 100
}

// Snapshot returns aggregated metrics for the given window duration.
func (s *Series) Snapshot(window time.Duration) SeriesSnapshot {
	points := s.History(int(window.Seconds() / s.interval.Seconds()))

	var snap SeriesSnapshot
	var latencyUs, latencyCount int64

	for _, p := range points {
		snap.Incoming += p.Incoming
		snap.Requests += p.Requests
		snap.Errors5xx += p.Errors5xx
		snap.Blocked += p.Blocked
		latencyUs += p.LatencyUs
		latencyCount += p.LatencyCount
	}

	if latencyCount > 0 {
		snap.AvgLatencyMs = float64(latencyUs) / float64(latencyCount) / 1000
	}

	if len(points) > 0 {
		snap.RPS = float64(snap.Incoming) / window.Seconds()
	}

	if snap.Incoming > 0 {
		snap.ErrorRate = float64(snap.Errors5xx) / float64(snap.Incoming) * 100
		snap.BlockedRate = float64(snap.Blocked) / float64(snap.Incoming) * 100
	}

	return snap
}

// BaselineRPS returns the average RPS across all available history points.
func (s *Series) BaselineRPS() float64 {
	points := s.History(0) // all available
	if len(points) == 0 {
		return 0
	}

	var total int64
	for _, p := range points {
		total += p.Incoming
	}

	duration := float64(len(points)) * s.interval.Seconds()
	if duration == 0 {
		return 0
	}

	return float64(total) / duration
}

// tick acquires the lock and advances to the current interval.
func (s *Series) tick() {
	s.mu.Lock()
	defer s.mu.Unlock()

	s.tickLocked()
}

// tickLocked advances to the current interval, flushing accumulated counters.
// Caller must hold s.mu.
func (s *Series) tickLocked() {
	now := time.Now().Unix()
	slot := now - (now % int64(s.interval.Seconds()))

	if slot == s.lastTick {
		return
	}

	// first call
	if s.lastTick == 0 {
		s.lastTick = slot
		return
	}

	// flush current counters to the current point
	s.points[s.pos] = Point{
		Time:         s.lastTick,
		Incoming:     s.curIncoming.Swap(0),
		Requests:     s.curRequests.Swap(0),
		Blocked:      s.curBlocked.Swap(0),
		Filtered:     s.curFiltered.Swap(0),
		RateLimited:  s.curRateLimited.Swap(0),
		Captcha:      s.curCaptcha.Swap(0),
		CaptchaPass:  s.curCaptchaPass.Swap(0),
		WAFMatches:   s.curWAFMatches.Swap(0),
		SignInvalid:  s.curSignInvalid.Swap(0),
		Errors5xx:    s.curErrors5xx.Swap(0),
		LatencyUs:    s.curLatencyUs.Swap(0),
		LatencyCount: s.curLatencyCount.Swap(0),
		LatencyMaxUs: s.curLatencyMaxUs.Swap(0),
		BytesSent:    s.curBytesSent.Swap(0),
	}

	s.pos = (s.pos + 1) % s.size
	if !s.full && s.pos == 0 {
		s.full = true
	}

	// fill gaps if intervals were skipped
	for gap := s.lastTick + int64(s.interval.Seconds()); gap < slot; gap += int64(s.interval.Seconds()) {
		s.points[s.pos] = Point{Time: gap}
		s.pos = (s.pos + 1) % s.size

		if !s.full && s.pos == 0 {
			s.full = true
		}
	}

	s.lastTick = slot
}
