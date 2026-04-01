package dashboard

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"wafsrv/internal/waf/event"
	"wafsrv/internal/waf/ip"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/stretchr/testify/suite"
	"github.com/vmkteam/embedlog"
)

type DashboardSuite struct {
	suite.Suite
	server *httptest.Server
	ipSvc  *ip.Service
}

func TestDashboard(t *testing.T) {
	suite.Run(t, new(DashboardSuite))
}

func (s *DashboardSuite) SetupTest() {
	var err error
	s.ipSvc, err = ip.New(ip.Config{}, embedlog.NewLogger(false, false), ip.Metrics{
		BlockedTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "test_blocked_total",
			Help: "test",
		}, []string{"reason"}),
		WhitelistedTotal: prometheus.NewCounter(prometheus.CounterOpts{
			Name: "test_whitelisted_total",
			Help: "test",
		}),
	})
	s.Require().NoError(err)

	rpcServer := New(s.ipSvc, StatusInfo{
		Service:          "test-svc",
		Targets:          []string{"http://localhost:3000"},
		Listen:           ":8080",
		WAFEnabled:       true,
		WAFMode:          "blocking",
		WAFParanoiaLevel: 1,
		RateLimitEnabled: true,
		RateLimitPerIP:   "100/min",
		RateLimitRules: []RuleInfo{
			{Name: "login", Match: []string{"auth.login"}, Limit: "10/min", Action: "block"},
		},
		StartedAt: time.Now(),
	}, nil, NewAttackService(), event.NewRecorder(
		event.NewBuffer(100),
		event.NewSeries(time.Second, 10),
		event.NewTops(5*time.Minute, 100),
	), nil, ConfigResponse{})

	s.server = httptest.NewServer(rpcServer)
}

func (s *DashboardSuite) TearDownTest() {
	s.server.Close()
}

// --- status.get ---

func (s *DashboardSuite) TestStatusGet() {
	result := s.rpc("status.get", "{}")

	s.Contains(result, "test-svc")
	s.Contains(result, "uptimeSeconds")
	s.Contains(result, `"wafEnabled":true`)
	s.Contains(result, `"wafMode":"blocking"`)
	s.Contains(result, `"rateLimitEnabled":true`)
}

// --- block.add ---

func (s *DashboardSuite) TestBlockAddIP() {
	result := s.rpc("block.add", `{"blockType":"ip","value":"1.2.3.4","reason":"test","duration":""}`)
	s.Contains(result, `"result":true`)

	entries := s.ipSvc.ListBlocks("ip")
	s.Require().Len(entries, 1)
	s.Equal("1.2.3.4", entries[0].Value)
	s.Equal("test", entries[0].Reason)
}

func (s *DashboardSuite) TestBlockAddCIDR() {
	result := s.rpc("block.add", `{"blockType":"cidr","value":"10.0.0.0/8","reason":"subnet","duration":""}`)
	s.Contains(result, `"result":true`)

	entries := s.ipSvc.ListBlocks("cidr")
	s.Require().Len(entries, 1)
	s.Equal("10.0.0.0/8", entries[0].Value)
}

func (s *DashboardSuite) TestBlockAddCountry() {
	result := s.rpc("block.add", `{"blockType":"country","value":"CN","reason":"policy","duration":""}`)
	s.Contains(result, `"result":true`)

	entries := s.ipSvc.ListBlocks("country")
	s.Require().Len(entries, 1)
	s.Equal("CN", entries[0].Value)
	s.Equal("policy", entries[0].Reason)
}

func (s *DashboardSuite) TestBlockAddWithDuration() {
	result := s.rpc("block.add", `{"blockType":"ip","value":"3.3.3.3","reason":"temp","duration":"1h"}`)
	s.Contains(result, `"result":true`)

	entries := s.ipSvc.ListBlocks("ip")
	s.Require().Len(entries, 1)
	s.False(entries[0].ExpiresAt.IsZero(), "should have expiry")
}

func (s *DashboardSuite) TestBlockAddInvalidType() {
	result := s.rpc("block.add", `{"blockType":"invalid","value":"x","reason":"","duration":""}`)
	s.Contains(result, "error")
}

func (s *DashboardSuite) TestBlockAddInvalidIP() {
	result := s.rpc("block.add", `{"blockType":"ip","value":"not-ip","reason":"","duration":""}`)
	s.Contains(result, "error")
}

func (s *DashboardSuite) TestBlockAddInvalidDuration() {
	result := s.rpc("block.add", `{"blockType":"ip","value":"1.1.1.1","reason":"","duration":"bad"}`)
	s.Contains(result, "error")
}

// --- block.remove ---

func (s *DashboardSuite) TestBlockRemoveIP() {
	s.rpc("block.add", `{"blockType":"ip","value":"4.4.4.4","reason":"","duration":""}`)

	result := s.rpc("block.remove", `{"blockType":"ip","value":"4.4.4.4"}`)
	s.Contains(result, `"result":true`)

	entries := s.ipSvc.ListBlocks("ip")
	s.Empty(entries)
}

func (s *DashboardSuite) TestBlockRemoveCIDR() {
	s.rpc("block.add", `{"blockType":"cidr","value":"172.16.0.0/12","reason":"","duration":""}`)

	result := s.rpc("block.remove", `{"blockType":"cidr","value":"172.16.0.0/12"}`)
	s.Contains(result, `"result":true`)

	entries := s.ipSvc.ListBlocks("cidr")
	s.Empty(entries)
}

func (s *DashboardSuite) TestBlockRemoveCountry() {
	s.rpc("block.add", `{"blockType":"country","value":"KP","reason":"","duration":""}`)

	result := s.rpc("block.remove", `{"blockType":"country","value":"KP"}`)
	s.Contains(result, `"result":true`)

	entries := s.ipSvc.ListBlocks("country")
	s.Empty(entries)
}

// --- block.list ---

func (s *DashboardSuite) TestBlockListIP() {
	s.rpc("block.add", `{"blockType":"ip","value":"5.5.5.5","reason":"r1","duration":""}`)
	s.rpc("block.add", `{"blockType":"ip","value":"6.6.6.6","reason":"r2","duration":"1h"}`)

	result := s.rpc("block.list", `{"blockType":"ip"}`)

	var resp struct {
		Result []BlockEntry `json:"result"`
	}
	s.Require().NoError(json.Unmarshal([]byte(result), &resp))
	s.Len(resp.Result, 2)

	// check fields
	for _, e := range resp.Result {
		s.Equal("ip", e.Type)
		s.NotEmpty(e.Value)
		s.NotEmpty(e.AddedAt)
	}
}

func (s *DashboardSuite) TestBlockListEmpty() {
	result := s.rpc("block.list", `{"blockType":"ip"}`)

	var resp struct {
		Result []BlockEntry `json:"result"`
	}
	s.Require().NoError(json.Unmarshal([]byte(result), &resp))
	s.Empty(resp.Result)
}

func (s *DashboardSuite) TestBlockListInvalidType() {
	result := s.rpc("block.list", `{"blockType":"invalid"}`)
	s.Contains(result, "error")
}

// --- status.rules ---

func (s *DashboardSuite) TestStatusRules() {
	result := s.rpc("status.rules", "{}")
	s.Contains(result, "login")
	s.Contains(result, "auth.login")
	s.Contains(result, "10/min")
}

// --- attack ---

func (s *DashboardSuite) TestAttackEnableDisableViaRPC() {
	// enable via RPC
	result := s.rpc("attack.enable", `{"duration":"5m"}`)
	s.Contains(result, `"enabled":true`)

	// status persists after F5 (new RPC call)
	result = s.rpc("attack.status", "{}")
	s.Contains(result, `"enabled":true`, "state should persist across RPC calls")

	// disable
	result = s.rpc("attack.disable", "{}")
	s.Contains(result, `"enabled":false`)

	// verify disabled
	result = s.rpc("attack.status", "{}")
	s.Contains(result, `"enabled":false`)
}

func (s *DashboardSuite) TestAttackEnableNoDuration() {
	svc := NewAttackService()

	st, err := svc.Enable(context.Background(), "")
	s.Require().NoError(err)
	s.True(st.Enabled)
	s.Empty(st.ExpiresAt)
}

func (s *DashboardSuite) TestAttackIsEnabled() {
	svc := NewAttackService()

	s.False(svc.IsEnabled())

	svc.Enable(context.Background(), "")
	s.True(svc.IsEnabled())

	svc.Disable(context.Background())
	s.False(svc.IsEnabled())
}

// --- helpers ---

func (s *DashboardSuite) rpc(method, params string) string {
	s.T().Helper()

	body := fmt.Sprintf(`{"jsonrpc":"2.0","method":"%s","params":%s,"id":1}`, method, params)
	resp, err := http.Post(s.server.URL, "application/json", strings.NewReader(body))
	s.Require().NoError(err)
	defer resp.Body.Close()

	result, err := io.ReadAll(resp.Body)
	s.Require().NoError(err)

	return string(result)
}
