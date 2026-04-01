package e2e

import (
	"net/http"
	"time"
)

// --- 05: Management API ---

func (s *E2ESuite) Test05_Mgmt_Health() {
	resp := s.get(mgmtURL + "/health")
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)
	body := s.readBody(resp)
	s.Contains(body, `"status":"ok"`)
}

func (s *E2ESuite) Test05_Mgmt_Metrics() {
	body := s.getMetrics()
	s.Contains(body, "wafsrv_requests_total")
	s.Contains(body, "wafsrv_request_duration_seconds")
}

func (s *E2ESuite) Test05_Mgmt_StatusGet() {
	result := s.mgmtRPC("status.get", "{}")
	s.Contains(result, "e2e-test", "should contain service name")
	s.Contains(result, "uptimeSeconds", "should contain uptime")
	s.Contains(result, `"wafEnabled":true`)
	s.Contains(result, `"rateLimitEnabled":true`)
}

func (s *E2ESuite) Test05_Mgmt_BlockAddInvalidType() {
	result := s.mgmtRPC("block.add", `{"blockType":"invalid","value":"1.2.3.4","reason":"test"}`)
	s.Contains(result, "error")
}

func (s *E2ESuite) Test05_Mgmt_Dashboard() {
	resp := s.get(mgmtURL + "/")
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)
	body := s.readBody(resp)
	s.Contains(body, "wafsrv")
	s.Contains(body, "alpine")
}

func (s *E2ESuite) Test05_Mgmt_StatusRules() {
	result := s.mgmtRPC("status.rules", "{}")
	s.Contains(result, "slow-rpc")
}

func (s *E2ESuite) Test05_Mgmt_EventsRecent() {
	result := s.mgmtRPC("events.recent", `{"limit":10}`)
	s.Contains(result, "result")
}

func (s *E2ESuite) Test05_Mgmt_MetricsHistory() {
	result := s.mgmtRPC("metrics.history", `{"minutes":1}`)
	s.Contains(result, "result")
}

func (s *E2ESuite) Test05_Mgmt_MetricsRPS() {
	result := s.mgmtRPC("metrics.rps", "{}")
	s.Contains(result, "result")
}

func (s *E2ESuite) Test05_Mgmt_UnknownMethod() {
	result := s.mgmtRPC("nonexistent.method", "{}")
	s.Contains(result, "error")
}

// --- 08: Under Attack Mode ---

func (s *E2ESuite) Test08_Attack_EnableDisable() {
	result := s.mgmtRPC("attack.enable", `{"duration":"5m"}`)
	s.Contains(result, `"enabled":true`)

	result = s.mgmtRPC("attack.status", "{}")
	s.Contains(result, `"enabled":true`)

	result = s.mgmtRPC("attack.disable", "{}")
	s.Contains(result, `"enabled":false`)
}

func (s *E2ESuite) Test08_Attack_EnableNoDuration() {
	result := s.mgmtRPC("attack.enable", `{"duration":""}`)
	s.Contains(result, `"enabled":true`)
	s.NotContains(result, "expiresAt")

	s.mgmtRPC("attack.disable", "{}")
}

// --- 12: Metrics Consistency ---

func (s *E2ESuite) Test12_Metrics_Consistency() {
	for range 5 {
		resp, _ := http.Get(dataURL + "/")
		if resp != nil {
			resp.Body.Close()
		}
	}

	for range 2 {
		resp, _ := http.Get(dataURL + "/?id=1'+OR+1=1--")
		if resp != nil {
			resp.Body.Close()
		}
	}

	req, _ := http.NewRequest(http.MethodGet, dataURL+"/", nil)
	req.Header.Set("User-Agent", "E2EBlockBot/1.0")
	resp, _ := http.DefaultClient.Do(req)
	if resp != nil {
		resp.Body.Close()
	}

	time.Sleep(6 * time.Second)

	metrics := s.getMetrics()
	s.Contains(metrics, `wafsrv_requests_total{`)
	s.Contains(metrics, `wafsrv_decision_total{action="pass",platform=""}`)
	s.Contains(metrics, `wafsrv_waf_blocked_total`)
	s.Contains(metrics, `wafsrv_traffic_filter_total{action="block",rule="e2e-block-bot"}`)

	tops := s.mgmtRPC("metrics.tops", `{"n":10}`)
	s.Contains(tops, `"total":`)
	s.Contains(tops, `"paths"`)
	s.Contains(tops, `"ips"`)
}

// --- 14: Metrics Tops ---

func (s *E2ESuite) Test14_Tops_IPsContainGeo() {
	resp, _ := http.Get(dataURL + "/")
	if resp != nil {
		resp.Body.Close()
	}

	tops := s.mgmtRPC("metrics.tops", `{"n":10}`)
	s.Contains(tops, `"ip":`)
	s.Contains(tops, `"total":`)
}

func (s *E2ESuite) Test14_Tops_PathsExist() {
	tops := s.mgmtRPC("metrics.tops", `{"n":10}`)
	s.Contains(tops, `"paths":[`)
}

func (s *E2ESuite) Test14_Tops_WAFRulesAfterAttack() {
	resp, _ := http.Get(dataURL + "/?id=1'+OR+1=1--")
	if resp != nil {
		resp.Body.Close()
	}

	tops := s.mgmtRPC("metrics.tops", `{"n":10}`)
	s.Contains(tops, `"wafRules":[`)
}

// --- 16: Config API ---

func (s *E2ESuite) Test16_Config_Get() {
	result := s.mgmtRPC("config.get", "{}")
	s.Contains(result, `"proxy"`)
	s.Contains(result, `"targetDiscoveryEnabled"`)
	s.Contains(result, `"serviceName":"e2e-test"`)
}

func (s *E2ESuite) Test16_Config_TargetDiscoveryDisabled() {
	result := s.mgmtRPC("config.get", "{}")
	s.Contains(result, `"targetDiscoveryEnabled":false`, "discovery should be disabled in e2e config")
}
