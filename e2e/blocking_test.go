package e2e

import (
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"
)

// --- 03: Rate Limiting ---

func (s *E2ESuite) Test03_RateLimit_PerMethod() {
	for i := range 5 {
		resp := s.postRPC(dataURL+"/rpc/", "pgd.generate", "{}")
		resp.Body.Close()
		s.Equal(http.StatusOK, resp.StatusCode, "request %d should pass", i+1)
	}

	resp := s.postRPC(dataURL+"/rpc/", "pgd.generate", "{}")
	defer resp.Body.Close()
	s.Equal(http.StatusTooManyRequests, resp.StatusCode, "should be rate limited")
	s.NotEmpty(resp.Header.Get("Retry-After"))
}

func (s *E2ESuite) Test03_RateLimit_OtherMethodNotAffected() {
	resp := s.postRPC(dataURL+"/rpc/", "app.About", "{}")
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)
}

func (s *E2ESuite) Test03_RateLimit_ZZ_Metrics() {
	body := s.getMetrics()
	s.Contains(body, "wafsrv_ratelimit_exceeded_total")
}

// --- 04: IP Blocking ---

func (s *E2ESuite) Test04_IP_BlockAndUnblock() {
	clientIP := s.detectClientIP()

	result := s.mgmtRPC("block.add", fmt.Sprintf(`{"blockType":"ip","value":"%s","reason":"e2e"}`, clientIP))
	s.Contains(result, `"result":true`, "block.add should succeed")

	s.assertStatus(dataURL+"/", http.StatusForbidden)

	result = s.mgmtRPC("block.list", `{"blockType":"ip"}`)
	s.Contains(result, clientIP, "block.list should contain IP")

	result = s.mgmtRPC("block.remove", fmt.Sprintf(`{"blockType":"ip","value":"%s"}`, clientIP))
	s.Contains(result, `"result":true`, "block.remove should succeed")

	s.assertStatus(dataURL+"/", http.StatusOK)
}

func (s *E2ESuite) Test04_IP_BlockCIDR() {
	clientIP := s.detectClientIP()

	cidr := clientIP + "/128"
	if !strings.Contains(clientIP, ":") {
		cidr = clientIP + "/32"
	}

	result := s.mgmtRPC("block.add", fmt.Sprintf(`{"blockType":"cidr","value":"%s","reason":"e2e-cidr","duration":""}`, cidr))
	s.Contains(result, `"result":true`)

	s.assertStatus(dataURL+"/", http.StatusForbidden)

	s.mgmtRPC("block.remove", fmt.Sprintf(`{"blockType":"cidr","value":"%s"}`, cidr))
	s.assertStatus(dataURL+"/", http.StatusOK)
}

func (s *E2ESuite) Test04_IP_BlockCountry() {
	result := s.mgmtRPC("block.add", `{"blockType":"country","value":"XX","reason":"e2e-country","duration":""}`)
	s.Contains(result, `"result":true`)

	list := s.mgmtRPC("block.list", `{"blockType":"country"}`)
	s.Contains(list, "XX")

	s.mgmtRPC("block.remove", `{"blockType":"country","value":"XX"}`)

	list = s.mgmtRPC("block.list", `{"blockType":"country"}`)
	s.NotContains(list, "XX")
}

func (s *E2ESuite) Test04_IP_BlockWithDuration() {
	clientIP := s.detectClientIP()

	result := s.mgmtRPC("block.add", fmt.Sprintf(`{"blockType":"ip","value":"%s","reason":"e2e-ttl","duration":"1s"}`, clientIP))
	s.Contains(result, `"result":true`)

	s.assertStatus(dataURL+"/", http.StatusForbidden)

	time.Sleep(1200 * time.Millisecond)
	s.assertStatus(dataURL+"/", http.StatusOK)
}

func (s *E2ESuite) Test04_IP_Metrics() {
	body := s.getMetrics()
	s.Contains(body, "wafsrv_ip_blocked_total")
}

// --- 10: Traffic Filter ---

func (s *E2ESuite) Test10_Filter_ListReturnsConfig() {
	result := s.mgmtRPC("filter.list", "{}")
	s.Contains(result, "e2e-block-bot")
	s.Contains(result, "e2e-log-bot")
	s.Contains(result, `"source":"config"`)
}

func (s *E2ESuite) Test10_Filter_BlockByUA() {
	req, _ := http.NewRequest(http.MethodGet, dataURL+"/", nil)
	req.Header.Set("User-Agent", "E2EBlockBot/1.0")
	resp, err := http.DefaultClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusForbidden, resp.StatusCode, "should block E2EBlockBot")
}

func (s *E2ESuite) Test10_Filter_LogByUA() {
	req, _ := http.NewRequest(http.MethodGet, dataURL+"/", nil)
	req.Header.Set("User-Agent", "E2ELogBot/1.0")
	resp, err := http.DefaultClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode, "should pass E2ELogBot (log action)")
}

func (s *E2ESuite) Test10_Filter_DynamicAddRemove() {
	result := s.mgmtRPC("filter.add", `{"rule":{"name":"e2e-dyn","action":"block","uaPrefix":["E2EDynBot/"]}}`)
	s.Contains(result, `"result":"ok"`)

	list := s.mgmtRPC("filter.list", "{}")
	s.Contains(list, "e2e-dyn")
	s.Contains(list, `"source":"api"`)

	req, _ := http.NewRequest(http.MethodGet, dataURL+"/", nil)
	req.Header.Set("User-Agent", "E2EDynBot/1.0")
	resp, err := http.DefaultClient.Do(req)
	s.Require().NoError(err)
	resp.Body.Close()
	s.Equal(http.StatusForbidden, resp.StatusCode)

	result = s.mgmtRPC("filter.remove", `{"name":"e2e-dyn"}`)
	s.Contains(result, `"result":"ok"`)

	resp, err = http.DefaultClient.Do(req)
	s.Require().NoError(err)
	resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)
}

func (s *E2ESuite) Test10_Filter_ZZ_Metrics() {
	body := s.getMetrics()
	s.Contains(body, "wafsrv_traffic_filter_total")
	s.Contains(body, `rule="e2e-block-bot"`)
}

// --- 09: Concurrent / Race ---

func (s *E2ESuite) Test09_Concurrent_NormalRequests() {
	var wg sync.WaitGroup
	for range 50 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := http.Get(dataURL + "/")
			if err == nil {
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()
}

func (s *E2ESuite) Test09_Concurrent_BlockUnblock() {
	var wg sync.WaitGroup
	for i := range 10 {
		wg.Add(1)
		ip := fmt.Sprintf("10.0.0.%d", i+1)
		go func() {
			defer wg.Done()
			s.mgmtRPC("block.add", fmt.Sprintf(`{"blockType":"ip","value":"%s","reason":"race"}`, ip)) //nolint:testifylint // concurrent test helper
		}()
	}
	wg.Wait()

	for i := range 10 {
		wg.Add(1)
		ip := fmt.Sprintf("10.0.0.%d", i+1)
		go func() {
			defer wg.Done()
			s.mgmtRPC("block.remove", fmt.Sprintf(`{"blockType":"ip","value":"%s"}`, ip)) //nolint:testifylint // concurrent test helper
		}()
	}
	wg.Wait()
}

func (s *E2ESuite) Test09_Concurrent_MixedTraffic() {
	var wg sync.WaitGroup
	for range 20 {
		wg.Add(2)
		go func() {
			defer wg.Done()
			resp, err := http.Get(dataURL + "/")
			if err == nil {
				resp.Body.Close()
			}
		}()
		go func() {
			defer wg.Done()
			resp, err := http.Get(dataURL + "/?id=1'+OR+1=1--")
			if err == nil {
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()
}
