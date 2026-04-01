package e2e

import (
	"net/http"
	"strings"
)

// --- 02: WAF ---

func (s *E2ESuite) Test02_WAF_SQLi_Blocked() {
	s.assertStatus(dataURL+"/?id=1'+OR+1=1--", http.StatusForbidden)
}

func (s *E2ESuite) Test02_WAF_XSS_Blocked() {
	s.assertStatus(dataURL+"/?q=<script>alert(1)</script>", http.StatusForbidden)
}

func (s *E2ESuite) Test02_WAF_PathTraversal_Blocked() {
	s.assertStatus(dataURL+"/?file=../../etc/passwd", http.StatusForbidden)
}

func (s *E2ESuite) Test02_WAF_ShellInjection_Blocked() {
	s.assertStatus(dataURL+"/?cmd=;cat+/etc/passwd", http.StatusForbidden)
}

func (s *E2ESuite) Test02_WAF_UnionSelect_Blocked() {
	s.assertStatus(dataURL+"/?id=1+UNION+SELECT+username,password+FROM+users--", http.StatusForbidden)
}

func (s *E2ESuite) Test02_WAF_Body_SQLi_Blocked() {
	resp, err := http.Post(dataURL+"/", "application/x-www-form-urlencoded",
		strings.NewReader("id=1'+OR+1=1--"))
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusForbidden, resp.StatusCode, "SQLi in POST body should be blocked")
}

func (s *E2ESuite) Test02_WAF_Body_XSS_Blocked() {
	resp, err := http.Post(dataURL+"/", "application/x-www-form-urlencoded",
		strings.NewReader("q=<script>alert(1)</script>"))
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusForbidden, resp.StatusCode, "XSS in POST body should be blocked")
}

func (s *E2ESuite) Test02_WAF_Body_NormalPost_Passes() {
	resp, err := http.Post(dataURL+"/", "application/x-www-form-urlencoded",
		strings.NewReader("name=John&age=30"))
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode, "normal POST body should pass")
}

func (s *E2ESuite) Test02_WAF_NormalRequest_Passes() {
	s.assertStatus(dataURL+"/", http.StatusOK)
}

func (s *E2ESuite) Test02_WAF_NormalQueryParams_Passes() {
	s.assertStatus(dataURL+"/?page=1&limit=10", http.StatusOK)
}

func (s *E2ESuite) Test02_WAF_SafeSpecialChars_Passes() {
	s.assertStatus(dataURL+"/?search=union+street", http.StatusOK)
	s.assertStatus(dataURL+"/?title=select+best+product", http.StatusOK)
}

func (s *E2ESuite) Test02_WAF_ZZ_Metrics() {
	body := s.getMetrics()
	s.Contains(body, "wafsrv_waf_blocked_total")
}

// --- 06: Decision Engine ---

func (s *E2ESuite) Test06_Decision_NormalPass() {
	s.assertStatus(dataURL+"/", http.StatusOK)
}

func (s *E2ESuite) Test06_Decision_Metrics() {
	body := s.getMetrics()
	s.Contains(body, "wafsrv_decision_total")
}

func (s *E2ESuite) Test06_Decision_PassCount() {
	body := s.getMetrics()
	s.Contains(body, `wafsrv_decision_total{action="pass",platform=""}`)
}

// --- 15: Request Signing ---

func (s *E2ESuite) Test15_Sign_Unsigned_Passes() {
	s.assertStatus(dataURL+"/", http.StatusOK)
}

func (s *E2ESuite) Test15_Sign_InvalidFormat() {
	req, _ := http.NewRequest(http.MethodGet, dataURL+"/", nil)
	req.Header.Set("X-Waf-Sign", "bad-format")
	resp, err := http.DefaultClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode)

	metrics := s.getMetrics()
	s.Contains(metrics, "wafsrv_sign_total")
}

func (s *E2ESuite) Test15_Sign_ExpiredTimestamp() {
	req, _ := http.NewRequest(http.MethodGet, dataURL+"/", nil)
	req.Header.Set("X-Waf-Sign", "v1.1000000000.abc12345.0000000000000000000000000000000000000000000000000000000000000000")
	resp, err := http.DefaultClient.Do(req)
	s.Require().NoError(err)
	defer resp.Body.Close()
	s.Equal(http.StatusOK, resp.StatusCode, "detection mode — expired passes with score")
}

func (s *E2ESuite) Test15_Sign_Metrics() {
	metrics := s.getMetrics()
	s.Contains(metrics, "wafsrv_sign_total")
}
