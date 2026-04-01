package waf

import (
	"log/slog"
	"net/http"
)

// SecurityAttrs returns common slog attributes for security event logging.
func SecurityAttrs(r *http.Request) []slog.Attr {
	rc := FromContext(r.Context())
	if rc == nil {
		return nil
	}

	attrs := []slog.Attr{
		slog.String("requestId", rc.RequestID),
		slog.String("clientIp", rc.ClientIP.String()),
		slog.String("userAgent", r.UserAgent()),
	}

	if rc.IP != nil {
		if rc.IP.Country != "" {
			attrs = append(attrs, slog.String("country", rc.IP.Country))
		}

		if rc.IP.ASNOrg != "" {
			attrs = append(attrs, slog.String("asnOrg", rc.IP.ASNOrg))
		}
	}

	return attrs
}
