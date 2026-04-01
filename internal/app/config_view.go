package app

import "wafsrv/internal/dashboard"

// BuildConfigResponse creates a masked config response from app config.
func BuildConfigResponse(c Config) dashboard.ConfigResponse {
	return dashboard.ConfigResponse{
		Proxy:         buildProxySection(c),
		Management:    dashboard.ManagementSection{Listen: c.Management.Listen},
		JSONRPC:       buildJSONRPCSection(c),
		WAF:           dashboard.WAFSection{Enabled: c.WAF.WAFEnabled(), Mode: c.WAF.Mode, ParanoiaLevel: c.WAF.ParanoiaLevel},
		RateLimit:     buildRateLimitSection(c),
		IP:            buildIPSection(c),
		TrafficFilter: dashboard.TrafficFilterSection{Enabled: c.TrafficFilter.TrafficFilterEnabled(), RuleCount: len(c.TrafficFilter.Rules)},
		Signing:       buildSigningSection(c),
		Decision:      buildDecisionSection(c),
		Captcha:       dashboard.CaptchaSection{Provider: c.Captcha.Provider, HasKeys: c.Captcha.SiteKey != "" && c.Captcha.SecretKey != "", CookieName: c.Captcha.CookieName, CookieTTL: c.Captcha.CookieTTL, IPCacheTTL: c.Captcha.IPCacheTTL},
		Alerting:      dashboard.AlertingSection{Enabled: c.Alerting.AlertingEnabled(), WebhookCount: len(c.Alerting.Webhooks)},
		Adaptive:      buildAdaptiveSection(c),
		Storage:       dashboard.StorageSection{Backend: c.Storage.Backend, Hosts: len(c.Storage.Aerospike.Hosts), Namespace: c.Storage.Aerospike.Namespace, KeyPrefix: c.Storage.Aerospike.KeyPrefix},
	}
}

func buildProxySection(c Config) dashboard.ProxySection {
	td := c.Proxy.TargetDiscovery

	return dashboard.ProxySection{
		Listen:         c.Proxy.Listen,
		Targets:        c.Proxy.Targets,
		ServiceName:    c.Proxy.ServiceName,
		Platforms:      c.Proxy.Platforms,
		ReadTimeout:    c.Proxy.Timeouts.Read,
		WriteTimeout:   c.Proxy.Timeouts.Write,
		IdleTimeout:    c.Proxy.Timeouts.Idle,
		MaxRequestBody: c.Proxy.Limits.MaxRequestBody,
		RealIPHeaders:  c.Proxy.RealIP.Headers,
		TrustedProxies: c.Proxy.RealIP.TrustedProxies,
		CBEnabled:      c.Proxy.CircuitBreaker.Enabled == nil || *c.Proxy.CircuitBreaker.Enabled,
		CBThreshold:    c.Proxy.CircuitBreaker.Threshold,
		CBTimeout:      c.Proxy.CircuitBreaker.Timeout,
		StaticPaths:    c.Proxy.Static.Paths,
		StaticExts:     c.Proxy.Static.Extensions,

		TargetDiscoveryEnabled: td.TargetDiscoveryEnabled(),
		TargetDiscoveryHost:    td.Hostname,
		TargetDiscoveryScheme:  td.Scheme,
		TargetDiscoveryDNS:     td.DNSServer,
		TargetDiscoveryRefresh: td.RefreshInterval,
		TargetDiscoveryTimeout: td.ResolveTimeout,
	}
}

func buildJSONRPCSection(c Config) dashboard.JSONRPCSection {
	eps := make([]dashboard.JSONRPCEndpointInfo, len(c.JSONRPC.Endpoints))
	for i, ep := range c.JSONRPC.Endpoints {
		eps[i] = dashboard.JSONRPCEndpointInfo{
			Path: ep.Path, Name: ep.Name,
			SchemaURL: ep.SchemaURL, SchemaRefresh: ep.SchemaRefresh,
			MethodWhitelist: ep.MethodWhitelist, MaxBatchSize: ep.MaxBatchSize,
		}
	}

	return dashboard.JSONRPCSection{Endpoints: eps}
}

func buildRateLimitSection(c Config) dashboard.RateLimitSection {
	rules := make([]dashboard.RuleInfo, len(c.RateLimit.Rules))
	for i, r := range c.RateLimit.Rules {
		rules[i] = dashboard.RuleInfo{
			Name: r.Name, Endpoint: r.Endpoint,
			Match: r.Match, Limit: r.Limit, Action: r.Action,
		}
	}

	return dashboard.RateLimitSection{
		Enabled: c.RateLimit.RateLimitEnabled(), PerIP: c.RateLimit.PerIP,
		Action: c.RateLimit.Action, MaxCounters: c.RateLimit.MaxCounters, Rules: rules,
	}
}

func buildIPSection(c Config) dashboard.IPSection {
	rep := c.IP.Reputation

	return dashboard.IPSection{
		GeoDatabase:      c.IP.GeoDatabase != "",
		ASNDatabase:      c.IP.ASNDatabase != "",
		WhitelistCIDRs:   len(c.IP.Whitelist.CIDRs),
		BlacklistCIDRs:   len(c.IP.Blacklist.CIDRs),
		VerifyBots:       c.IP.Whitelist.VerifyBotsEnabled(),
		BotDomains:       c.IP.Whitelist.BotDomains,
		FakeBotScore:     c.IP.Whitelist.BotVerify.FakeBotScore,
		BlockCountries:   c.IP.Countries.Block,
		CaptchaCountries: c.IP.Countries.Captcha,
		LogCountries:     c.IP.Countries.Log,
		Reputation: dashboard.ReputationInfo{
			Enabled:         rep.ReputationEnabled(),
			UpdateInterval:  rep.UpdateInterval,
			ScoreAdjustment: rep.ScoreAdjustment,
			FireHOL:         rep.FireHOL.IsEnabled(),
			FireHOLLevel:    rep.FireHOL.Level,
			Tor:             rep.Tor.IsEnabled(),
			TorAction:       rep.Tor.Action,
			Datacenter:      rep.Datacenter.IsEnabled(),
			DcScore:         rep.Datacenter.ScoreAdjustment,
			FeedCount:       len(rep.Feeds),
		},
	}
}

func buildSigningSection(c Config) dashboard.SigningSection {
	return dashboard.SigningSection{
		Enabled:    c.Signing.SigningEnabled(),
		Mode:       c.Signing.Mode,
		TTL:        c.Signing.TTL,
		NonceCache: c.Signing.NonceCache,
		Web:        c.Signing.Web.Enabled != nil && *c.Signing.Web.Enabled,
		Android:    c.Signing.Android.Enabled != nil && *c.Signing.Android.Enabled,
		IOS:        c.Signing.IOS.Enabled != nil && *c.Signing.IOS.Enabled,
		Methods:    len(c.Signing.Methods),
	}
}

func buildDecisionSection(c Config) dashboard.DecisionSection {
	plats := make([]dashboard.PlatformCaptchaInfo, len(c.Decision.Platforms))
	for i, p := range c.Decision.Platforms {
		plats[i] = dashboard.PlatformCaptchaInfo{
			Platform: p.Platform, Captcha: p.Captcha,
			MinVersion: p.MinVersion, Fallback: p.Fallback,
		}
	}

	return dashboard.DecisionSection{
		CaptchaThreshold:     c.Decision.CaptchaThreshold,
		BlockThreshold:       c.Decision.BlockThreshold,
		CaptchaStatusCode:    c.Decision.CaptchaStatusCode,
		BlockStatusCode:      c.Decision.BlockStatusCode,
		CaptchaToBlock:       c.Decision.CaptchaToBlock,
		CaptchaToBlockWindow: c.Decision.CaptchaToBlockWindow,
		SoftBlockDuration:    c.Decision.SoftBlockDuration,
		CaptchaFallback:      c.Decision.CaptchaFallback,
		Platforms:            plats,
	}
}

func buildAdaptiveSection(c Config) dashboard.AdaptiveSection {
	aa := c.Adaptive.AutoAttack
	return dashboard.AdaptiveSection{
		Enabled:        c.Adaptive.AdaptiveEnabled(),
		Mode:           c.Adaptive.Mode,
		EvalInterval:   c.Adaptive.EvalInterval,
		WarmupDuration: c.Adaptive.WarmupDuration,
		RPSMultiplier:  aa.RPSMultiplier,
		RPSRecovery:    aa.RPSRecoveryMultiplier,
		MinRPS:         aa.MinRPS,
		ErrorRate:      aa.ErrorRateThreshold,
		LatencyMs:      aa.LatencyThresholdMs,
		BlockedRate:    aa.BlockedRateThreshold,
		Window:         aa.Window,
		Cooldown:       aa.Cooldown,
		Duration:       aa.Duration,
	}
}
