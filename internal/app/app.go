package app

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"wafsrv/internal/dashboard"
	"wafsrv/internal/waf"
	"wafsrv/internal/waf/adaptive"
	"wafsrv/internal/waf/alerting"
	"wafsrv/internal/waf/challenge"
	"wafsrv/internal/waf/decide"
	"wafsrv/internal/waf/engine"
	"wafsrv/internal/waf/event"
	"wafsrv/internal/waf/filter"
	"wafsrv/internal/waf/ip"
	"wafsrv/internal/waf/limit"
	"wafsrv/internal/waf/proxy"
	"wafsrv/internal/waf/rpc"
	"wafsrv/internal/waf/sign"
	"wafsrv/internal/waf/storage"

	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/vmkteam/embedlog"
)

// App is the main application that runs data and management servers.
type App struct {
	embedlog.Logger
	appName  string
	cfg      Config
	proxyCfg proxy.Config
	proxy    *proxy.Proxy
	data     *http.Server
	mgmt     *http.Server

	// waf
	ipService     *ip.Service
	trafficFilter *filter.TrafficFilter
	signVerifier  *sign.Verifier
	rpcInspector  *rpc.Inspector
	limiter       *limit.Limiter
	wafEngine     *engine.Engine

	// decision & alerting
	captchaCache   *challenge.Cache
	decisionEngine *decide.Engine
	alerter        *alerting.Alerter
	recorder       *event.Recorder

	// adaptive
	attackSvc      *dashboard.AttackService
	adaptiveEngine *adaptive.Engine

	// storage
	aerospike *storage.Aerospike
	counter   storage.Counter
	kvStore   storage.KVStore

	// platform normalization
	platformSet map[string]struct{}

	// metrics
	metrics *appMetrics
}

// New creates a new App.
func New(appName string, sl embedlog.Logger, cfg Config) (*App, error) {
	pcfg, err := cfg.ProxyConfig()
	if err != nil {
		return nil, fmt.Errorf("app: %w", err)
	}

	resolver, err := buildResolver(cfg)
	if err != nil {
		return nil, fmt.Errorf("app: %w", err)
	}

	p, err := proxy.New(pcfg, resolver)
	if err != nil {
		// non-fatal for discovery mode: proxy starts with empty pool
		sl.Print(context.Background(), "proxy: initial resolve failed, will retry", "error", err)
	}

	a := &App{
		Logger:   sl,
		appName:  appName,
		cfg:      cfg,
		proxyCfg: pcfg,
		proxy:    p,
	}

	if err := a.initStorage(); err != nil {
		return nil, err
	}

	a.recorder = event.NewRecorder(
		event.NewBuffer(1000),
		event.NewSeries(5*time.Second, 360), // 30 min history
		event.NewTops(30*time.Minute, 10000),
	)
	a.metrics = newMetrics()

	if err := a.initWAF(); err != nil {
		return nil, err
	}

	a.platformSet = a.buildPlatformSet()
	a.attackSvc = dashboard.NewAttackService()
	a.initDecision()
	a.initAdaptive()

	return a, nil
}

func buildResolver(cfg Config) (proxy.Resolver, error) {
	if cfg.Proxy.TargetDiscovery.TargetDiscoveryEnabled() {
		td := cfg.Proxy.TargetDiscovery
		return proxy.NewSRVResolver(proxy.SRVResolverConfig{
			Hostname:  td.Hostname,
			Service:   td.Service,
			Proto:     td.Proto,
			DNSServer: td.DNSServer,
		}), nil
	}

	urls, err := cfg.ProxyTargetURLs()
	if err != nil {
		return nil, err
	}

	return proxy.Static(urls), nil
}

func (a *App) initStorage() error {
	switch a.cfg.Storage.Backend {
	case StorageAerospike:
		asCfg := a.cfg.Storage.Aerospike
		as, err := storage.NewAerospike(storage.AerospikeConfig{
			Hosts:          asCfg.Hosts,
			Namespace:      asCfg.Namespace,
			KeyPrefix:      asCfg.KeyPrefix,
			ConnectTimeout: parseDuration(asCfg.ConnectTimeout, 5*time.Second),
			OperTimeout:    parseDuration(asCfg.OperTimeout, 50*time.Millisecond),
		})
		if err != nil {
			return fmt.Errorf("app: %w", err)
		}

		a.aerospike = as
		a.counter = as.Counter("rl")
		a.kvStore = as.KV("kv")
	default:
		a.counter = storage.NewMemoryCounter(a.cfg.RateLimit.MaxCounters)
		a.kvStore = storage.NewMemoryKV(100000)
	}

	return nil
}

func (a *App) initAdaptive() {
	if !a.cfg.Adaptive.AdaptiveEnabled() {
		return
	}

	aa := a.cfg.Adaptive.AutoAttack
	a.adaptiveEngine = adaptive.New(adaptive.Config{
		Mode:           a.cfg.Adaptive.Mode,
		EvalInterval:   parseDuration(a.cfg.Adaptive.EvalInterval, 10*time.Second),
		WarmupDuration: parseDuration(a.cfg.Adaptive.WarmupDuration, 2*time.Minute),
		AutoAttack: adaptive.AutoAttackConfig{
			RPSMultiplier:         aa.RPSMultiplier,
			RPSRecoveryMultiplier: aa.RPSRecoveryMultiplier,
			MinRPS:                aa.MinRPS,
			ErrorRateThreshold:    aa.ErrorRateThreshold,
			LatencyThresholdMs:    aa.LatencyThresholdMs,
			BlockedRateThreshold:  aa.BlockedRateThreshold,
			Window:                parseDuration(aa.Window, time.Minute),
			Cooldown:              parseDuration(aa.Cooldown, 5*time.Minute),
			Duration:              parseDuration(aa.Duration, 10*time.Minute),
		},
	}, a.recorder.Series(), a.attackSvc, a.alertSender(), slog.Default(), a.metrics.adaptiveMetrics())
}

func (a *App) initWAF() error {
	ipCfg, err := a.cfg.IPServiceConfig()
	if err != nil {
		return fmt.Errorf("app: %w", err)
	}

	a.ipService, err = ip.New(ipCfg, a.Logger, a.metrics.ipMetrics(a.recorder))
	if err != nil {
		return fmt.Errorf("app: %w", err)
	}

	if a.cfg.TrafficFilter.TrafficFilterEnabled() {
		a.trafficFilter = filter.New(a.cfg.TrafficFilter.Rules, a.Logger, a.metrics.filterMetrics(a.recorder))
	}

	if a.cfg.Signing.SigningEnabled() {
		methods := make([]sign.MethodRule, len(a.cfg.Signing.Methods))
		for i, m := range a.cfg.Signing.Methods {
			methods[i] = sign.MethodRule{
				Name: m.Name, Endpoint: m.Endpoint,
				Methods: m.Methods, Platforms: m.Platforms, SignFields: m.SignFields,
			}
		}

		a.signVerifier = sign.New(sign.Config{
			Mode:       a.cfg.Signing.Mode,
			TTL:        parseDuration(a.cfg.Signing.TTL, 5*time.Minute),
			NonceCache: a.cfg.Signing.NonceCache,
			Web: sign.PlatformSecret{
				Enabled: a.cfg.Signing.Web.Enabled != nil && *a.cfg.Signing.Web.Enabled,
				Secret:  a.cfg.Signing.Web.Secret,
			},
			Android: sign.PlatformSecret{
				Enabled: a.cfg.Signing.Android.Enabled != nil && *a.cfg.Signing.Android.Enabled,
				Secret:  a.cfg.Signing.Android.Secret,
			},
			IOS: sign.PlatformSecret{
				Enabled: a.cfg.Signing.IOS.Enabled != nil && *a.cfg.Signing.IOS.Enabled,
				Secret:  a.cfg.Signing.IOS.Secret,
			},
			Methods: methods,
		}, a.kvStore, a.Logger, a.metrics.signMetrics(a.recorder))
	}

	if a.cfg.RateLimit.RateLimitEnabled() {
		limCfg, err2 := a.cfg.LimiterConfig()
		if err2 != nil {
			return fmt.Errorf("app: %w", err2)
		}

		a.limiter = limit.New(limCfg, a.counter, a.Logger, a.metrics.limitMetrics(a.recorder))
	}

	if a.cfg.WAF.WAFEnabled() {
		a.wafEngine, err = engine.New(engine.Config{
			Mode:          a.cfg.WAF.Mode,
			ParanoiaLevel: a.cfg.WAF.ParanoiaLevel,
		}, a.Logger, a.metrics.engineMetrics(a.recorder))
		if err != nil {
			return fmt.Errorf("app: %w", err)
		}
	}

	a.initRPCInspector()

	return nil
}

func (a *App) initRPCInspector() {
	logger := slog.Default()

	var configs []rpc.InspectConfig

	discoveries := make(map[string]*rpc.Discovery)

	target := a.proxy.FirstBackendURL()

	for _, ep := range a.cfg.JSONRPC.Endpoints {
		if ep.SchemaURL == "" && ep.MaxBatchSize == 0 {
			continue
		}

		configs = append(configs, rpc.InspectConfig{
			Endpoint:        ep.Name,
			MethodWhitelist: ep.MethodWhitelist,
			MaxBatchSize:    ep.MaxBatchSize,
		})

		if ep.SchemaURL != "" {
			url := rpc.ResolveSchemaURL(ep.SchemaURL, target)
			refresh := parseDuration(ep.SchemaRefresh, 5*time.Minute)
			discoveries[ep.Name] = rpc.NewDiscovery(rpc.DiscoveryConfig{
				SchemaURL: url,
				Refresh:   refresh,
			}, logger)
		}
	}

	if len(configs) > 0 {
		a.rpcInspector = rpc.NewInspector(configs, discoveries, a.metrics.inspectMetrics(a.recorder))
	}
}

func (a *App) initDecision() {
	// captcha cache
	a.captchaCache = challenge.NewCache(challenge.CacheConfig{
		CookieName: a.cfg.Captcha.CookieName,
		CookieTTL:  parseDuration(a.cfg.Captcha.CookieTTL, 30*time.Minute),
		IPCacheTTL: parseDuration(a.cfg.Captcha.IPCacheTTL, 30*time.Minute),
	}, a.kvStore)

	// decision engine
	platforms := make([]decide.PlatformConfig, len(a.cfg.Decision.Platforms))
	for i, p := range a.cfg.Decision.Platforms {
		fb := parseFallbackAction(p.Fallback)
		if fb == waf.ActionPass && p.Fallback == "" {
			fb = parseFallbackAction(a.cfg.Decision.CaptchaFallback)
		}

		platforms[i] = decide.PlatformConfig{
			Platform:   strings.ToLower(p.Platform),
			Captcha:    p.Captcha,
			MinVersion: decide.ParseSemver(p.MinVersion),
			Fallback:   fb,
		}
	}

	var verifier *challenge.Verifier
	var powVerifier *challenge.PowVerifier

	switch a.cfg.Captcha.Provider {
	case "pow":
		powVerifier = challenge.NewPowVerifier(
			a.captchaCache.Secret(),
			challenge.PowConfig{
				Difficulty:       a.cfg.Captcha.PoW.Difficulty,
				AttackDifficulty: a.cfg.Captcha.PoW.AttackDifficulty,
				Timeout:          parseDuration(a.cfg.Captcha.PoW.Timeout, 10*time.Second),
				SaltTTL:          parseDuration(a.cfg.Captcha.PoW.SaltTTL, 5*time.Minute),
			},
			func() bool { return a.attackSvc.IsEnabled() },
		)
	case "hcaptcha":
		if a.cfg.Captcha.SecretKey != "" {
			verifier = challenge.NewVerifier(challenge.HCaptchaVerifyURL, 10*time.Second)
		}
	default: // "turnstile"
		if a.cfg.Captcha.SecretKey != "" {
			verifier = challenge.NewVerifier(challenge.TurnstileVerifyURL, 10*time.Second)
		}
	}

	// alerting (before decide — decide uses alerter)
	if a.cfg.Alerting.AlertingEnabled() {
		webhooks := make([]alerting.Webhook, 0, len(a.cfg.Alerting.Webhooks))
		for _, wh := range a.cfg.Alerting.Webhooks {
			webhooks = append(webhooks, alerting.Webhook{
				URL:         wh.URL,
				Events:      wh.Events,
				MinInterval: parseDuration(wh.MinInterval, 5*time.Minute),
			})
		}

		a.alerter = alerting.New(webhooks, a.cfg.Proxy.ServiceName, slog.Default())
	}

	a.decisionEngine = decide.New(decide.Config{
		CaptchaThreshold:     a.cfg.Decision.CaptchaThreshold,
		BlockThreshold:       a.cfg.Decision.BlockThreshold,
		CaptchaStatusCode:    a.cfg.Decision.CaptchaStatusCode,
		BlockStatusCode:      a.cfg.Decision.BlockStatusCode,
		CaptchaToBlock:       a.cfg.Decision.CaptchaToBlock,
		CaptchaToBlockWindow: parseDuration(a.cfg.Decision.CaptchaToBlockWindow, 10*time.Minute),
		SoftBlockDuration:    parseDuration(a.cfg.Decision.SoftBlockDuration, 10*time.Minute),
		CaptchaProvider:      a.cfg.Captcha.Provider,
		CaptchaSiteKey:       a.cfg.Captcha.SiteKey,
		CaptchaSecretKey:     a.cfg.Captcha.SecretKey,
		CaptchaCookieName:    a.cfg.Captcha.CookieName,
		CaptchaFallback:      parseFallbackAction(a.cfg.Decision.CaptchaFallback),
		Platforms:            platforms,
		Branding: challenge.Branding{
			Title:        "Security Check",
			PrimaryColor: "#4F46E5",
		},
	}, a.kvStore, a.captchaCache, verifier, powVerifier, a.alertSender(), a.Logger, a.metrics.decideMetrics(a.recorder, a.platformSet))
}

// Run starts both data and management servers.
func (a *App) Run(ctx context.Context) error {
	trusted, err := proxy.ParseTrustedProxies(a.cfg.Proxy.RealIP.TrustedProxies)
	if err != nil {
		return fmt.Errorf("app: invalid trusted proxies: %w", err)
	}

	a.data = &http.Server{
		Addr:         a.cfg.Proxy.Listen,
		Handler:      a.buildDataHandler(trusted),
		ReadTimeout:  a.proxyCfg.ReadTimeout,
		WriteTimeout: a.proxyCfg.WriteTimeout,
		IdleTimeout:  a.proxyCfg.IdleTimeout,
	}

	a.mgmt = &http.Server{
		Addr:    a.cfg.Management.Listen,
		Handler: a.buildMgmtHandler(),
	}

	errCh := make(chan error, 1)

	go func() {
		a.Print(ctx, "management server starting", "addr", a.cfg.Management.Listen)

		if err := a.mgmt.ListenAndServe(); err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- fmt.Errorf("management server: %w", err)
		}
	}()

	// start IP reputation feeds refresh (background)
	if a.ipService != nil {
		a.ipService.Start(ctx)
	}

	// start adaptive engine (background eval loop)
	if a.adaptiveEngine != nil {
		a.adaptiveEngine.Start(ctx)
	}

	// start RPC schema discovery (background refresh)
	if a.rpcInspector != nil {
		for _, d := range a.rpcInspector.Discoveries() {
			d.Start(ctx)
		}
	}

	// start proxy target discovery (background refresh)
	go a.proxy.Run(ctx, func(r proxy.ResolveResult) {
		if r.Error != nil {
			a.Print(ctx, "proxy: resolve failed, keeping old pool", "error", r.Error)
			return
		}

		if r.Added > 0 || r.Removed > 0 {
			a.Print(ctx, "proxy: pool updated", "backends", r.Backends, "added", r.Added, "removed", r.Removed)
		}
	})

	a.Print(ctx, "data server starting", "addr", a.cfg.Proxy.Listen, "targets", a.cfg.Proxy.Targets)

	go func() {
		if err := a.data.ListenAndServe(); err != nil {
			errCh <- err
		}
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Shutdown gracefully shuts down both servers.
func (a *App) Shutdown(timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	var errs []error

	if a.mgmt != nil {
		if err := a.mgmt.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}

	if a.data != nil {
		if err := a.data.Shutdown(ctx); err != nil {
			errs = append(errs, err)
		}
	}

	if a.alerter != nil {
		a.alerter.Shutdown()
	}

	if a.ipService != nil {
		if err := a.ipService.Close(); err != nil {
			errs = append(errs, err)
		}
	}

	if a.aerospike != nil {
		a.aerospike.Close()
	}

	return errors.Join(errs...)
}

// alertSender returns the alerter as alerting.Sender interface, or nil.
// Avoids Go nil interface trap: typed nil (*Alerter)(nil) != nil when stored as interface.
func (a *App) alertSender() alerting.Sender {
	if a.alerter != nil {
		return a.alerter
	}

	return nil
}

func (a *App) buildPlatformSet() map[string]struct{} {
	ps := make(map[string]struct{})
	for _, p := range a.cfg.Proxy.Platforms {
		ps[strings.ToLower(p)] = struct{}{}
	}
	// also collect from Decision.Platforms (already lowercased in initDecision)
	for _, p := range a.cfg.Decision.Platforms {
		ps[strings.ToLower(p.Platform)] = struct{}{}
	}

	return ps
}

func (a *App) buildDataHandler(trusted []netip.Prefix) http.Handler {
	logger := slog.Default()
	platformSet := a.platformSet

	middlewares := []Middleware{
		accessLog(accessLogConfig{
			logger:          logger,
			serviceName:     a.cfg.Proxy.ServiceName,
			requestsTotal:   a.metrics.requestsTotal,
			requestDuration: a.metrics.requestDuration,
			recorder:        a.recorder,
			platformSet:     platformSet,
		}),
		initContext,
	}

	middlewares = append(middlewares,
		realIP(a.cfg.Proxy.RealIP.Headers, trusted),
		bodyLimit(a.proxyCfg.MaxRequestBody),
	)

	if mw := staticBypass(a.cfg.Proxy.Static); mw != nil {
		middlewares = append(middlewares, mw)
	}

	middlewares = append(middlewares, rpcParser(a.cfg.JSONRPC.Endpoints))

	if a.rpcInspector != nil {
		middlewares = append(middlewares, a.rpcInspector.Middleware())
	}

	if a.ipService != nil {
		middlewares = append(middlewares, a.ipService.Middleware())
	}

	if a.trafficFilter != nil {
		middlewares = append(middlewares, a.trafficFilter.Middleware())
	}

	if a.signVerifier != nil {
		middlewares = append(middlewares, a.signVerifier.Middleware())
	}

	if a.limiter != nil {
		middlewares = append(middlewares, a.limiter.Middleware())
	}

	if a.wafEngine != nil {
		middlewares = append(middlewares, a.wafEngine.Middleware())
	}

	if a.decisionEngine != nil {
		middlewares = append(middlewares, a.decisionEngine.Middleware())
	}

	middlewares = append(middlewares, observe(observeConfig{
		rpcRequestsTotal: a.metrics.rpcRequestsTotal,
		serviceName:      a.cfg.Proxy.ServiceName,
		recorder:         a.recorder,
		platformSet:      platformSet,
	}))

	return Chain(middlewares...)(a.proxy.HandlerWithLatency(a.recorder))
}

func (a *App) buildMgmtHandler() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /health", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"status":"ok"}`))
	})

	mux.Handle("GET /metrics", promhttp.HandlerFor(a.metrics.registry, promhttp.HandlerOpts{}))

	rules := make([]dashboard.RuleInfo, 0, len(a.cfg.RateLimit.Rules))
	for _, r := range a.cfg.RateLimit.Rules {
		rules = append(rules, dashboard.RuleInfo{
			Name:     r.Name,
			Endpoint: r.Endpoint,
			Match:    r.Match,
			Limit:    r.Limit,
			Action:   r.Action,
		})
	}

	attackSvc := a.attackSvc

	rpcServer := dashboard.New(a.ipService, dashboard.StatusInfo{
		Service:          a.cfg.Proxy.ServiceName,
		Targets:          a.cfg.Proxy.Targets,
		Listen:           a.cfg.Proxy.Listen,
		WAFEnabled:       a.cfg.WAF.WAFEnabled(),
		WAFMode:          a.cfg.WAF.Mode,
		WAFParanoiaLevel: a.cfg.WAF.ParanoiaLevel,
		RateLimitEnabled: a.cfg.RateLimit.RateLimitEnabled(),
		RateLimitPerIP:   a.cfg.RateLimit.PerIP,
		RateLimitRules:   rules,
		BotVerifyEnabled: a.cfg.IP.Whitelist.VerifyBotsEnabled() && len(a.cfg.IP.Whitelist.BotDomains) > 0,
		StartedAt:        time.Now(),
	}, a.proxy, attackSvc, a.recorder, a.trafficFilter, BuildConfigResponse(a.cfg))

	mux.Handle("/rpc/", rpcServer)
	mux.Handle("/", dashboard.WebHandler())

	return mux
}
