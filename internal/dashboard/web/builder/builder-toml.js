// builder-toml.js — TOML generation from config state

function builderToml() {
  return {
    generateToml() {
      const c = this.cfg;
      const lines = [];
      const D = this._defaults || this.defaultConfig();

      this._genProxy(c, D, lines);
      this._genJSONRPC(c, D, lines);
      this._genManagement(c, D, lines);
      this._genWAF(c, lines);
      this._genRateLimit(c, lines);
      this._genIP(c, D, lines);
      this._genTrafficFilter(c, lines);
      this._genSigning(c, lines);
      this._genDecision(c, D, lines);
      this._genCaptcha(c, D, lines);
      this._genAlerting(c, lines);
      this._genAdaptive(c, D, lines);
      this._genStorage(c, D, lines);

      this.toml = lines.join('\n') + '\n';
      this.lineCount = lines.filter(l => l.trim()).length;
    },

    // --- Proxy ---
    _genProxy(c, D, lines) {
      lines.push('[Proxy]');
      if (c.proxy.listen !== D.proxy.listen) lines.push(`Listen = ${this._q(c.proxy.listen)}`);
      if (!c.proxy.targetDiscovery.enabled) {
        lines.push(`Targets = [${c.proxy.targets.filter(t => t.trim()).map(t => this._q(t.trim())).join(', ')}]`);
      }
      lines.push(`ServiceName = ${this._q(c.proxy.serviceName)}`);
      if (c.proxy.platforms.length > 0) {
        lines.push(`Platforms = [${c.proxy.platforms.map(p => this._q(p)).join(', ')}]`);
      }

      // Timeouts
      if (c.proxy.timeouts.read !== D.proxy.timeouts.read ||
          c.proxy.timeouts.write !== D.proxy.timeouts.write ||
          c.proxy.timeouts.idle !== D.proxy.timeouts.idle) {
        lines.push('');
        lines.push('[Proxy.Timeouts]');
        if (c.proxy.timeouts.read !== D.proxy.timeouts.read) lines.push(`Read = ${this._q(c.proxy.timeouts.read)}`);
        if (c.proxy.timeouts.write !== D.proxy.timeouts.write) lines.push(`Write = ${this._q(c.proxy.timeouts.write)}`);
        if (c.proxy.timeouts.idle !== D.proxy.timeouts.idle) lines.push(`Idle = ${this._q(c.proxy.timeouts.idle)}`);
      }

      // Limits
      if (c.proxy.limits.maxRequestBody !== D.proxy.limits.maxRequestBody) {
        lines.push('');
        lines.push('[Proxy.Limits]');
        lines.push(`MaxRequestBody = ${this._q(c.proxy.limits.maxRequestBody)}`);
      }

      // RealIP
      if (!this._arrEq(c.proxy.realIP.headers, D.proxy.realIP.headers) ||
          !this._arrEq(c.proxy.realIP.trustedProxies, D.proxy.realIP.trustedProxies)) {
        lines.push('');
        lines.push('[Proxy.RealIP]');
        if (!this._arrEq(c.proxy.realIP.headers, D.proxy.realIP.headers)) {
          lines.push(`Headers = [${c.proxy.realIP.headers.map(h => this._q(h)).join(', ')}]`);
        }
        if (!this._arrEq(c.proxy.realIP.trustedProxies, D.proxy.realIP.trustedProxies)) {
          lines.push(`TrustedProxies = [${c.proxy.realIP.trustedProxies.map(p => this._q(p)).join(', ')}]`);
        }
      }

      // Circuit Breaker
      if (c.proxy.circuitBreaker.enabled !== D.proxy.circuitBreaker.enabled ||
          c.proxy.circuitBreaker.threshold !== D.proxy.circuitBreaker.threshold ||
          c.proxy.circuitBreaker.timeout !== D.proxy.circuitBreaker.timeout) {
        lines.push('');
        lines.push('[Proxy.CircuitBreaker]');
        if (c.proxy.circuitBreaker.enabled !== D.proxy.circuitBreaker.enabled) lines.push(`Enabled = ${c.proxy.circuitBreaker.enabled}`);
        if (c.proxy.circuitBreaker.threshold !== D.proxy.circuitBreaker.threshold) lines.push(`Threshold = ${c.proxy.circuitBreaker.threshold}`);
        if (c.proxy.circuitBreaker.timeout !== D.proxy.circuitBreaker.timeout) lines.push(`Timeout = ${this._q(c.proxy.circuitBreaker.timeout)}`);
      }

      // Static
      if (c.proxy.static.paths.length > 0 || c.proxy.static.extensions.length > 0) {
        lines.push('');
        lines.push('[Proxy.Static]');
        if (c.proxy.static.paths.length > 0) lines.push(`Paths = [${c.proxy.static.paths.map(p => this._q(p)).join(', ')}]`);
        if (c.proxy.static.extensions.length > 0) lines.push(`Extensions = [${c.proxy.static.extensions.map(e => this._q(e)).join(', ')}]`);
      }

      // TargetDiscovery
      if (c.proxy.targetDiscovery.enabled) {
        const td = c.proxy.targetDiscovery;
        lines.push('');
        lines.push('[Proxy.TargetDiscovery]');
        lines.push(`Enabled = true`);
        if (td.hostname) lines.push(`Hostname = ${this._q(td.hostname)}`);
        if (td.service) lines.push(`Service = ${this._q(td.service)}`);
        if (td.proto) lines.push(`Proto = ${this._q(td.proto)}`);
        if (td.scheme !== 'http') lines.push(`Scheme = ${this._q(td.scheme)}`);
        if (td.dnsServer) lines.push(`DNSServer = ${this._q(td.dnsServer)}`);
        if (td.refreshInterval !== '1s') lines.push(`RefreshInterval = ${this._q(td.refreshInterval)}`);
        if (td.resolveTimeout !== '3s') lines.push(`ResolveTimeout = ${this._q(td.resolveTimeout)}`);
      }
    },

    // --- JSONRPC ---
    _genJSONRPC(c, D, lines) {
      const hasNonDefault = c.jsonrpc.endpoints.some(ep =>
        ep.path !== '/rpc/' || ep.name !== 'main' || ep.schemaURL || ep.methodWhitelist || ep.maxBatchSize > 0
      ) || c.jsonrpc.endpoints.length !== 1;

      if (hasNonDefault) {
        for (const ep of c.jsonrpc.endpoints) {
          lines.push('');
          lines.push('[[JSONRPC.Endpoints]]');
          lines.push(`Path = ${this._q(ep.path)}`);
          lines.push(`Name = ${this._q(ep.name)}`);
          if (ep.schemaURL) {
            lines.push(`SchemaURL = ${this._q(ep.schemaURL)}`);
            if (ep.schemaRefresh && ep.schemaRefresh !== '5m') lines.push(`SchemaRefresh = ${this._q(ep.schemaRefresh)}`);
          }
          if (ep.methodWhitelist) lines.push('MethodWhitelist = true');
          if (ep.maxBatchSize > 0) lines.push(`MaxBatchSize = ${ep.maxBatchSize}`);
        }
      }
    },

    // --- Management ---
    _genManagement(c, D, lines) {
      if (c.management.listen !== D.management.listen) {
        lines.push('');
        lines.push('[Management]');
        lines.push(`Listen = ${this._q(c.management.listen)}`);
      }
    },

    // --- WAF ---
    _genWAF(c, lines) {
      if (!c.waf.enabled) return;
      lines.push('');
      lines.push('# === WAF ===');
      lines.push('');
      lines.push('[WAF]');
      lines.push('Enabled = true');
      lines.push(`Mode = ${this._q(c.waf.mode)}`);
      if (c.waf.paranoiaLevel !== 1) lines.push(`ParanoiaLevel = ${c.waf.paranoiaLevel}`);
    },

    // --- RateLimit ---
    _genRateLimit(c, lines) {
      if (!c.rateLimit.enabled) return;
      lines.push('');
      lines.push('# === Rate Limiting ===');
      lines.push('');
      lines.push('[RateLimit]');
      lines.push('Enabled = true');
      if (c.rateLimit.perIP !== '100/min') lines.push(`PerIP = ${this._q(c.rateLimit.perIP)}`);
      if (c.rateLimit.action !== 'block') lines.push(`Action = ${this._q(c.rateLimit.action)}`);
      if (c.rateLimit.maxCounters !== 100000) lines.push(`MaxCounters = ${c.rateLimit.maxCounters}`);

      for (const r of c.rateLimit.rules) {
        if (!r.name) continue;
        lines.push('');
        lines.push('[[RateLimit.Rules]]');
        lines.push(`Name = ${this._q(r.name)}`);
        if (r.endpoint) lines.push(`Endpoint = ${this._q(r.endpoint)}`);
        if (r.match.length > 0) lines.push(`Match = [${r.match.map(m => this._q(m)).join(', ')}]`);
        lines.push(`Limit = ${this._q(r.limit)}`);
        if (r.action) lines.push(`Action = ${this._q(r.action)}`);
      }
    },

    // --- IP ---
    _genIP(c, D, lines) {
      const hasGeo = c.ip.geoDatabase || c.ip.asnDatabase;
      const hasWL = c.ip.whitelist.cidrs.length > 0;
      const hasBL = c.ip.blacklist.cidrs.length > 0;
      const hasCountries = c.ip.countries.block.length > 0 || c.ip.countries.captcha.length > 0 || c.ip.countries.log.length > 0;
      const verifyChanged = c.ip.whitelist.verifyBots !== D.ip.whitelist.verifyBots;
      const hasReputation = c.ip.reputation && c.ip.reputation.enabled;

      if (!hasGeo && !hasWL && !hasBL && !hasCountries && !verifyChanged && !hasReputation) return;

      lines.push('');
      lines.push('# === IP Intelligence ===');
      lines.push('');
      lines.push('[IP]');
      if (c.ip.geoDatabase) lines.push(`GeoDatabase = ${this._q(c.ip.geoDatabase)}`);
      if (c.ip.asnDatabase) lines.push(`ASNDatabase = ${this._q(c.ip.asnDatabase)}`);

      if (hasWL || verifyChanged) {
        lines.push('');
        lines.push('[IP.Whitelist]');
        if (hasWL) lines.push(`CIDRs = [${c.ip.whitelist.cidrs.map(s => this._q(s)).join(', ')}]`);
        if (verifyChanged) lines.push(`VerifyBots = ${c.ip.whitelist.verifyBots}`);
      }

      if (hasBL) {
        lines.push('');
        lines.push('[IP.Blacklist]');
        lines.push(`CIDRs = [${c.ip.blacklist.cidrs.map(s => this._q(s)).join(', ')}]`);
      }

      if (hasCountries) {
        lines.push('');
        lines.push('[IP.Countries]');
        if (c.ip.countries.block.length > 0) lines.push(`Block = [${c.ip.countries.block.map(s => this._q(s)).join(', ')}]`);
        if (c.ip.countries.captcha.length > 0) lines.push(`Captcha = [${c.ip.countries.captcha.map(s => this._q(s)).join(', ')}]`);
        if (c.ip.countries.log.length > 0) lines.push(`Log = [${c.ip.countries.log.map(s => this._q(s)).join(', ')}]`);
      }

      if (hasReputation) {
        const r = c.ip.reputation;
        const dr = D.ip.reputation;
        lines.push('');
        lines.push('[IP.Reputation]');
        lines.push('Enabled = true');
        if (r.updateInterval !== dr.updateInterval) lines.push(`UpdateInterval = ${this._q(r.updateInterval)}`);
        if (r.scoreAdjustment !== dr.scoreAdjustment) lines.push(`ScoreAdjustment = ${r.scoreAdjustment}`);
        if (!r.firehol.enabled) {
          lines.push('');
          lines.push('[IP.Reputation.FireHOL]');
          lines.push('Enabled = false');
        } else if (r.firehol.level !== dr.firehol.level) {
          lines.push('');
          lines.push('[IP.Reputation.FireHOL]');
          lines.push(`Level = ${r.firehol.level}`);
        }
        if (!r.tor.enabled) {
          lines.push('');
          lines.push('[IP.Reputation.Tor]');
          lines.push('Enabled = false');
        } else if (r.tor.action !== dr.tor.action) {
          lines.push('');
          lines.push('[IP.Reputation.Tor]');
          lines.push(`Action = ${this._q(r.tor.action)}`);
        }
        if (!r.datacenter.enabled) {
          lines.push('');
          lines.push('[IP.Reputation.Datacenter]');
          lines.push('Enabled = false');
        } else if (r.datacenter.scoreAdjustment !== dr.datacenter.scoreAdjustment) {
          lines.push('');
          lines.push('[IP.Reputation.Datacenter]');
          lines.push(`ScoreAdjustment = ${r.datacenter.scoreAdjustment}`);
        }
        for (const f of (r.feeds || [])) {
          if (!f.url) continue;
          lines.push('');
          lines.push('[[IP.Reputation.Feeds]]');
          if (f.name) lines.push(`Name = ${this._q(f.name)}`);
          lines.push(`URL = ${this._q(f.url)}`);
          if (f.action && f.action !== 'score') lines.push(`Action = ${this._q(f.action)}`);
        }
      }
    },

    // --- TrafficFilter ---
    _genTrafficFilter(c, lines) {
      if (!c.trafficFilter.enabled) return;
      lines.push('');
      lines.push('# === Traffic Filter ===');
      lines.push('');
      lines.push('[TrafficFilter]');
      lines.push('Enabled = true');

      // Use trafficConditions as single source of truth for field mapping
      for (const r of c.trafficFilter.rules) {
        if (!r.name) continue;
        lines.push('');
        lines.push('[[TrafficFilter.Rules]]');
        lines.push(`Name = ${this._q(r.name)}`);
        lines.push(`Action = ${this._q(r.action)}`);
        for (const cond of this.trafficConditions) {
          if (r[cond.key] && r[cond.key].length > 0) {
            const vals = cond.numeric ? r[cond.key].join(', ') : r[cond.key].map(v => this._q(v)).join(', ');
            lines.push(`${cond.toml} = [${vals}]`);
          }
        }
      }
    },

    // --- Signing ---
    _genSigning(c, lines) {
      if (!c.signing.enabled) return;
      lines.push('');
      lines.push('# === Request Signing ===');
      lines.push('');
      lines.push('[Signing]');
      lines.push('Enabled = true');
      if (c.signing.mode !== 'detection') lines.push(`Mode = ${this._q(c.signing.mode)}`);
      if (c.signing.ttl !== '5m') lines.push(`TTL = ${this._q(c.signing.ttl)}`);
      if (c.signing.nonceCache !== 100000) lines.push(`NonceCache = ${c.signing.nonceCache}`);

      for (const [key, label] of [['web', 'Web'], ['android', 'Android'], ['ios', 'IOS']]) {
        const p = c.signing[key];
        if (p.enabled || p.secret) {
          lines.push('');
          lines.push(`[Signing.${label}]`);
          if (p.enabled) lines.push('Enabled = true');
          if (p.secret) lines.push(`Secret = ${this._q(p.secret)}`);
          if (p.minVersion) lines.push(`MinVersion = ${this._q(p.minVersion)}`);
          if (p.notifyOnly) lines.push('NotifyOnly = true');
        }
      }

      for (const m of c.signing.methods) {
        if (!m.name) continue;
        lines.push('');
        lines.push('[[Signing.Methods]]');
        lines.push(`Name = ${this._q(m.name)}`);
        if (m.endpoint) lines.push(`Endpoint = ${this._q(m.endpoint)}`);
        if (m.methods.length > 0) lines.push(`Methods = [${m.methods.map(v => this._q(v)).join(', ')}]`);
        if (m.platforms.length > 0) lines.push(`Platforms = [${m.platforms.map(v => this._q(v)).join(', ')}]`);
        if (m.signFields.length > 0) lines.push(`SignFields = [${m.signFields.map(v => this._q(v)).join(', ')}]`);
      }
    },

    // --- Decision ---
    _genDecision(c, D, lines) {
      const d = c.decision;
      const dd = D.decision;
      const hasNonDefault = d.captchaThreshold !== dd.captchaThreshold || d.blockThreshold !== dd.blockThreshold ||
        d.captchaStatusCode !== dd.captchaStatusCode || d.blockStatusCode !== dd.blockStatusCode ||
        d.captchaToBlock !== dd.captchaToBlock || d.captchaToBlockWindow !== dd.captchaToBlockWindow ||
        d.softBlockDuration !== dd.softBlockDuration || d.captchaFallback !== dd.captchaFallback ||
        d.platforms.length > 0;

      if (!hasNonDefault) return;

      // Collect scalar lines first
      const scalarLines = [];
      if (d.captchaThreshold !== dd.captchaThreshold) scalarLines.push(`CaptchaThreshold = ${d.captchaThreshold}`);
      if (d.blockThreshold !== dd.blockThreshold) scalarLines.push(`BlockThreshold = ${d.blockThreshold}`);
      if (d.captchaStatusCode !== dd.captchaStatusCode) scalarLines.push(`CaptchaStatusCode = ${d.captchaStatusCode}`);
      if (d.blockStatusCode !== dd.blockStatusCode) scalarLines.push(`BlockStatusCode = ${d.blockStatusCode}`);
      if (d.captchaToBlock !== dd.captchaToBlock) scalarLines.push(`CaptchaToBlock = ${d.captchaToBlock}`);
      if (d.captchaToBlockWindow !== dd.captchaToBlockWindow) scalarLines.push(`CaptchaToBlockWindow = ${this._q(d.captchaToBlockWindow)}`);
      if (d.softBlockDuration !== dd.softBlockDuration) scalarLines.push(`SoftBlockDuration = ${this._q(d.softBlockDuration)}`);
      if (d.captchaFallback !== dd.captchaFallback) scalarLines.push(`CaptchaFallback = ${this._q(d.captchaFallback)}`);

      lines.push('');
      lines.push('# === Decision Engine ===');
      if (scalarLines.length > 0) {
        lines.push('');
        lines.push('[Decision]');
        lines.push(...scalarLines);
      }

      for (const p of d.platforms) {
        if (!p.platform) continue;
        lines.push('');
        lines.push('[[Decision.Platforms]]');
        lines.push(`Platform = ${this._q(p.platform)}`);
        lines.push(`Captcha = ${p.captcha}`);
        if (p.minVersion) lines.push(`MinVersion = ${this._q(p.minVersion)}`);
        if (p.fallback) lines.push(`Fallback = ${this._q(p.fallback)}`);
      }
    },

    // --- Captcha ---
    _genCaptcha(c, D, lines) {
      if (!c.captcha.provider) return;
      lines.push('');
      lines.push('# === CAPTCHA ===');
      lines.push('');
      lines.push('[Captcha]');
      lines.push(`Provider = ${this._q(c.captcha.provider)}`);
      // SiteKey/SecretKey only for turnstile/hcaptcha
      if (c.captcha.provider !== 'pow') {
        if (c.captcha.siteKey) lines.push(`SiteKey = ${this._q(c.captcha.siteKey)}`);
        if (c.captcha.secretKey) lines.push(`SecretKey = ${this._q(c.captcha.secretKey)}`);
      }
      if (c.captcha.cookieName !== D.captcha.cookieName) lines.push(`CookieName = ${this._q(c.captcha.cookieName)}`);
      if (c.captcha.cookieTTL !== D.captcha.cookieTTL) lines.push(`CookieTTL = ${this._q(c.captcha.cookieTTL)}`);
      if (c.captcha.ipCacheTTL !== D.captcha.ipCacheTTL) lines.push(`IPCacheTTL = ${this._q(c.captcha.ipCacheTTL)}`);

      // PoW sub-section
      if (c.captcha.provider === 'pow') {
        const pw = c.captcha.pow;
        const dpw = D.captcha.pow;
        const changed = pw.difficulty !== dpw.difficulty || pw.attackDifficulty !== dpw.attackDifficulty ||
          pw.timeout !== dpw.timeout || pw.saltTTL !== dpw.saltTTL;
        if (changed) {
          lines.push('');
          lines.push('[Captcha.PoW]');
          if (pw.difficulty !== dpw.difficulty) lines.push(`Difficulty = ${pw.difficulty}`);
          if (pw.attackDifficulty !== dpw.attackDifficulty) lines.push(`AttackDifficulty = ${pw.attackDifficulty}`);
          if (pw.timeout !== dpw.timeout) lines.push(`Timeout = ${this._q(pw.timeout)}`);
          if (pw.saltTTL !== dpw.saltTTL) lines.push(`SaltTTL = ${this._q(pw.saltTTL)}`);
        }
      }
    },

    // --- Alerting ---
    _genAlerting(c, lines) {
      if (!c.alerting.enabled) return;
      lines.push('');
      lines.push('# === Alerting ===');
      lines.push('');
      lines.push('[Alerting]');
      lines.push('Enabled = true');

      for (const w of c.alerting.webhooks) {
        lines.push('');
        lines.push('[[Alerting.Webhooks]]');
        lines.push(`URL = ${this._q(w.url)}`);
        if (w.events.length > 0) lines.push(`Events = [${w.events.map(e => this._q(e)).join(', ')}]`);
        if (w.minInterval !== '5m') lines.push(`MinInterval = ${this._q(w.minInterval)}`);
      }
    },

    // --- Adaptive ---
    _genAdaptive(c, D, lines) {
      if (!c.adaptive.enabled) return;
      const a = c.adaptive;
      const da = D.adaptive;

      lines.push('');
      lines.push('# === Adaptive ===');
      lines.push('');
      lines.push('[Adaptive]');
      lines.push('Enabled = true');
      lines.push(`Mode = ${this._q(a.mode)}`);
      if (a.evalInterval !== da.evalInterval) lines.push(`EvalInterval = ${this._q(a.evalInterval)}`);
      if (a.warmupDuration !== da.warmupDuration) lines.push(`WarmupDuration = ${this._q(a.warmupDuration)}`);

      const aa = a.autoAttack;
      const daa = da.autoAttack;
      const aaChanged = aa.rpsMultiplier !== daa.rpsMultiplier || aa.rpsRecoveryMultiplier !== daa.rpsRecoveryMultiplier ||
        aa.minRPS !== daa.minRPS || aa.errorRateThreshold !== daa.errorRateThreshold ||
        aa.latencyThresholdMs !== daa.latencyThresholdMs || aa.blockedRateThreshold !== daa.blockedRateThreshold ||
        aa.window !== daa.window || aa.cooldown !== daa.cooldown || aa.duration !== daa.duration;

      if (aaChanged) {
        lines.push('');
        lines.push('[Adaptive.AutoAttack]');
        if (aa.rpsMultiplier !== daa.rpsMultiplier) lines.push(`RPSMultiplier = ${aa.rpsMultiplier}`);
        if (aa.rpsRecoveryMultiplier !== daa.rpsRecoveryMultiplier) lines.push(`RPSRecoveryMultiplier = ${aa.rpsRecoveryMultiplier}`);
        if (aa.minRPS !== daa.minRPS) lines.push(`MinRPS = ${aa.minRPS}`);
        if (aa.errorRateThreshold !== daa.errorRateThreshold) lines.push(`ErrorRateThreshold = ${aa.errorRateThreshold}`);
        if (aa.latencyThresholdMs !== daa.latencyThresholdMs) lines.push(`LatencyThresholdMs = ${aa.latencyThresholdMs}`);
        if (aa.blockedRateThreshold !== daa.blockedRateThreshold) lines.push(`BlockedRateThreshold = ${aa.blockedRateThreshold}`);
        if (aa.window !== daa.window) lines.push(`Window = ${this._q(aa.window)}`);
        if (aa.cooldown !== daa.cooldown) lines.push(`Cooldown = ${this._q(aa.cooldown)}`);
        if (aa.duration !== daa.duration) lines.push(`Duration = ${this._q(aa.duration)}`);
      }
    },

    // --- Storage ---
    _genStorage(c, D, lines) {
      if (c.storage.backend === D.storage.backend) return;
      lines.push('');
      lines.push('# === Storage ===');
      lines.push('');
      lines.push('[Storage]');
      lines.push(`Backend = ${this._q(c.storage.backend)}`);

      if (c.storage.backend === 'aerospike') {
        lines.push('');
        lines.push('[Storage.Aerospike]');
        if (c.storage.aerospike.hosts.length > 0) lines.push(`Hosts = [${c.storage.aerospike.hosts.map(h => this._q(h)).join(', ')}]`);
        if (c.storage.aerospike.namespace !== 'wafsrv') lines.push(`Namespace = ${this._q(c.storage.aerospike.namespace)}`);
        if (c.storage.aerospike.keyPrefix) lines.push(`KeyPrefix = ${this._q(c.storage.aerospike.keyPrefix)}`);
        if (c.storage.aerospike.connectTimeout !== '5s') lines.push(`ConnectTimeout = ${this._q(c.storage.aerospike.connectTimeout)}`);
        if (c.storage.aerospike.operTimeout !== '50ms') lines.push(`OperTimeout = ${this._q(c.storage.aerospike.operTimeout)}`);
      }
    },

    // --- Helpers ---
    _q(s) { return '"' + (s || '').replace(/\\/g, '\\\\').replace(/"/g, '\\"') + '"'; },

    _arrEq(a, b) {
      if (a.length !== b.length) return false;
      return a.every((v, i) => v === b[i]);
    },
  };
}
