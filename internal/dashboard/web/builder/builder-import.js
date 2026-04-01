// builder-import.js — TOML import: parse TOML string into config state

function builderImport() {
  return {
    showImport: false,
    importText: '',
    importError: '',

    openImport() {
      this.showImport = true;
      this.importText = '';
      this.importError = '';
    },

    closeImport() {
      this.showImport = false;
    },

    doImport() {
      try {
        const parsed = this._parseToml(this.importText);
        this._applyParsed(parsed);
        this.showImport = false;
        this.activePreset = 'custom';
        this.onChange();
      } catch (e) {
        this.importError = e.message;
      }
    },

    // --- Minimal TOML parser (covers wafsrv config subset) ---
    _parseToml(text) {
      const result = {};
      let currentPath = [];
      let currentObj = result;
      let isArrayTable = false;

      const lines = text.split('\n');
      for (let i = 0; i < lines.length; i++) {
        const raw = lines[i];
        const line = raw.replace(/#.*$/, '').trim();
        if (!line) continue;

        // Array of tables: [[Foo.Bar]]
        const arrMatch = line.match(/^\[\[(.+)\]\]$/);
        if (arrMatch) {
          currentPath = arrMatch[1].split('.').map(s => s.trim());
          isArrayTable = true;
          currentObj = this._ensureArrayTable(result, currentPath);
          continue;
        }

        // Table: [Foo.Bar]
        const tblMatch = line.match(/^\[(.+)\]$/);
        if (tblMatch) {
          currentPath = tblMatch[1].split('.').map(s => s.trim());
          isArrayTable = false;
          currentObj = this._ensureTable(result, currentPath);
          continue;
        }

        // Key = Value
        const kvMatch = line.match(/^(\w+)\s*=\s*(.+)$/);
        if (kvMatch) {
          const key = kvMatch[1];
          const val = this._parseValue(kvMatch[2].trim());
          currentObj[key] = val;
          continue;
        }
      }

      return result;
    },

    _ensureTable(root, path) {
      let obj = root;
      for (const key of path) {
        if (!(key in obj)) obj[key] = {};
        obj = obj[key];
        // If we hit an array (from [[...]]), get last element
        if (Array.isArray(obj)) obj = obj[obj.length - 1];
      }
      return obj;
    },

    _ensureArrayTable(root, path) {
      let obj = root;
      for (let i = 0; i < path.length; i++) {
        const key = path[i];
        if (i === path.length - 1) {
          // Last segment: ensure array and push new object
          if (!(key in obj)) obj[key] = [];
          if (!Array.isArray(obj[key])) obj[key] = [obj[key]];
          const item = {};
          obj[key].push(item);
          return item;
        }
        if (!(key in obj)) obj[key] = {};
        obj = obj[key];
        if (Array.isArray(obj)) obj = obj[obj.length - 1];
      }
      return obj;
    },

    _parseValue(s) {
      // Boolean
      if (s === 'true') return true;
      if (s === 'false') return false;

      // String
      if (s.startsWith('"') && s.endsWith('"')) {
        return s.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, '\\');
      }

      // Array
      if (s.startsWith('[')) {
        return this._parseArray(s);
      }

      // Number (int or float)
      const num = Number(s);
      if (!isNaN(num) && s !== '') return num;

      return s;
    },

    _parseArray(s) {
      // Remove outer brackets
      const inner = s.slice(1, -1).trim();
      if (!inner) return [];

      const items = [];
      let current = '';
      let inString = false;
      let depth = 0;

      for (let i = 0; i < inner.length; i++) {
        const ch = inner[i];
        if (ch === '"' && inner[i - 1] !== '\\') {
          inString = !inString;
          current += ch;
        } else if (!inString && ch === '[') {
          depth++;
          current += ch;
        } else if (!inString && ch === ']') {
          depth--;
          current += ch;
        } else if (!inString && depth === 0 && ch === ',') {
          items.push(this._parseValue(current.trim()));
          current = '';
        } else {
          current += ch;
        }
      }
      if (current.trim()) items.push(this._parseValue(current.trim()));

      return items;
    },

    // --- Apply parsed TOML to config ---
    _applyParsed(t) {
      const cfg = this.defaultConfig();

      // Proxy
      if (t.Proxy) {
        const p = t.Proxy;
        if (p.Listen) cfg.proxy.listen = p.Listen;
        if (p.Targets) cfg.proxy.targets = [...p.Targets];
        if (p.ServiceName) cfg.proxy.serviceName = p.ServiceName;
        if (p.Platforms) cfg.proxy.platforms = [...p.Platforms];
        if (p.Timeouts) {
          if (p.Timeouts.Read) cfg.proxy.timeouts.read = p.Timeouts.Read;
          if (p.Timeouts.Write) cfg.proxy.timeouts.write = p.Timeouts.Write;
          if (p.Timeouts.Idle) cfg.proxy.timeouts.idle = p.Timeouts.Idle;
        }
        if (p.Limits && p.Limits.MaxRequestBody) cfg.proxy.limits.maxRequestBody = p.Limits.MaxRequestBody;
        if (p.RealIP) {
          if (p.RealIP.Headers) cfg.proxy.realIP.headers = [...p.RealIP.Headers];
          if (p.RealIP.TrustedProxies) cfg.proxy.realIP.trustedProxies = [...p.RealIP.TrustedProxies];
        }
        if (p.CircuitBreaker) {
          if (p.CircuitBreaker.Enabled !== undefined) cfg.proxy.circuitBreaker.enabled = p.CircuitBreaker.Enabled;
          if (p.CircuitBreaker.Threshold) cfg.proxy.circuitBreaker.threshold = p.CircuitBreaker.Threshold;
          if (p.CircuitBreaker.Timeout) cfg.proxy.circuitBreaker.timeout = p.CircuitBreaker.Timeout;
        }
        if (p.Static) {
          if (p.Static.Paths) cfg.proxy.static.paths = [...p.Static.Paths];
          if (p.Static.Extensions) cfg.proxy.static.extensions = [...p.Static.Extensions];
        }
      }

      // JSONRPC
      if (t.JSONRPC && t.JSONRPC.Endpoints) {
        cfg.jsonrpc.endpoints = t.JSONRPC.Endpoints.map(e => ({
          ...this.defaultEndpoint(),
          path: e.Path || '/rpc/', name: e.Name || 'main',
          schemaURL: e.SchemaURL || '', schemaRefresh: e.SchemaRefresh || '5m',
          methodWhitelist: e.MethodWhitelist || false, maxBatchSize: e.MaxBatchSize || 0,
        }));
      }

      // Management
      if (t.Management && t.Management.Listen) cfg.management.listen = t.Management.Listen;

      // WAF
      if (t.WAF) {
        if (t.WAF.Enabled) cfg.waf.enabled = true;
        if (t.WAF.Mode) cfg.waf.mode = t.WAF.Mode;
        if (t.WAF.ParanoiaLevel) cfg.waf.paranoiaLevel = t.WAF.ParanoiaLevel;
      }

      // RateLimit
      if (t.RateLimit) {
        if (t.RateLimit.Enabled) cfg.rateLimit.enabled = true;
        if (t.RateLimit.PerIP) cfg.rateLimit.perIP = t.RateLimit.PerIP;
        if (t.RateLimit.Action) cfg.rateLimit.action = t.RateLimit.Action;
        if (t.RateLimit.MaxCounters) cfg.rateLimit.maxCounters = t.RateLimit.MaxCounters;
        if (t.RateLimit.Rules) {
          cfg.rateLimit.rules = t.RateLimit.Rules.map(r => ({
            ...this.defaultRateLimitRule(),
            name: r.Name || '', endpoint: r.Endpoint || '',
            match: r.Match ? [...r.Match] : [], limit: r.Limit || '10/min', action: r.Action || '',
          }));
        }
      }

      // IP
      if (t.IP) {
        if (t.IP.GeoDatabase) cfg.ip.geoDatabase = t.IP.GeoDatabase;
        if (t.IP.ASNDatabase) cfg.ip.asnDatabase = t.IP.ASNDatabase;
        if (t.IP.Whitelist) {
          if (t.IP.Whitelist.CIDRs) cfg.ip.whitelist.cidrs = [...t.IP.Whitelist.CIDRs];
          if (t.IP.Whitelist.VerifyBots !== undefined) cfg.ip.whitelist.verifyBots = t.IP.Whitelist.VerifyBots;
        }
        if (t.IP.Blacklist && t.IP.Blacklist.CIDRs) cfg.ip.blacklist.cidrs = [...t.IP.Blacklist.CIDRs];
        if (t.IP.Countries) {
          if (t.IP.Countries.Block) cfg.ip.countries.block = [...t.IP.Countries.Block];
          if (t.IP.Countries.Captcha) cfg.ip.countries.captcha = [...t.IP.Countries.Captcha];
          if (t.IP.Countries.Log) cfg.ip.countries.log = [...t.IP.Countries.Log];
        }
        if (t.IP.Reputation) {
          const r = t.IP.Reputation;
          if (r.Enabled) cfg.ip.reputation.enabled = true;
          if (r.UpdateInterval) cfg.ip.reputation.updateInterval = r.UpdateInterval;
          if (r.ScoreAdjustment !== undefined) cfg.ip.reputation.scoreAdjustment = r.ScoreAdjustment;
          if (r.FireHOL) {
            if (r.FireHOL.Enabled !== undefined) cfg.ip.reputation.firehol.enabled = r.FireHOL.Enabled;
            if (r.FireHOL.Level !== undefined) cfg.ip.reputation.firehol.level = r.FireHOL.Level;
          }
          if (r.Tor) {
            if (r.Tor.Enabled !== undefined) cfg.ip.reputation.tor.enabled = r.Tor.Enabled;
            if (r.Tor.Action) cfg.ip.reputation.tor.action = r.Tor.Action;
          }
          if (r.Datacenter) {
            if (r.Datacenter.Enabled !== undefined) cfg.ip.reputation.datacenter.enabled = r.Datacenter.Enabled;
            if (r.Datacenter.ScoreAdjustment !== undefined) cfg.ip.reputation.datacenter.scoreAdjustment = r.Datacenter.ScoreAdjustment;
            if (r.Datacenter.ExtraASNs) cfg.ip.reputation.datacenter.extraASNs = [...r.Datacenter.ExtraASNs];
          }
          if (r.Feeds) {
            cfg.ip.reputation.feeds = r.Feeds.map(f => ({name: f.Name || '', url: f.URL || '', action: f.Action || 'score'}));
          }
        }
      }

      // TrafficFilter
      if (t.TrafficFilter) {
        if (t.TrafficFilter.Enabled) cfg.trafficFilter.enabled = true;
        if (t.TrafficFilter.Rules) {
          // Use trafficConditions as single source of truth for TOML↔JS mapping
          cfg.trafficFilter.rules = t.TrafficFilter.Rules.map(r => {
            const rule = {...this.defaultTrafficRule(), name: r.Name || '', action: r.Action || 'block'};
            for (const cond of this.trafficConditions) {
              if (r[cond.toml]) rule[cond.key] = [...r[cond.toml]];
            }
            return rule;
          });
        }
      }

      // Signing
      if (t.Signing) {
        if (t.Signing.Enabled) cfg.signing.enabled = true;
        if (t.Signing.Mode) cfg.signing.mode = t.Signing.Mode;
        if (t.Signing.TTL) cfg.signing.ttl = t.Signing.TTL;
        if (t.Signing.NonceCache) cfg.signing.nonceCache = t.Signing.NonceCache;
        for (const [toml, js] of [['Web', 'web'], ['Android', 'android'], ['IOS', 'ios']]) {
          if (t.Signing[toml]) {
            const sp = t.Signing[toml];
            if (sp.Enabled) cfg.signing[js].enabled = true;
            if (sp.Secret) cfg.signing[js].secret = sp.Secret;
            if (sp.MinVersion) cfg.signing[js].minVersion = sp.MinVersion;
            if (sp.NotifyOnly) cfg.signing[js].notifyOnly = true;
          }
        }
        if (t.Signing.Methods) {
          cfg.signing.methods = t.Signing.Methods.map(m => ({
            ...this.defaultSigningMethod(),
            name: m.Name || '', endpoint: m.Endpoint || '',
            methods: m.Methods ? [...m.Methods] : [],
            platforms: m.Platforms ? [...m.Platforms] : [],
            signFields: m.SignFields ? [...m.SignFields] : [],
          }));
        }
      }

      // Decision
      if (t.Decision) {
        const d = t.Decision;
        if (d.CaptchaThreshold) cfg.decision.captchaThreshold = d.CaptchaThreshold;
        if (d.BlockThreshold) cfg.decision.blockThreshold = d.BlockThreshold;
        if (d.CaptchaStatusCode) cfg.decision.captchaStatusCode = d.CaptchaStatusCode;
        if (d.BlockStatusCode) cfg.decision.blockStatusCode = d.BlockStatusCode;
        if (d.CaptchaToBlock) cfg.decision.captchaToBlock = d.CaptchaToBlock;
        if (d.CaptchaToBlockWindow) cfg.decision.captchaToBlockWindow = d.CaptchaToBlockWindow;
        if (d.SoftBlockDuration) cfg.decision.softBlockDuration = d.SoftBlockDuration;
        if (d.CaptchaFallback) cfg.decision.captchaFallback = d.CaptchaFallback;
        if (d.Platforms) {
          cfg.decision.platforms = d.Platforms.map(p => ({
            ...this.defaultPlatformCaptcha(),
            platform: p.Platform || '', captcha: p.Captcha ?? true,
            minVersion: p.MinVersion || '', fallback: p.Fallback || '',
          }));
        }
      }

      // Captcha
      if (t.Captcha) {
        if (t.Captcha.Provider) cfg.captcha.provider = t.Captcha.Provider;
        if (t.Captcha.SiteKey) cfg.captcha.siteKey = t.Captcha.SiteKey;
        if (t.Captcha.SecretKey) cfg.captcha.secretKey = t.Captcha.SecretKey;
        if (t.Captcha.CookieName) cfg.captcha.cookieName = t.Captcha.CookieName;
        if (t.Captcha.CookieTTL) cfg.captcha.cookieTTL = t.Captcha.CookieTTL;
        if (t.Captcha.IPCacheTTL) cfg.captcha.ipCacheTTL = t.Captcha.IPCacheTTL;
        if (t.Captcha.PoW) {
          const pw = t.Captcha.PoW;
          if (pw.Difficulty !== undefined) cfg.captcha.pow.difficulty = pw.Difficulty;
          if (pw.AttackDifficulty !== undefined) cfg.captcha.pow.attackDifficulty = pw.AttackDifficulty;
          if (pw.Timeout) cfg.captcha.pow.timeout = pw.Timeout;
          if (pw.SaltTTL) cfg.captcha.pow.saltTTL = pw.SaltTTL;
        }
      }

      // Alerting
      if (t.Alerting) {
        if (t.Alerting.Enabled) cfg.alerting.enabled = true;
        if (t.Alerting.Webhooks) {
          cfg.alerting.webhooks = t.Alerting.Webhooks.map(w => ({
            ...this.defaultWebhook(),
            url: w.URL || '', events: w.Events ? [...w.Events] : [],
            minInterval: w.MinInterval || '5m',
          }));
        }
      }

      // Adaptive
      if (t.Adaptive) {
        if (t.Adaptive.Enabled) cfg.adaptive.enabled = true;
        if (t.Adaptive.Mode) cfg.adaptive.mode = t.Adaptive.Mode;
        if (t.Adaptive.EvalInterval) cfg.adaptive.evalInterval = t.Adaptive.EvalInterval;
        if (t.Adaptive.WarmupDuration) cfg.adaptive.warmupDuration = t.Adaptive.WarmupDuration;
        if (t.Adaptive.AutoAttack) {
          const a = t.Adaptive.AutoAttack;
          const aa = cfg.adaptive.autoAttack;
          if (a.RPSMultiplier !== undefined) aa.rpsMultiplier = a.RPSMultiplier;
          if (a.RPSRecoveryMultiplier !== undefined) aa.rpsRecoveryMultiplier = a.RPSRecoveryMultiplier;
          if (a.MinRPS !== undefined) aa.minRPS = a.MinRPS;
          if (a.ErrorRateThreshold !== undefined) aa.errorRateThreshold = a.ErrorRateThreshold;
          if (a.LatencyThresholdMs !== undefined) aa.latencyThresholdMs = a.LatencyThresholdMs;
          if (a.BlockedRateThreshold !== undefined) aa.blockedRateThreshold = a.BlockedRateThreshold;
          if (a.Window) aa.window = a.Window;
          if (a.Cooldown) aa.cooldown = a.Cooldown;
          if (a.Duration) aa.duration = a.Duration;
        }
      }

      // Storage
      if (t.Storage) {
        if (t.Storage.Backend) cfg.storage.backend = t.Storage.Backend;
        if (t.Storage.Aerospike) {
          if (t.Storage.Aerospike.Hosts) cfg.storage.aerospike.hosts = [...t.Storage.Aerospike.Hosts];
          if (t.Storage.Aerospike.Namespace) cfg.storage.aerospike.namespace = t.Storage.Aerospike.Namespace;
          if (t.Storage.Aerospike.KeyPrefix) cfg.storage.aerospike.keyPrefix = t.Storage.Aerospike.KeyPrefix;
          if (t.Storage.Aerospike.ConnectTimeout) cfg.storage.aerospike.connectTimeout = t.Storage.Aerospike.ConnectTimeout;
          if (t.Storage.Aerospike.OperTimeout) cfg.storage.aerospike.operTimeout = t.Storage.Aerospike.OperTimeout;
        }
      }

      this.cfg = cfg;
    },
  };
}
