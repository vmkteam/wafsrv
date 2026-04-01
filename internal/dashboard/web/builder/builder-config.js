// builder-config.js — default config, preset definitions, apply logic

function builderConfig() {
  return {
    // --- Default config (all sections) ---
    defaultConfig() {
      return {
        proxy: {
          listen: ':8080',
          targets: ['http://localhost:3000'],
          serviceName: '',
          platforms: [],
          timeouts: {read: '30s', write: '30s', idle: '120s'},
          limits: {maxRequestBody: '1MB'},
          realIP: {
            headers: ['X-Real-IP', 'X-Forwarded-For'],
            trustedProxies: ['10.0.0.0/8', '172.16.0.0/12', '192.168.0.0/16'],
          },
          circuitBreaker: {enabled: true, threshold: 10, timeout: '30s'},
          static: {paths: [], extensions: []},
          targetDiscovery: {enabled: false, hostname: '', service: '', proto: '', scheme: 'http', dnsServer: '', refreshInterval: '1s', resolveTimeout: '3s'},
        },
        jsonrpc: {
          endpoints: [this.defaultEndpoint()],
        },
        management: {listen: '127.0.0.1:8081'},
        waf: {enabled: false, mode: 'detection', paranoiaLevel: 1},
        rateLimit: {
          enabled: false, perIP: '100/min', action: 'block', maxCounters: 100000,
          rules: [],
        },
        ip: {
          geoDatabase: '', asnDatabase: '',
          whitelist: {cidrs: [], verifyBots: true, botDomains: ['googlebot.com', 'search.msn.com', 'yandex.ru', 'yandex.net', 'yandex.com'],
            botVerify: {cacheSize: 10000, cacheTTL: '1h', dnsTimeout: '2s', rangesRefresh: '24h', fakeBotScore: 5.0}},
          blacklist: {cidrs: []},
          countries: {block: [], captcha: [], log: []},
          reputation: {enabled: false, updateInterval: '1h', scoreAdjustment: 3.0,
            firehol: {enabled: true, level: 1}, tor: {enabled: true, action: 'score'},
            datacenter: {enabled: true, scoreAdjustment: 2.0, extraASNs: []}, feeds: []},
        },
        trafficFilter: {enabled: false, rules: []},
        signing: {
          enabled: false, mode: 'detection', ttl: '5m', nonceCache: 100000,
          web: {enabled: false, secret: '', minVersion: '', notifyOnly: false},
          android: {enabled: false, secret: '', minVersion: '', notifyOnly: false},
          ios: {enabled: false, secret: '', minVersion: '', notifyOnly: false},
          methods: [],
        },
        decision: {
          captchaThreshold: 5, blockThreshold: 8,
          captchaStatusCode: 499, blockStatusCode: 403,
          captchaToBlock: 3, captchaToBlockWindow: '10m',
          softBlockDuration: '10m', captchaFallback: 'block',
          platforms: [],
        },
        captcha: {provider: '', siteKey: '', secretKey: '', cookieName: 'waf_pass', cookieTTL: '30m', ipCacheTTL: '30m',
          pow: {difficulty: 50000, attackDifficulty: 500000, timeout: '10s', saltTTL: '5m'}},
        alerting: {enabled: false, webhooks: []},
        adaptive: {
          enabled: false, mode: 'notify', evalInterval: '10s', warmupDuration: '2m',
          autoAttack: {
            rpsMultiplier: 3.0, rpsRecoveryMultiplier: 1.5, minRPS: 10,
            errorRateThreshold: 20, latencyThresholdMs: 500, blockedRateThreshold: 50,
            window: '1m', cooldown: '5m', duration: '10m',
          },
        },
        storage: {backend: 'memory', aerospike: {hosts: [], namespace: 'wafsrv', keyPrefix: '', connectTimeout: '5s', operTimeout: '50ms'}},
      };
    },

    defaultEndpoint() {
      return {path: '/rpc/', name: 'main', schemaURL: '', schemaRefresh: '5m', methodWhitelist: false, maxBatchSize: 0};
    },

    defaultRateLimitRule() {
      return {name: '', endpoint: '', match: [], limit: '10/min', action: ''};
    },

    defaultSigningMethod() {
      return {name: '', endpoint: '', methods: [], platforms: [], signFields: []};
    },

    defaultPlatformCaptcha() {
      return {platform: '', captcha: true, minVersion: '', fallback: ''};
    },

    defaultWebhook() {
      return {url: '', events: [], minInterval: '5m'};
    },

    defaultTrafficRule() {
      return {
        name: '', action: 'block',
        uaPrefix: [], uaContains: [], uaExact: [], uaExclude: [],
        country: [], platform: [], version: [],
        ip: [], asn: [], rpcMethod: [],
        host: [], path: [], method: [], referer: [],
      };
    },

    // --- Presets ---
    presetDefs: {
      'minimal': {
        proxy: {serviceName: 'myapp'},
      },
      'api-gateway': {
        proxy: {serviceName: 'apisrv'},
        rateLimit: {
          enabled: true,
          rules: [
            {name: 'login', endpoint: 'main', match: ['auth.login', 'auth.loginByPhone'], limit: '10/min', action: ''},
            {name: 'sms', endpoint: 'main', match: ['sms.send'], limit: '3/min', action: ''},
          ],
        },
        ip: {whitelist: {cidrs: ['10.0.0.0/8']}},
      },
      'waf-basic': {
        proxy: {serviceName: 'apisrv', targets: ['http://backend:3000']},
        waf: {enabled: true, mode: 'detection', paranoiaLevel: 1},
        rateLimit: {
          enabled: true,
          rules: [
            {name: 'login', endpoint: 'main', match: ['auth.login'], limit: '10/min', action: ''},
          ],
        },
        ip: {
          geoDatabase: 'data/dbip-country-lite.mmdb', asnDatabase: 'data/dbip-asn-lite.mmdb',
          countries: {captcha: ['CN', 'VN']},
          reputation: {enabled: true},
        },
        trafficFilter: {
          enabled: true,
          rules: [
            {name: 'headless-chrome', action: 'block', uaPrefix: ['HeadlessChrome']},
            {name: 'python-bots', action: 'captcha', uaPrefix: ['Python/', 'python-requests/']},
          ],
        },
      },
      'waf-captcha': {
        proxy: {serviceName: 'apisrv', targets: ['http://backend:3000']},
        waf: {enabled: true, mode: 'detection', paranoiaLevel: 1},
        rateLimit: {
          enabled: true,
          rules: [
            {name: 'login', endpoint: 'main', match: ['auth.login'], limit: '10/min', action: ''},
          ],
        },
        ip: {
          geoDatabase: 'data/dbip-country-lite.mmdb', asnDatabase: 'data/dbip-asn-lite.mmdb',
          countries: {block: ['KP', 'IR'], captcha: ['CN', 'VN', 'TH']},
        },
        trafficFilter: {
          enabled: true,
          rules: [
            {name: 'headless-chrome', action: 'block', uaPrefix: ['HeadlessChrome']},
            {name: 'python-bots', action: 'captcha', uaPrefix: ['Python/', 'python-requests/']},
            {name: 'seo-crawlers', action: 'captcha', uaContains: ['SemrushBot', 'AhrefsBot', 'MJ12bot']},
          ],
        },
        decision: {captchaFallback: 'block'},
        captcha: {provider: 'turnstile'},
        alerting: {
          enabled: true,
          webhooks: [{url: '', events: ['hard_block', 'under_attack'], minInterval: '5m'}],
        },
      },
      'full': {
        proxy: {serviceName: 'apisrv', targets: ['http://backend:3000'], platforms: ['web', 'ios', 'android']},
        jsonrpc: {endpoints: [{path: '/rpc/', name: 'main', schemaURL: '/rpc/', schemaRefresh: '5m', methodWhitelist: true, maxBatchSize: 20}]},
        waf: {enabled: true, mode: 'detection', paranoiaLevel: 1},
        rateLimit: {
          enabled: true,
          rules: [
            {name: 'login', endpoint: 'main', match: ['auth.login', 'auth.loginByPhone'], limit: '10/min', action: ''},
            {name: 'sms', endpoint: 'main', match: ['sms.send'], limit: '3/min', action: ''},
          ],
        },
        ip: {
          geoDatabase: 'data/dbip-country-lite.mmdb', asnDatabase: 'data/dbip-asn-lite.mmdb',
          countries: {block: ['KP', 'IR'], captcha: ['CN', 'VN', 'TH']},
          reputation: {enabled: true, tor: {action: 'captcha'}},
        },
        trafficFilter: {
          enabled: true,
          rules: [
            {name: 'headless-chrome', action: 'block', uaPrefix: ['HeadlessChrome']},
            {name: 'python-bots', action: 'captcha', uaPrefix: ['Python/', 'python-requests/']},
            {name: 'seo-crawlers', action: 'captcha', uaContains: ['SemrushBot', 'AhrefsBot', 'MJ12bot']},
            {name: 'hosting-providers', action: 'captcha', asn: [14061, 16509, 24940]},
          ],
        },
        signing: {enabled: true, mode: 'detection',
          web: {enabled: true}, android: {enabled: true, minVersion: '3.0.0'}, ios: {enabled: true, minVersion: '2.5.0'},
          methods: [{name: 'auth', endpoint: 'main', methods: ['auth.login', 'auth.getCode'], platforms: ['Web', 'Android', 'iOS'], signFields: ['phone', 'email']}],
        },
        decision: {
          captchaFallback: 'block',
          platforms: [
            {platform: 'web', captcha: true},
            {platform: 'ios', captcha: true, minVersion: '2.5.0', fallback: 'pass'},
            {platform: 'android', captcha: true, minVersion: '3.0.0', fallback: 'pass'},
          ],
        },
        captcha: {provider: 'turnstile'},
        alerting: {enabled: true, webhooks: [{url: '', events: ['hard_block', 'under_attack', 'captcha_fail'], minInterval: '5m'}]},
        adaptive: {enabled: true, mode: 'notify'},
      },
      'multi': {
        proxy: {serviceName: 'apisrv', targets: ['http://backend1:3000', 'http://backend2:3000'], platforms: ['web', 'ios', 'android']},
        jsonrpc: {endpoints: [{path: '/rpc/', name: 'main', schemaURL: '/rpc/', schemaRefresh: '5m', methodWhitelist: true, maxBatchSize: 20}]},
        waf: {enabled: true, mode: 'blocking', paranoiaLevel: 1},
        rateLimit: {
          enabled: true,
          rules: [
            {name: 'login', endpoint: 'main', match: ['auth.login', 'auth.loginByPhone'], limit: '10/min', action: ''},
            {name: 'sms', endpoint: 'main', match: ['sms.send'], limit: '3/min', action: ''},
          ],
        },
        ip: {
          geoDatabase: 'data/dbip-country-lite.mmdb', asnDatabase: 'data/dbip-asn-lite.mmdb',
          countries: {block: ['KP', 'IR'], captcha: ['CN', 'VN', 'TH']},
          reputation: {enabled: true, tor: {action: 'captcha'}},
        },
        trafficFilter: {
          enabled: true,
          rules: [
            {name: 'headless-chrome', action: 'block', uaPrefix: ['HeadlessChrome']},
            {name: 'python-bots', action: 'captcha', uaPrefix: ['Python/', 'python-requests/']},
          ],
        },
        signing: {enabled: true, mode: 'detection',
          web: {enabled: true}, android: {enabled: true, minVersion: '3.0.0'}, ios: {enabled: true, minVersion: '2.5.0'},
        },
        decision: {
          captchaFallback: 'block',
          platforms: [
            {platform: 'web', captcha: true},
            {platform: 'ios', captcha: true, minVersion: '2.5.0', fallback: 'pass'},
            {platform: 'android', captcha: true, minVersion: '3.0.0', fallback: 'pass'},
          ],
        },
        captcha: {provider: 'turnstile'},
        alerting: {enabled: true, webhooks: [{url: '', events: ['hard_block', 'under_attack'], minInterval: '5m'}]},
        adaptive: {enabled: true, mode: 'auto'},
        storage: {backend: 'aerospike', aerospike: {hosts: ['127.0.0.1:3000'], keyPrefix: 'apisrv:'}},
      },
      'consul-discovery': {
        proxy: {serviceName: 'apisrv', targets: [], targetDiscovery: {enabled: true, hostname: 'apisrv.service.consul', scheme: 'http', dnsServer: '127.0.0.1:8600'}},
        rateLimit: {enabled: true},
        waf: {enabled: true, mode: 'detection', paranoiaLevel: 1},
      },
      'custom': {},
    },

    applyPreset(id) {
      this.activePreset = id;
      const base = this.defaultConfig();
      const p = this.presetDefs[id] || {};

      // Proxy
      if (p.proxy) {
        if (p.proxy.serviceName) base.proxy.serviceName = p.proxy.serviceName;
        if (p.proxy.targets) base.proxy.targets = [...p.proxy.targets];
        if (p.proxy.platforms) base.proxy.platforms = [...p.proxy.platforms];
        if (p.proxy.targetDiscovery) Object.assign(base.proxy.targetDiscovery, p.proxy.targetDiscovery);
      }

      // JSONRPC
      if (p.jsonrpc) {
        base.jsonrpc.endpoints = p.jsonrpc.endpoints.map(e => ({...this.defaultEndpoint(), ...e}));
      }

      // WAF
      if (p.waf) Object.assign(base.waf, p.waf);

      // RateLimit
      if (p.rateLimit) {
        base.rateLimit.enabled = p.rateLimit.enabled ?? false;
        if (p.rateLimit.perIP) base.rateLimit.perIP = p.rateLimit.perIP;
        if (p.rateLimit.action) base.rateLimit.action = p.rateLimit.action;
        if (p.rateLimit.rules) base.rateLimit.rules = p.rateLimit.rules.map(r => ({...this.defaultRateLimitRule(), ...r, match: [...(r.match || [])]}));
      }

      // IP
      if (p.ip) {
        if (p.ip.geoDatabase) base.ip.geoDatabase = p.ip.geoDatabase;
        if (p.ip.asnDatabase) base.ip.asnDatabase = p.ip.asnDatabase;
        if (p.ip.whitelist) {
          if (p.ip.whitelist.cidrs) base.ip.whitelist.cidrs = [...p.ip.whitelist.cidrs];
        }
        if (p.ip.blacklist) {
          if (p.ip.blacklist.cidrs) base.ip.blacklist.cidrs = [...p.ip.blacklist.cidrs];
        }
        if (p.ip.countries) {
          if (p.ip.countries.block) base.ip.countries.block = [...p.ip.countries.block];
          if (p.ip.countries.captcha) base.ip.countries.captcha = [...p.ip.countries.captcha];
          if (p.ip.countries.log) base.ip.countries.log = [...p.ip.countries.log];
        }
        if (p.ip.reputation) {
          base.ip.reputation.enabled = p.ip.reputation.enabled ?? false;
          if (p.ip.reputation.updateInterval) base.ip.reputation.updateInterval = p.ip.reputation.updateInterval;
          if (p.ip.reputation.scoreAdjustment) base.ip.reputation.scoreAdjustment = p.ip.reputation.scoreAdjustment;
          if (p.ip.reputation.firehol) Object.assign(base.ip.reputation.firehol, p.ip.reputation.firehol);
          if (p.ip.reputation.tor) Object.assign(base.ip.reputation.tor, p.ip.reputation.tor);
          if (p.ip.reputation.datacenter) Object.assign(base.ip.reputation.datacenter, p.ip.reputation.datacenter);
          if (p.ip.reputation.feeds) base.ip.reputation.feeds = [...p.ip.reputation.feeds];
        }
      }

      // TrafficFilter
      if (p.trafficFilter) {
        base.trafficFilter.enabled = p.trafficFilter.enabled ?? false;
        if (p.trafficFilter.rules) {
          base.trafficFilter.rules = p.trafficFilter.rules.map(r => {
            const rule = {...this.defaultTrafficRule(), ...r};
            for (const k of Object.keys(rule)) {
              if (Array.isArray(rule[k])) rule[k] = [...rule[k]];
            }
            return rule;
          });
        }
      }

      // Signing
      if (p.signing) {
        base.signing.enabled = p.signing.enabled ?? false;
        if (p.signing.mode) base.signing.mode = p.signing.mode;
        if (p.signing.ttl) base.signing.ttl = p.signing.ttl;
        for (const plat of ['web', 'android', 'ios']) {
          if (p.signing[plat]) Object.assign(base.signing[plat], p.signing[plat]);
        }
        if (p.signing.methods) {
          base.signing.methods = p.signing.methods.map(m => {
            const sm = {...this.defaultSigningMethod(), ...m};
            for (const k of ['methods', 'platforms', 'signFields']) sm[k] = [...(sm[k] || [])];
            return sm;
          });
        }
      }

      // Decision
      if (p.decision) {
        Object.assign(base.decision, p.decision);
        if (p.decision.platforms) {
          base.decision.platforms = p.decision.platforms.map(pl => ({...this.defaultPlatformCaptcha(), ...pl}));
        }
      }

      // Captcha
      if (p.captcha) {
        const pow = base.captcha.pow;
        Object.assign(base.captcha, p.captcha);
        base.captcha.pow = pow;
        if (p.captcha.pow) Object.assign(base.captcha.pow, p.captcha.pow);
      }

      // Alerting
      if (p.alerting) {
        base.alerting.enabled = p.alerting.enabled ?? false;
        if (p.alerting.webhooks) {
          base.alerting.webhooks = p.alerting.webhooks.map(w => ({...this.defaultWebhook(), ...w, events: [...(w.events || [])]}));
        }
      }

      // Adaptive
      if (p.adaptive) {
        base.adaptive.enabled = p.adaptive.enabled ?? false;
        if (p.adaptive.mode) base.adaptive.mode = p.adaptive.mode;
        if (p.adaptive.autoAttack) Object.assign(base.adaptive.autoAttack, p.adaptive.autoAttack);
      }

      // Storage
      if (p.storage) {
        base.storage.backend = p.storage.backend || 'memory';
        if (p.storage.aerospike) {
          Object.assign(base.storage.aerospike, p.storage.aerospike);
          if (p.storage.aerospike.hosts) base.storage.aerospike.hosts = [...p.storage.aerospike.hosts];
        }
      }

      this.cfg = base;
      this.onChange();
    },
  };
}
