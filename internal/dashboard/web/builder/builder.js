// builder.js — core Alpine component: init, theme, chips, validation, helpers

function builder() {
  return {
    // Merge mixins
    ...builderConfig(),
    ...builderToml(),
    ...builderImport(),

    theme: 'auto',
    activePreset: 'custom',
    copied: false,
    toml: '',
    lineCount: 0,
    errors: {},
    targetErrors: {},
    cfg: null,
    _saveTimer: null,
    _defaults: null, // cached defaults for TOML comparison

    presetList: [
      {id: 'minimal', label: 'Minimal'},
      {id: 'api-gateway', label: 'API Gateway'},
      {id: 'waf-basic', label: 'WAF Basic'},
      {id: 'waf-captcha', label: 'WAF + Captcha'},
      {id: 'full', label: 'Full Protection'},
      {id: 'multi', label: 'Multi-instance'},
      {id: 'consul-discovery', label: 'Consul Discovery'},
      {id: 'custom', label: 'Custom'},
    ],

    init() {
      const saved = localStorage.getItem('wafsrv-builder-theme');
      if (saved === 'dark' || saved === 'light') {
        this.theme = saved;
        document.documentElement.setAttribute('data-theme', saved);
      } else {
        this.theme = window.matchMedia('(prefers-color-scheme:dark)').matches ? 'dark' : 'light';
      }
      this._defaults = this.defaultConfig();
      // Restore saved config or use default
      const savedCfg = localStorage.getItem('wafsrv-builder-cfg');
      if (savedCfg) {
        try {
          this.cfg = JSON.parse(savedCfg);
          this.activePreset = localStorage.getItem('wafsrv-builder-preset') || 'custom';
        } catch { this.cfg = this.defaultConfig(); }
      } else {
        this.cfg = this.defaultConfig();
      }
      this.validate();
      this.generateToml();
    },

    toggleTheme() {
      this.theme = this.theme === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', this.theme);
      localStorage.setItem('wafsrv-builder-theme', this.theme);
    },

    onChange() {
      this.activePreset = 'custom';
      this.validate();
      this.generateToml();
      this._debounceSave();
    },

    _debounceSave() {
      clearTimeout(this._saveTimer);
      this._saveTimer = setTimeout(() => this._saveState(), 500);
    },

    _saveState() {
      try {
        localStorage.setItem('wafsrv-builder-cfg', JSON.stringify(this.cfg));
        localStorage.setItem('wafsrv-builder-preset', this.activePreset);
      } catch {}
    },

    resetConfig() {
      if (!confirm('Reset to defaults? All changes will be lost.')) return;
      localStorage.removeItem('wafsrv-builder-cfg');
      localStorage.removeItem('wafsrv-builder-preset');
      this._defaults = this.defaultConfig();
      this.cfg = this.defaultConfig();
      this.activePreset = 'custom';
      this.validate();
      this.generateToml();
    },

    // Active features count for header
    activeFeatures() {
      const c = this.cfg;
      const features = [];
      if (c.waf.enabled) features.push('WAF');
      if (c.rateLimit.enabled) features.push('RL');
      if (c.trafficFilter.enabled) features.push('Filter');
      if (c.signing.enabled) features.push('Sign');
      if (c.captcha.provider) features.push('Captcha');
      if (c.alerting.enabled) features.push('Alert');
      if (c.adaptive.enabled) features.push('Adaptive');
      if (c.storage.backend !== 'memory') features.push('Aerospike');
      return features;
    },

    // --- Chips (unified) ---
    addChip(path, event, numeric) {
      const raw = event.target.value.trim();
      if (!raw) return;
      const val = numeric ? parseInt(raw, 10) : raw;
      if (numeric && isNaN(val)) return;
      const arr = this._getArr(path);
      if (arr && !arr.includes(val)) {
        arr.push(val);
        this.onChange();
      }
      event.target.value = '';
    },

    popChip(path, event) {
      if (event.target.value !== '') return;
      const arr = this._getArr(path);
      if (arr && arr.length > 0) {
        arr.pop();
        this.onChange();
      }
    },

    _getArr(path) {
      const parts = path.split('.');
      let obj = this.cfg;
      for (const p of parts) {
        if (obj && typeof obj === 'object') {
          const idx = parseInt(p, 10);
          obj = isNaN(idx) ? obj[p] : obj[idx];
        } else return null;
      }
      return Array.isArray(obj) ? obj : null;
    },

    // --- Targets ---
    addTarget() { this.cfg.proxy.targets.push(''); this.onChange(); },
    removeTarget(i) { this.cfg.proxy.targets.splice(i, 1); this.onChange(); },

    // --- Endpoints ---
    addEndpoint() { this.cfg.jsonrpc.endpoints.push(this.defaultEndpoint()); this.onChange(); },

    // --- RateLimit Rules ---
    addRateLimitRule() { this.cfg.rateLimit.rules.push(this.defaultRateLimitRule()); this.onChange(); },
    removeRateLimitRule(i) { this.cfg.rateLimit.rules.splice(i, 1); this.onChange(); },

    // --- Traffic Filter Rules ---
    addTrafficRule() { this.cfg.trafficFilter.rules.push(this.defaultTrafficRule()); this.onChange(); },
    removeTrafficRule(i) { this.cfg.trafficFilter.rules.splice(i, 1); this.onChange(); },

    // --- Signing Methods ---
    addSigningMethod() { this.cfg.signing.methods.push(this.defaultSigningMethod()); this.onChange(); },
    removeSigningMethod(i) { this.cfg.signing.methods.splice(i, 1); this.onChange(); },

    // --- Decision Platforms ---
    addDecisionPlatform() { this.cfg.decision.platforms.push(this.defaultPlatformCaptcha()); this.onChange(); },
    removeDecisionPlatform(i) { this.cfg.decision.platforms.splice(i, 1); this.onChange(); },

    // --- Alerting Webhooks ---
    addWebhook() { this.cfg.alerting.webhooks.push(this.defaultWebhook()); this.onChange(); },
    removeWebhook(i) { this.cfg.alerting.webhooks.splice(i, 1); this.onChange(); },

    // --- Captcha test keys ---
    captchaTestKeys: {
      turnstile: {siteKey: '1x00000000000000000000AA', secretKey: '1x0000000000000000000000000000000AA'},
      hcaptcha: {siteKey: '10000000-ffff-ffff-ffff-000000000001', secretKey: '0x0000000000000000000000000000000000000000'},
    },

    applyTestKeys() {
      const keys = this.captchaTestKeys[this.cfg.captcha.provider];
      if (keys) {
        this.cfg.captcha.siteKey = keys.siteKey;
        this.cfg.captcha.secretKey = keys.secretKey;
        this.onChange();
      }
    },

    // --- Alerting event options ---
    alertEventOptions: ['hard_block', 'soft_block', 'under_attack', 'attack_disabled', 'captcha_fail', 'rate_limit', 'waf_match', 'ip_blocked'],

    // Traffic rule condition fields — single source of truth for JS↔TOML mapping
    trafficConditions: [
      {key: 'uaPrefix', toml: 'UAPrefix', label: 'UA Prefix'},
      {key: 'uaContains', toml: 'UAContains', label: 'UA Contains'},
      {key: 'uaExact', toml: 'UAExact', label: 'UA Exact'},
      {key: 'uaExclude', toml: 'UAExclude', label: 'UA Exclude'},
      {key: 'country', toml: 'Country', label: 'Country'},
      {key: 'platform', toml: 'Platform', label: 'Platform'},
      {key: 'version', toml: 'Version', label: 'Version'},
      {key: 'ip', toml: 'IP', label: 'IP / CIDR'},
      {key: 'asn', toml: 'ASN', label: 'ASN', numeric: true},
      {key: 'rpcMethod', toml: 'RPCMethod', label: 'RPC Method'},
      {key: 'host', toml: 'Host', label: 'Host'},
      {key: 'path', toml: 'Path', label: 'Path'},
      {key: 'method', toml: 'Method', label: 'HTTP Method'},
      {key: 'referer', toml: 'Referer', label: 'Referer'},
    ],

    availableConditions(rule) {
      return this.trafficConditions.filter(c => !rule[c.key] || rule[c.key].length === 0);
    },

    addCondition(ruleIdx, key) {
      if (!this.cfg.trafficFilter.rules[ruleIdx][key]) {
        this.cfg.trafficFilter.rules[ruleIdx][key] = [];
      }
    },

    // --- Endpoint names for select ---
    endpointNames() {
      return this.cfg.jsonrpc.endpoints.map(e => e.name).filter(Boolean);
    },

    // --- Validation ---
    validate() {
      this.errors = {};
      this.targetErrors = {};

      if (!this.cfg.proxy.serviceName.trim()) {
        this.errors.serviceName = 'ServiceName is required';
      } else if (/\s/.test(this.cfg.proxy.serviceName)) {
        this.errors.serviceName = 'No spaces allowed';
      }

      const targets = this.cfg.proxy.targets;
      if (targets.length === 0 || targets.every(t => !t.trim())) {
        this.errors.targets = 'At least one target is required';
      }
      targets.forEach((t, i) => {
        if (t.trim() && !this._isURL(t.trim())) {
          this.targetErrors[i] = 'Invalid URL';
        }
      });

      if (this.cfg.rateLimit.enabled && this.cfg.rateLimit.perIP && !this._isRate(this.cfg.rateLimit.perIP)) {
        this.errors.rlPerIP = 'Format: N/(sec|min|hour)';
      }
    },

    _isURL(s) {
      try { const u = new URL(s); return u.protocol === 'http:' || u.protocol === 'https:'; }
      catch { return false; }
    },

    _isRate(s) { return /^\d+\/(sec|min|hour)$/.test(s); },

    // --- Copy / Download ---
    async copyToml() {
      try {
        await navigator.clipboard.writeText(this.toml);
      } catch {
        const ta = document.createElement('textarea');
        ta.value = this.toml;
        document.body.appendChild(ta);
        ta.select();
        document.execCommand('copy');
        document.body.removeChild(ta);
      }
      this.copied = true;
      setTimeout(() => this.copied = false, 2000);
    },

    downloadToml() {
      const blob = new Blob([this.toml], {type: 'application/toml'});
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = 'local.toml';
      a.click();
      URL.revokeObjectURL(url);
    },
  };
}
