function dashboard() {
  return {
    status: {},
    attack: {enabled: false},
    blocks: [],
    rules: [],
    recentEvents: [],
    activeTab: 'ip',
    totalRequests: 0,
    rps: '—',
    passed: 0,
    captchaPassed: 0,
    blocked: 0,
    rateLimited: 0,
    captchaCount: 0,
    wafMatches: 0,
    signInvalid: 0,
    errorRate: '—',
    uptimeText: '—',
    filtered: 0,
    totalBytes: 0,
    captchaRate: {captcha: 0, captchaPass: 0, solveRate: 0},
    topsData: {ips: [], blockedIps: [], paths: [], countries: [], platforms: [], wafRules: [], bots: [], fakeBots: 0, userAgents: [], referers: [], rpcMethods: [], asns: [], signResults: [], decisions: []},
    topsSubTab: 'traffic',
    latencies: {targets: [], methods: [], targetErrors: []},
    latencyHistory: {},  // key → [{time, avgMs}] last 60 snapshots (5 min at 5s interval)
    filterRules: [],
    filterForm: {name: '', action: 'block', uaPrefix: '', country: ''},
    cfgData: null,
    mainTab: 'overview',
    avgLatency: '—',
    maxLatency: '—',
    cbState: 'n/a',
    form: {type: 'ip', value: '', reason: '', duration: ''},
    theme: 'auto',
    history: [],

    _prev: null,
    _prevTime: null,

    start() {
      // restore theme
      const saved = localStorage.getItem('wafsrv-theme');
      if (saved === 'dark' || saved === 'light') {
        this.theme = saved;
        document.documentElement.setAttribute('data-theme', saved);
      } else {
        this.theme = window.matchMedia('(prefers-color-scheme:dark)').matches ? 'dark' : 'light';
      }

      this.loadConfigData();
      this.refresh();
      setInterval(() => this.refresh(), 5000);
    },

    toggleTheme() {
      this.theme = this.theme === 'dark' ? 'light' : 'dark';
      document.documentElement.setAttribute('data-theme', this.theme);
      localStorage.setItem('wafsrv-theme', this.theme);
    },

    async refresh() {
      await Promise.all([
        this.loadStatus(),
        this.loadHistory(),
        this.loadTops(),
        this.loadBlocks(),
        this.loadRules(),
        this.loadFilterRules(),
        this.loadEvents(),
        this.loadAttack(),
        this.loadLatencies(),
        this.loadCaptchaRate(),
        this.loadConfigData(),
      ]);
    },

    async rpc(method, params) {
      const resp = await fetch('/rpc/', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({jsonrpc: '2.0', method, params: params || {}, id: 1}),
      });
      const data = await resp.json();
      if (data.error) throw new Error(data.error.message);
      return data.result;
    },

    // --- Status ---
    async loadStatus() {
      try {
        this.status = await this.rpc('status.get');
        this.uptimeText = this.fmtUptime(this.status.uptimeSeconds);
        if (this.status.proxyStatus && this.status.proxyStatus.targets && this.status.proxyStatus.targets.length > 0) {
          this.cbState = this.status.proxyStatus.targets[0].state;
        }
      } catch (_) {}
    },

    // --- Attack ---
    async loadAttack() {
      try { this.attack = await this.rpc('attack.status'); } catch (_) {}
    },

    async toggleAttack() {
      try {
        if (this.attack.enabled) {
          this.attack = await this.rpc('attack.disable');
        } else {
          const dur = prompt('Duration (e.g. 5m, 1h, empty=manual):', '5m');
          if (dur === null) return;
          this.attack = await this.rpc('attack.enable', {duration: dur});
        }
      } catch (e) { alert('Error: ' + e.message); }
    },

    // --- Metrics (from time series) ---
    async loadHistory() {
      try {
        this.history = await this.rpc('metrics.history', {minutes: 30}) || [];

        // RPS from server
        this.rps = Math.round(await this.rpc('metrics.rps'));

        // totals from last point
        if (this.history.length > 0) {
          const sum = (key) => this.history.reduce((s, p) => s + (p[key] || 0), 0);
          this.totalRequests = sum('incoming') || sum('requests');
          this.blocked = sum('blocked');
          this.filtered = sum('filtered');
          this.rateLimited = sum('rateLimited');
          this.captchaCount = sum('captcha');
          this.captchaPassed = sum('captchaPass');
          this.wafMatches = sum('wafMatches');
          this.signInvalid = sum('signInvalid');
          this.passed = sum('requests');
          this.totalBytes = sum('bytesSent');

          const totalErr = sum('errors5xx');
          this.errorRate = this.totalRequests > 0 ? (totalErr / this.totalRequests * 100).toFixed(1) + '%' : '0%';

          // latency from last completed point
          const last = this.history[this.history.length - 1];
          if (last && last.latencyCount > 0) {
            this.avgLatency = Math.round(last.latencyUs / last.latencyCount / 1000) + 'ms';
            this.maxLatency = Math.round(last.latencyMaxUs / 1000) + 'ms';
          } else {
            this.avgLatency = '—';
            this.maxLatency = '—';
          }
        }
      } catch (_) {}
    },

    spark(field) {
      if (!this.history || this.history.length === 0) return [];

      const vals = this.history.map(p => p[field] || 0);
      const max = Math.max(...vals, 1);
      // last 30 points (2.5 min at 5s interval)
      const slice = vals.slice(-30);
      return slice.map(v => Math.max(Math.round(v / max * 100), 2));
    },

    // --- Captcha Rate ---
    async loadCaptchaRate() {
      try { this.captchaRate = await this.rpc('metrics.captchaRate', {minutes: 30}) || {captcha: 0, captchaPass: 0, solveRate: 0}; } catch (_) {}
    },

    // --- Latencies ---
    async loadLatencies() {
      try {
        this.latencies = await this.rpc('metrics.latencies') || {targets: [], methods: [], targetErrors: []};
        this.recordLatencyHistory(this.latencies.methods);
      } catch (_) { this.latencies = {targets: [], methods: [], targetErrors: []}; }
    },

    recordLatencyHistory(methods) {
      const now = Date.now();
      for (const m of methods || []) {
        if (!this.latencyHistory[m.key]) this.latencyHistory[m.key] = [];
        const h = this.latencyHistory[m.key];
        h.push({time: now, avgMs: m.avgMs, p95Ms: m.p95Ms, count: m.count});
        // keep last 60 snapshots (5 min)
        if (h.length > 60) h.shift();
      }
    },

    latencySpark(key) {
      const h = this.latencyHistory[key];
      if (!h || h.length < 2) return [];
      // use delta count between snapshots as "requests in interval"
      // and avgMs for sparkline height
      const vals = h.map(p => p.avgMs);
      const max = Math.max(...vals, 0.1);
      return vals.slice(-30).map(v => Math.max(Math.round(v / max * 100), 2));
    },

    // --- Tops ---
    async loadTops() {
      try { this.topsData = await this.rpc('metrics.tops', {n: 10}) || {ips:[], paths:[], countries:[]}; } catch (_) {}
    },

    // --- Blocks ---
    async loadBlocks() {
      try {
        this.blocks = await this.rpc('block.list', {blockType: this.activeTab}) || [];
      } catch (_) { this.blocks = []; }
    },

    async addBlock() {
      try {
        await this.rpc('block.add', {
          blockType: this.form.type,
          value: this.form.value,
          reason: this.form.reason,
          duration: this.form.duration,
        });
        this.activeTab = this.form.type;
        this.form.value = '';
        this.form.reason = '';
        this.form.duration = '';
        await this.loadBlocks();
      } catch (e) { alert('Error: ' + e.message); }
    },

    async removeBlock(value) {
      try {
        await this.rpc('block.remove', {blockType: this.activeTab, value});
        await this.loadBlocks();
      } catch (e) { alert('Error: ' + e.message); }
    },

    // --- Filter Rules ---
    async loadFilterRules() {
      try { this.filterRules = await this.rpc('filter.list') || []; } catch (_) { this.filterRules = []; }
    },

    async addFilterRule() {
      try {
        const rule = {name: this.filterForm.name, action: this.filterForm.action};
        if (this.filterForm.uaPrefix) rule.uaPrefix = this.filterForm.uaPrefix.split(',').map(s => s.trim()).filter(Boolean);
        if (this.filterForm.country) rule.country = this.filterForm.country.split(',').map(s => s.trim()).filter(Boolean);
        await this.rpc('filter.add', {rule});
        this.filterForm = {name: '', action: 'block', uaPrefix: '', country: ''};
        await this.loadFilterRules();
      } catch (e) { alert('Error: ' + e.message); }
    },

    async removeFilterRule(name) {
      try {
        await this.rpc('filter.remove', {name});
        await this.loadFilterRules();
      } catch (e) { alert('Error: ' + e.message); }
    },

    fmtFilterConditions(r) {
      const parts = [];
      if (r.uaPrefix && r.uaPrefix.length) parts.push('UA~' + r.uaPrefix.join(','));
      if (r.uaExact && r.uaExact.length) parts.push('UA=' + r.uaExact.join(','));
      if (r.country && r.country.length) parts.push('Country:' + r.country.join(','));
      if (r.platform && r.platform.length) parts.push('Platform:' + r.platform.join(','));
      if (r.ip && r.ip.length) parts.push('IP:' + r.ip.join(','));
      if (r.host && r.host.length) parts.push('Host:' + r.host.join(','));
      if (r.path && r.path.length) parts.push('Path:' + r.path.join(','));
      if (r.version && r.version.length) parts.push('Ver:' + r.version.join(','));
      if (r.method && r.method.length) parts.push('Method:' + r.method.join(','));
      if (r.uaContains && r.uaContains.length) parts.push('UA⊃' + r.uaContains.join(','));
      if (r.asn && r.asn.length) parts.push('ASN:' + r.asn.join(','));
      if (r.rpcMethod && r.rpcMethod.length) parts.push('RPC:' + r.rpcMethod.join(','));
      if (r.referer && r.referer.length) parts.push('Ref:' + r.referer.join(','));
      return parts.join(' AND ') || '—';
    },

    // --- Events ---
    async loadEvents() {
      try { this.recentEvents = await this.rpc('events.recent', {limit: 20}) || []; } catch (_) { this.recentEvents = []; }
    },

    // --- Rules ---
    async loadRules() {
      try { this.rules = await this.rpc('status.rules') || []; } catch (_) { this.rules = []; }
    },

    // --- Config (loaded once, retried on failure) ---
    async loadConfigData() {
      if (this.cfgData) return;
      try {
        const data = await this.rpc('config.get');
        if (data) this.cfgData = data;
      } catch (_) {}
    },

    chartHeight(val, field) {
      if (!this.history || this.history.length === 0 || !val) return 0;
      const vals = this.history.map(p => p[field] || 0);
      const max = Math.max(...vals, 1);
      return Math.max(Math.round(val / max * 100), 2);
    },

    // --- Helpers ---
    fmtUptime(sec) {
      if (!sec) return '—';
      const h = Math.floor(sec / 3600);
      const m = Math.floor((sec % 3600) / 60);
      const s = Math.floor(sec % 60);
      if (h > 0) return h + 'h ' + m + 'm';
      if (m > 0) return m + 'm ' + s + 's';
      return s + 's';
    },

    wafRuleName(id) {
      const names = {
        '920100': 'Invalid HTTP Request Line',
        '920160': 'Content-Length Not Numeric',
        '920170': 'GET/HEAD with Body',
        '920180': 'POST Missing Content-Type',
        '920280': 'Missing Host Header',
        '920340': 'Request Body Not Empty',
        '920420': 'Content-Type Not Allowed',
        '920440': 'URL File Extension Restricted',
        '921110': 'HTTP Request Smuggling',
        '930100': 'Path Traversal (/../)',
        '930110': 'Path Traversal (../)',
        '930120': 'OS File Access Attempt',
        '931100': 'Remote File Inclusion (RFI)',
        '932100': 'Remote Command Execution (Unix)',
        '932110': 'Remote Command Execution (Windows)',
        '932130': 'Remote Command Execution (Unix Shell)',
        '932160': 'Remote Command Execution (Unix)',
        '933100': 'PHP Injection Attack',
        '933140': 'PHP I/O Stream',
        '934100': 'Node.js Injection',
        '941100': 'XSS Attack (libinjection)',
        '941110': 'XSS: Script Tag Vector',
        '941160': 'XSS: HTML Injection',
        '941390': 'Javascript Method Detected',
        '942100': 'SQL Injection (libinjection)',
        '942110': 'SQL Injection (string termination)',
        '942120': 'SQL Injection (operator)',
        '942130': 'SQL Injection (tautology)',
        '942150': 'SQL Injection (UNION)',
        '942160': 'SQL Injection (blind test)',
        '943100': 'Session Fixation',
        '944100': 'Java Code Injection',
        '949110': 'Anomaly Score Exceeded',
      };
      return names[id] || 'CRS Rule ' + id;
    },

    fmtNum(n) {
      if (n === null || n === undefined || n === '—') return '—';
      return Number(n).toLocaleString();
    },

    hasTops() {
      const t = this.topsData;
      return (t.ips && t.ips.length) || (t.paths && t.paths.length) || (t.rpcMethods && t.rpcMethods.length) || (t.decisions && t.decisions.length) || (t.userAgents && t.userAgents.length) || (t.wafRules && t.wafRules.length) || (t.asns && t.asns.length) || (t.blockedIps && t.blockedIps.length);
    },

    fmtBytesVal(b) {
      if (!b || b === 0) return '0';
      const i = Math.min(Math.floor(Math.log(b) / Math.log(1024)), 3);
      return (b / Math.pow(1024, i)).toFixed(i > 0 ? 1 : 0);
    },

    fmtBytesUnit(b) {
      if (!b || b === 0) return 'B';
      const units = ['B', 'KB', 'MB', 'GB'];
      return units[Math.min(Math.floor(Math.log(b) / Math.log(1024)), 3)];
    },

    targetErrorRate(targetKey) {
      const e = (this.latencies.targetErrors || []).find(e => e.key === targetKey);
      if (!e) return {errors: 0, rate: '0%'};
      return {errors: e.errors5xx, rate: e.errorRate.toFixed(1) + '%'};
    },

    fmtTime(iso) {
      if (!iso) return '—';
      return new Date(iso).toLocaleTimeString();
    },
  };
}
