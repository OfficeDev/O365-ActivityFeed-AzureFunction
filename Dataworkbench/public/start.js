(() => {
  'use strict';
  const health = document.getElementById('health');
  const summary = document.getElementById('shared-summary');
  const fmt = (value) => new Intl.NumberFormat().format(Number(value) || 0);
  async function load() {
    try {
      const [serviceResponse, dataResponse] = await Promise.all([fetch('/api/health'), fetch('/api/sit/summary')]);
      const service = await serviceResponse.json(); const data = await dataResponse.json();
      if (!service.ok) throw new Error('Service unavailable');
      health.className = `health ${data.ok ? 'ok' : 'bad'}`; health.innerHTML = `<span></span>${data.ok ? `Shared evidence updated ${data.lastSyncUtc ? new Date(data.lastSyncUtc).toLocaleString() : 'locally'}` : 'DLP synchronization required'}`;
      summary.innerHTML = data.ok ? `<span class="metric"><strong>${fmt(data.alerts)}</strong> alerts</span><span class="metric"><strong>${fmt(data.events)}</strong> events</span><span class="metric"><strong>${fmt(data.detections)}</strong> detections</span><span class="metric"><strong>${data.privacyMode === 'context-only' ? 'Redacted' : 'Protected'}</strong> value handling</span>` : '<span class="metric">Open DLP Response and synchronize alerts to populate both workspaces.</span>';
    } catch {
      health.className = 'health bad'; health.innerHTML = '<span></span>Workbench unavailable'; summary.innerHTML = '<span class="metric">Unable to load shared data status.</span>';
    }
  }
  load();
})();
