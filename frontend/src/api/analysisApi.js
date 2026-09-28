import { apiClient } from './client';

import mockAnalysis from '../mock/mockAnalysis.json';
import { DEMO_PRESETS } from '../mock/demoCaptures';

const USE_MOCK_ENV =
  import.meta.env.VITE_USE_MOCK === 'true';

/*
|--------------------------------------------------------------------------
| Local Mock Storage
|--------------------------------------------------------------------------
|
| Demo presets are loaded here so they can be accessed by analysis_id.
|
*/

const localMockAnalyses = [
  ...DEMO_PRESETS
    .filter((preset) => preset?.data)
    .map((preset) => preset.data),

  mockAnalysis,
];


/*
|--------------------------------------------------------------------------
| Helpers
|--------------------------------------------------------------------------
*/

const DEMO_ANALYSIS_IDS = new Set(
  [
    ...DEMO_PRESETS.filter((preset) => preset?.data?.analysis_id).map((preset) =>
      String(preset.data.analysis_id)
    ),
    String(mockAnalysis?.analysis_id),
  ].filter(Boolean)
);

function isDemoId(analysisId) {
  if (!analysisId) return false;
  const idStr = String(analysisId);
  return (
    DEMO_ANALYSIS_IDS.has(idStr) ||
    idStr.startsWith('demo-') ||
    idStr.startsWith('sec-') ||
    idStr.startsWith('multi-') ||
    idStr.startsWith('local-')
  );
}

function findLocalAnalysis(analysisId) {
  const direct = localMockAnalyses.find(
    (analysis) =>
      String(analysis.analysis_id) === String(analysisId)
  );
  if (direct) return direct;
  const preset = DEMO_PRESETS.find(
    (p) => String(p.id) === String(analysisId) || String(p.data?.analysis_id) === String(analysisId)
  );
  return preset?.data || null;
}


function createFallbackAnalysis(fileName = 'demo-capture.pcap') {
  const newAnalysis = {
    ...mockAnalysis,
    analysis_id: `local-${Date.now()}`,
    filename: fileName,
    uploaded_at: new Date().toISOString(),
  };

  localMockAnalyses.unshift(newAnalysis);

  return newAnalysis;
}


/*
|--------------------------------------------------------------------------
| API
|--------------------------------------------------------------------------
*/

export const analysisApi = {

  /*
  |--------------------------------------------------------------------------
  | Upload Analysis
  |--------------------------------------------------------------------------
  */

  async uploadAnalysis(file) {

    if (USE_MOCK_ENV) {
      await new Promise((resolve) =>
        setTimeout(resolve, 1200)
      );

      return createFallbackAnalysis(file.name);
    }

    const formData = new FormData();
    formData.append('file', file);

    const result = await apiClient('/api/analyze', {
      method: 'POST',
      body: formData,
    });

    /*
     | Store locally too so navigation to:
     | /analysis/:id works immediately for cached views.
     */
    if (result?.analysis_id) {
      const exists = findLocalAnalysis(result.analysis_id);
      if (!exists) {
        localMockAnalyses.unshift(result);
      }
    }

    return result;
  },


  /*
  |--------------------------------------------------------------------------
  | Analysis History
  |--------------------------------------------------------------------------
  */

  async getAnalyses(page = 1, limit = 20, search = '', date = '') {

    if (USE_MOCK_ENV) {

      let mapped = localMockAnalyses.map((analysis) => ({
        analysis_id: analysis.analysis_id,
        filename: analysis.filename,
        status: analysis.status || 'COMPLETED',
        risk_label: analysis.risk?.level || 'UNKNOWN',
        risk_score: analysis.risk?.score ?? null,
        session_count: analysis.summary?.total_sessions || analysis.sessions?.length || 0,
        finding_count: analysis.summary?.findings_count || analysis.findings?.length || 0,
        created_at: analysis.uploaded_at,
        completed_at: analysis.uploaded_at,
      }));

      if (search && search.trim()) {
        const term = search.trim().toLowerCase();
        mapped = mapped.filter(
          (item) =>
            String(item.filename || '').toLowerCase().includes(term) ||
            String(item.analysis_id || '').toLowerCase().includes(term)
        );
      }

      if (date && date.trim()) {
        const dStr = date.trim();
        mapped = mapped.filter((item) => {
          if (!item.created_at) return false;
          const d = new Date(item.created_at);
          if (isNaN(d.getTime())) return false;
          const y = d.getFullYear();
          const m = String(d.getMonth() + 1).padStart(2, '0');
          const day = String(d.getDate()).padStart(2, '0');
          return `${y}-${m}-${day}` === dStr;
        });
      }

      const total = mapped.length;
      const start = (page - 1) * limit;
      const items = mapped.slice(start, start + limit);

      const highRiskCount = localMockAnalyses.filter((item) => {
        const level = String(item.risk?.level || '').toLowerCase();
        return level === 'high' || level === 'critical';
      }).length;

      const totalSessions = localMockAnalyses.reduce(
        (acc, item) => acc + (item.summary?.total_sessions || item.sessions?.length || 0),
        0
      );

      const totalFindings = localMockAnalyses.reduce(
        (acc, item) => acc + (item.summary?.findings_count || item.findings?.length || 0),
        0
      );

      return {
        items,
        pagination: {
          page,
          limit,
          total,
          totalPages: Math.ceil(total / limit) || 1,
        },
        stats: {
          totalAnalyses: localMockAnalyses.length,
          highRiskCount,
          totalSessions,
          totalFindings,
        },
      };
    }

    const params = new URLSearchParams({
      page: String(page),
      limit: String(limit),
    });
    if (search && search.trim()) params.set('search', search.trim());
    if (date && date.trim()) params.set('date', date.trim());

    return await apiClient(
      `/api/analyses?${params.toString()}`
    );
  },


  /*
  |--------------------------------------------------------------------------
  | Get Analysis By ID
  |--------------------------------------------------------------------------
  */

  async getAnalysis(analysisId) {
    if (USE_MOCK_ENV || isDemoId(analysisId)) {
      const localMatch = findLocalAnalysis(analysisId);
      if (localMatch) {
        return localMatch;
      }

      throw new Error(
        `Analysis "${analysisId}" was not found in local demo data.`
      );
    }

    return await apiClient(
      `/api/analyses/${encodeURIComponent(analysisId)}`
    );
  },

  /*
  |--------------------------------------------------------------------------
  | Get Paginated, Filtered, and Sorted Sessions
  |--------------------------------------------------------------------------
  */

  async getSessions(analysisId, {
    page = 1,
    limit = 15,
    search = '',
    protocol = 'ALL',
    encryption = 'ALL',
    risk = 'ALL',
    anomaly = 'ALL',
    sortBy = 'tcp_stream',
    sortOrder = 'ASC',
  } = {}) {
    if (USE_MOCK_ENV || isDemoId(analysisId)) {
      const localMatch = findLocalAnalysis(analysisId);
      let allSessions = localMatch ? [...(localMatch.sessions || [])] : [];

      if (search && search.trim()) {
        const q = search.trim().toLowerCase();
        allSessions = allSessions.filter((s) =>
          (s.session_id || '').toLowerCase().includes(q) ||
          (s.client_ip || '').toLowerCase().includes(q) ||
          (s.server_ip || '').toLowerCase().includes(q) ||
          (s.protocol || '').toLowerCase().includes(q) ||
          (s.service || '').toLowerCase().includes(q)
        );
      }

      if (protocol && protocol !== 'ALL') {
        allSessions = allSessions.filter(
          (s) => (s.protocol || '').toUpperCase() === protocol.toUpperCase()
        );
      }

      if (encryption && encryption !== 'ALL') {
        allSessions = allSessions.filter(
          (s) => (s.security?.encryption_mode || '').toUpperCase() === encryption.toUpperCase()
        );
      }

      if (risk && risk !== 'ALL') {
        allSessions = allSessions.filter((s) => {
          const r = (s.risk?.level || s.risk_label || 'LOW').toUpperCase();
          return r === risk.toUpperCase();
        });
      }

      if (anomaly && anomaly !== 'ALL') {
        if (anomaly === 'ANOMALOUS') {
          allSessions = allSessions.filter((s) => s?.anomaly?.is_anomalous === true);
        } else if (anomaly === 'BASELINE') {
          allSessions = allSessions.filter((s) => s?.anomaly?.is_anomalous === false);
        }
      }

      const orderMultiplier = String(sortOrder).toUpperCase() === 'DESC' ? -1 : 1;
      allSessions.sort((a, b) => {
        if (sortBy === 'session_id') {
          return (a.session_id || '').localeCompare(b.session_id || '') * orderMultiplier;
        }
        if (sortBy === 'protocol') {
          return (a.protocol || '').localeCompare(b.protocol || '') * orderMultiplier;
        }
        if (sortBy === 'risk') {
          const rank = { CRITICAL: 4, HIGH: 3, MEDIUM: 2, LOW: 1 };
          const rA = rank[(a.risk?.level || a.risk_label || 'LOW').toUpperCase()] || 0;
          const rB = rank[(b.risk?.level || b.risk_label || 'LOW').toUpperCase()] || 0;
          return (rA - rB) * orderMultiplier;
        }
        if (sortBy === 'score' || sortBy === 'decision_score') {
          const scA = a.anomaly?.decision_score ?? 999;
          const scB = b.anomaly?.decision_score ?? 999;
          return (scA - scB) * orderMultiplier;
        }
        if (sortBy === 'anomaly') {
          const anomA = a.anomaly?.is_anomalous ? 1 : 0;
          const anomB = b.anomaly?.is_anomalous ? 1 : 0;
          return (anomB - anomA) * orderMultiplier;
        }
        if (sortBy === 'encryption') {
          return (
            (a.security?.encryption_mode || '').localeCompare(b.security?.encryption_mode || '') *
            orderMultiplier
          );
        }
        return ((a.tcp_stream ?? 0) - (b.tcp_stream ?? 0)) * orderMultiplier;
      });

      const total = allSessions.length;
      const totalPages = Math.ceil(total / limit) || 1;
      const offset = (page - 1) * limit;
      const items = allSessions.slice(offset, offset + limit);

      return {
        items,
        pagination: {
          page,
          limit,
          total,
          totalPages,
        },
      };
    }

    const params = new URLSearchParams({
      page: String(page),
      limit: String(limit),
    });
    if (search && search.trim()) params.set('search', search.trim());
    if (protocol && protocol !== 'ALL') params.set('protocol', protocol);
    if (encryption && encryption !== 'ALL') params.set('encryption', encryption);
    if (risk && risk !== 'ALL') params.set('risk', risk);
    if (anomaly && anomaly !== 'ALL') params.set('anomaly', anomaly);
    if (sortBy) params.set('sortBy', sortBy);
    if (sortOrder) params.set('sortOrder', sortOrder);

    return await apiClient(
      `/api/analyses/${encodeURIComponent(analysisId)}/sessions?${params.toString()}`
    );
  },


  /*
  |--------------------------------------------------------------------------
  | Export Analysis
  |--------------------------------------------------------------------------
  */

  async exportAnalysis(analysisId) {
    if (USE_MOCK_ENV || isDemoId(analysisId)) {
      const localMatch = findLocalAnalysis(analysisId);
      if (!localMatch) {
        throw new Error(
          'Analysis not available for export.'
        );
      }

      return new Blob(
        [
          JSON.stringify(
            localMatch,
            null,
            2
          ),
        ],
        {
          type:
            'application/json',
        }
      );
    }

    return await apiClient(
      `/api/analyses/${encodeURIComponent(analysisId)}/export`,
      {
        asBlob: true,
      }
    );
  },

  /*
  |--------------------------------------------------------------------------
  | Download Session PCAP
  |--------------------------------------------------------------------------
  */

  async downloadSessionPcap(analysisId, sessionId) {
    if (USE_MOCK_ENV || isDemoId(analysisId)) {
      return new Blob(
        [new Uint8Array([0xd4, 0xc3, 0xb2, 0xa1, 0x02, 0x00, 0x04, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00, 0x01, 0x00, 0x00, 0x00])],
        { type: 'application/vnd.tcpdump.pcap' }
      );
    }

    return await apiClient(
      `/api/analyses/${encodeURIComponent(analysisId)}/sessions/${encodeURIComponent(sessionId)}/pcap`,
      {
        asBlob: true,
      }
    );
  },

  /*
  |--------------------------------------------------------------------------
  | Session Provenance
  |--------------------------------------------------------------------------
  */

  async getSessionProvenance(analysisId, sessionId) {
    if (USE_MOCK_ENV || isDemoId(analysisId)) {
      return {
        analysis_id: analysisId,
        session_id: sessionId,
        tcp_stream: 0,
        source_pcap_filename: 'demo_capture.pcap',
        source_pcap_sha256: '7d793037a0760186574b0282f2f435e7c7a7f7e3c5f1d4c1c2e8e9b0a1f2c3d4',
        completeness: 'COMPLETE',
        wireshark_filter: 'tcp.stream == 0',
      };
    }

    return await apiClient(
      `/api/analyses/${encodeURIComponent(analysisId)}/sessions/${encodeURIComponent(sessionId)}/provenance`
    );
  },


  /*
  |--------------------------------------------------------------------------
  | Gateway Health
  |--------------------------------------------------------------------------
  */

  async checkHealth() {

    try {

      return await apiClient(
        '/api/health'
      );

    } catch {

      return {
        status: 'offline',
      };
    }
  },
};