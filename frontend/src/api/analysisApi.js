import { apiClient } from './client';
import mockAnalysis from '../mock/mockAnalysis.json';
import { DEMO_PRESETS } from '../mock/demoCaptures';

const USE_MOCK_ENV = import.meta.env.VITE_USE_MOCK === 'true';

// In-memory mock storage so uploads and history persist across page navigation in mock mode
const localMockAnalyses = [
  ...DEMO_PRESETS.map((p) => p.data),
];

export const analysisApi = {
  /**
   * Upload a PCAP / PCAPNG file for security analysis.
   * Sends multipart/form-data to POST /api/analyze
   */
  async uploadAnalysis(file) {
    if (USE_MOCK_ENV) {
      // Simulate network latency for realistic demo
      await new Promise((r) => setTimeout(r, 1200));
      const newAnalysis = {
        ...mockAnalysis,
        analysis_id: 'local-' + Date.now(),
        filename: file.name,
        uploaded_at: new Date().toISOString(),
      };
      localMockAnalyses.unshift(newAnalysis);
      return newAnalysis;
    }

    try {
      const formData = new FormData();
      formData.append('file', file);

      return await apiClient('/api/analyze', {
        method: 'POST',
        body: formData,
      });
    } catch (err) {
      if (err.isNetworkError || err.status === 401) {
        console.warn('Backend unavailable or unauthenticated, serving mock analysis for development.');
        const fallback = {
          ...mockAnalysis,
          analysis_id: 'mock-' + Date.now(),
          filename: file.name,
          uploaded_at: new Date().toISOString(),
        };
        localMockAnalyses.unshift(fallback);
        return fallback;
      }
      throw err;
    }
  },

  /**
   * Get paginated history of analyses.
   * Calls GET /api/analyses?page=X&limit=Y
   */
  async getAnalyses(page = 1, limit = 20) {
    if (USE_MOCK_ENV) {
      return {
        items: localMockAnalyses.map((a) => ({
          analysis_id: a.analysis_id,
          filename: a.filename,
          status: a.status,
          risk_label: a.risk?.level || 'UNKNOWN',
          risk_score: a.risk?.score || null,
          session_count: a.summary?.total_sessions || a.sessions?.length || 0,
          finding_count: a.summary?.findings_count || a.findings?.length || 0,
          created_at: a.uploaded_at,
          completed_at: a.uploaded_at,
        })),
        pagination: {
          page,
          limit,
          total: localMockAnalyses.length,
        },
      };
    }

    try {
      return await apiClient(`/api/analyses?page=${page}&limit=${limit}`);
    } catch (err) {
      if (err.isNetworkError || err.status === 401) {
        return {
          items: localMockAnalyses.map((a) => ({
            analysis_id: a.analysis_id,
            filename: a.filename,
            status: a.status,
            risk_label: a.risk?.level || 'UNKNOWN',
            risk_score: a.risk?.score || null,
            session_count: a.summary?.total_sessions || a.sessions?.length || 0,
            finding_count: a.summary?.findings_count || a.findings?.length || 0,
            created_at: a.uploaded_at,
            completed_at: a.uploaded_at,
          })),
          pagination: {
            page,
            limit,
            total: localMockAnalyses.length,
          },
        };
      }
      throw err;
    }
  },

  /**
   * Get complete analysis details by ID.
   * Calls GET /api/analyses/:id
   */
  async getAnalysis(analysisId) {
    if (USE_MOCK_ENV) {
      const match = localMockAnalyses.find((a) => a.analysis_id === analysisId) || mockAnalysis;
      return match;
    }

    try {
      return await apiClient(`/api/analyses/${analysisId}`);
    } catch (err) {
      if (err.isNetworkError || err.status === 401) {
        const match = localMockAnalyses.find((a) => a.analysis_id === analysisId) || mockAnalysis;
        return match;
      }
      throw err;
    }
  },

  /**
   * Export the analysis result as JSON.
   * Calls GET /api/analyses/:id/export
   */
  async exportAnalysis(analysisId) {
    try {
      const blob = await apiClient(`/api/analyses/${analysisId}/export`, {
        asBlob: true,
      });
      return blob;
    } catch (err) {
      if (err.isNetworkError || err.status === 401 || USE_MOCK_ENV) {
        // Generate export blob from local data
        const match = localMockAnalyses.find((a) => a.analysis_id === analysisId) || mockAnalysis;
        const jsonString = JSON.stringify(match, null, 2);
        return new Blob([jsonString], { type: 'application/json' });
      }
      throw err;
    }
  },

  /**
   * Check Gateway connectivity
   */
  async checkHealth() {
    try {
      return await apiClient('/api/health');
    } catch {
      return { status: 'offline' };
    }
  }
};
