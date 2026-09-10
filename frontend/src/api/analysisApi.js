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

function findLocalAnalysis(analysisId) {
  return localMockAnalyses.find(
    (analysis) =>
      String(analysis.analysis_id) === String(analysisId)
  );
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

  async getAnalyses(page = 1, limit = 20) {

    if (USE_MOCK_ENV) {

      const start =
        (page - 1) * limit;

      const end =
        start + limit;

      const items =
        localMockAnalyses
          .map((analysis) => ({
            analysis_id:
              analysis.analysis_id,

            filename:
              analysis.filename,

            status:
              analysis.status || 'COMPLETED',

            risk_label:
              analysis.risk?.level ||
              'UNKNOWN',

            risk_score:
              analysis.risk?.score ??
              null,

            session_count:
              analysis.summary?.total_sessions ||
              analysis.sessions?.length ||
              0,

            finding_count:
              analysis.summary?.findings_count ||
              analysis.findings?.length ||
              0,

            created_at:
              analysis.uploaded_at,

            completed_at:
              analysis.uploaded_at,
          }))
          .slice(start, end);

      return {
        items,

        pagination: {
          page,
          limit,
          total:
            localMockAnalyses.length,
        },
      };
    }

    return await apiClient(
      `/api/analyses?page=${page}&limit=${limit}`
    );
  },


  /*
  |--------------------------------------------------------------------------
  | Get Analysis By ID
  |--------------------------------------------------------------------------
  */

  async getAnalysis(analysisId) {
    const isDemoId =
      String(analysisId).startsWith('demo-') ||
      String(analysisId).startsWith('sec-') ||
      String(analysisId).startsWith('local-');

    if (USE_MOCK_ENV || isDemoId) {
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
  | Export Analysis
  |--------------------------------------------------------------------------
  */

  async exportAnalysis(analysisId) {
    const isDemoId =
      String(analysisId).startsWith('demo-') ||
      String(analysisId).startsWith('sec-') ||
      String(analysisId).startsWith('local-');

    if (USE_MOCK_ENV || isDemoId) {
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