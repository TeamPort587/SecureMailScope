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

    try {
      const formData = new FormData();

      formData.append('file', file);

      const result = await apiClient('/api/analyze', {
        method: 'POST',
        body: formData,
      });

      /*
       | Store locally too so navigation to:
       | /analysis/:id
       | works immediately.
       */

      if (result?.analysis_id) {
        const exists = findLocalAnalysis(
          result.analysis_id
        );

        if (!exists) {
          localMockAnalyses.unshift(result);
        }
      }

      return result;

    } catch (err) {

      if (
        err.isNetworkError ||
        err.status === 401
      ) {
        console.warn(
          'Backend unavailable. Using local development analysis.'
        );

        return createFallbackAnalysis(file.name);
      }

      throw err;
    }
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

    try {

      return await apiClient(
        `/api/analyses?page=${page}&limit=${limit}`
      );

    } catch (err) {

      if (
        err.isNetworkError ||
        err.status === 401
      ) {

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

      throw err;
    }
  },


  /*
  |--------------------------------------------------------------------------
  | Get Analysis By ID
  |--------------------------------------------------------------------------
  */

  async getAnalysis(analysisId) {

    /*
     | First check local state.
     |
     | This is important for:
     | - demo presets
     | - newly uploaded mock files
     | - immediate navigation
     |
     */

    const localMatch =
      findLocalAnalysis(analysisId);

    if (USE_MOCK_ENV) {

      if (localMatch) {
        return localMatch;
      }

      throw new Error(
        `Analysis "${analysisId}" was not found in local demo data.`
      );
    }


    /*
     | If analysis already exists locally,
     | return it immediately.
     */

    if (localMatch) {
      return localMatch;
    }


    /*
     | Otherwise ask backend.
     */

    try {

      const result =
        await apiClient(
          `/api/analyses/${encodeURIComponent(analysisId)}`
        );

      if (result?.analysis_id) {

        const exists =
          findLocalAnalysis(
            result.analysis_id
          );

        if (!exists) {
          localMockAnalyses.unshift(result);
        }
      }

      return result;

    } catch (err) {

      /*
       | Only fallback for actual connectivity/auth problems.
       |
       | DO NOT fallback on 404.
       */

      if (
        err.isNetworkError ||
        err.status === 401
      ) {

        const fallback =
          findLocalAnalysis(analysisId);

        if (fallback) {
          return fallback;
        }

        throw new Error(
          'Backend is unavailable and this analysis is not available locally.'
        );
      }


      if (err.status === 404) {

        throw new Error(
          `Analysis record "${analysisId}" was not found.`
        );
      }

      throw err;
    }
  },


  /*
  |--------------------------------------------------------------------------
  | Export Analysis
  |--------------------------------------------------------------------------
  */

  async exportAnalysis(analysisId) {

    const localMatch =
      findLocalAnalysis(analysisId);

    if (USE_MOCK_ENV) {

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

    try {

      return await apiClient(
        `/api/analyses/${encodeURIComponent(analysisId)}/export`,
        {
          asBlob: true,
        }
      );

    } catch (err) {

      if (
        (err.isNetworkError ||
          err.status === 401) &&
        localMatch
      ) {

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

      throw err;
    }
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