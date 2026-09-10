import { apiClient } from './client';

/**
 * Fallback questions if backend suggestions fail or for offline/demo captures.
 */
export function generateDefaultSuggestions(analysis) {
  const findings = analysis?.findings || [];
  const suggestions = [];

  const hasPlaintext = findings.some(
    (f) =>
      f.finding_type?.includes('PLAINTEXT') ||
      f.title?.toLowerCase().includes('plain')
  );
  const hasTlsIssues = findings.some(
    (f) =>
      f.finding_type?.includes('TLS') ||
      f.title?.toLowerCase().includes('tls')
  );
  const hasAuthBeforeTls = findings.some(
    (f) =>
      f.finding_type?.includes('AUTH') ||
      f.title?.toLowerCase().includes('auth')
  );
  const hasCertIssues = findings.some(
    (f) =>
      f.finding_type?.includes('CERT') ||
      f.title?.toLowerCase().includes('cert')
  );

  if (hasPlaintext || hasAuthBeforeTls) {
    suggestions.push('What are the risks of plaintext email authentication observed here?');
  }

  if (hasTlsIssues) {
    suggestions.push('How can I enforce modern TLS (v1.3) and strong ciphers in my mail server?');
  }

  if (hasCertIssues) {
    suggestions.push('What are the remediation steps for the certificate warnings in this capture?');
  }

  suggestions.push('What are the highest priority hardening steps based on this analysis?');
  suggestions.push('Can you explain the difference between STARTTLS and Implicit TLS for this configuration?');

  return suggestions.slice(0, 4);
}

export const copilotApi = {
  /**
   * Check AI Copilot status and Ollama availability.
   * @returns {Promise<{ status: 'online' | 'offline', model: string, model_available: boolean }>}
   */
  async getStatus() {
    try {
      return await apiClient('/api/copilot/status');
    } catch (err) {
      return {
        status: 'offline',
        model: 'mailscope-sec:3b',
        model_available: false,
        error: err.message,
      };
    }
  },

  /**
   * Fetch context-aware suggested questions for a given analysis.
   * Falls back to client-side heuristic questions if API is unavailable or for local demo captures.
   * @param {string} analysisId
   * @param {object} analysis - Optional full analysis object for fallback
   * @returns {Promise<string[]>}
   */
  async getSuggestions(analysisId, analysis = null) {
    if (!analysisId) {
      return generateDefaultSuggestions(analysis);
    }

    try {
      const data = await apiClient('/api/copilot/suggestions', {
        method: 'POST',
        body: JSON.stringify({ analysisId }),
      });

      if (data?.suggestions && Array.isArray(data.suggestions) && data.suggestions.length > 0) {
        return data.suggestions.slice(0, 4);
      }
    } catch {
      // Graceful fallback if analysis not in DB or offline
    }

    return generateDefaultSuggestions(analysis);
  },

  /**
   * Send chat prompt to AI Copilot.
   * @param {{ message: string, analysisId: string, history?: Array<{role: string, content: string}> }} params
   * @returns {Promise<{ response: string, model: string, source: string }>}
   */
  async chat({ message, analysisId, history = [] }) {
    return await apiClient('/api/copilot/chat', {
      method: 'POST',
      body: JSON.stringify({
        message,
        analysisId,
        history,
        stream: false,
      }),
    });
  },
};
