import { useState, useCallback, useEffect } from 'react';
import { analysisApi } from '../api/analysisApi';

export function useAnalysis(initialAnalysisId = null) {
  const [analysis, setAnalysis] = useState(null);
  const [loading, setLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [error, setError] = useState(null);

  const fetchAnalysis = useCallback(async (id) => {
    if (!id) return;
    setLoading(true);
    setError(null);
    try {
      const data = await analysisApi.getAnalysis(id);
      setAnalysis(data);
      return data;
    } catch (err) {
      setError(err.message || 'Failed to load analysis details.');
    } finally {
      setLoading(false);
    }
  }, []);

  const uploadPcap = useCallback(async (file) => {
    setUploading(true);
    setError(null);
    try {
      const result = await analysisApi.uploadAnalysis(file);
      setAnalysis(result);
      return result;
    } catch (err) {
      setError(err.message || 'Failed to analyze PCAP file.');
      throw err;
    } finally {
      setUploading(false);
    }
  }, []);

  const exportJson = useCallback(async (id) => {
    const targetId = id || analysis?.analysis_id;
    if (!targetId) return;
    try {
      const blob = await analysisApi.exportAnalysis(targetId);
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.style.display = 'none';
      a.href = url;
      a.download = `securemailscope_analysis_${targetId}.json`;
      document.body.appendChild(a);
      a.click();
      window.URL.revokeObjectURL(url);
      document.body.removeChild(a);
    } catch (err) {
      setError(err.message || 'Failed to export analysis JSON.');
    }
  }, [analysis]);

  const loadPreset = useCallback((presetData) => {
    setAnalysis(presetData);
    setError(null);
  }, []);

  useEffect(() => {
    if (initialAnalysisId) {
      fetchAnalysis(initialAnalysisId);
    }
  }, [initialAnalysisId, fetchAnalysis]);

  return {
    analysis,
    loading,
    uploading,
    error,
    fetchAnalysis,
    uploadPcap,
    exportJson,
    loadPreset,
    setAnalysis,
    setError,
  };
}
