import { useState, useCallback, useEffect } from 'react';
import { analysisApi } from '../api/analysisApi';

export function useAnalysis(initialAnalysisId = null, initialData = null) {
  const [analysis, setAnalysis] = useState(initialData);
  const [loading, setLoading] = useState(false);
  const [uploading, setUploading] = useState(false);
  const [generatingPdf, setGeneratingPdf] = useState(false);
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

  const exportPdf = useCallback(async (customAnalysis = null) => {
    const target = customAnalysis || analysis;
    if (!target) return;
    setGeneratingPdf(true);
    try {
      let fullAnalysis = target;
      if (!fullAnalysis.sessions && target.analysis_id) {
        fullAnalysis = await analysisApi.getAnalysis(target.analysis_id);
      }
      const { generatePdfReport } = await import('../utils/pdfReportGenerator');
      await generatePdfReport(fullAnalysis, { download: true });
    } catch (err) {
      setError(err.message || 'Failed to generate PDF report.');
    } finally {
      setGeneratingPdf(false);
    }
  }, [analysis]);


  const loadPreset = useCallback((presetData) => {
    setAnalysis(presetData);
    setError(null);
  }, []);

  useEffect(() => {
    if (initialAnalysisId) {
      if (!initialData || String(initialData.analysis_id) !== String(initialAnalysisId)) {
        fetchAnalysis(initialAnalysisId);
      }
    }
  }, [initialAnalysisId, initialData, fetchAnalysis]);

  return {
    analysis,
    loading,
    uploading,
    generatingPdf,
    error,
    fetchAnalysis,
    uploadPcap,
    exportJson,
    exportPdf,
    loadPreset,
    setAnalysis,
    setError,
  };
}

