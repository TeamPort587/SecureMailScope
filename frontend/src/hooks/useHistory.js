import { useState, useCallback, useEffect } from 'react';
import { analysisApi } from '../api/analysisApi';

export function useHistory(initialPage = 1, initialLimit = 10) {
  const [items, setItems] = useState([]);
  const [pagination, setPagination] = useState({ page: initialPage, limit: initialLimit, total: 0 });
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState(null);

  const fetchHistory = useCallback(async (page = initialPage, limit = initialLimit) => {
    setLoading(true);
    setError(null);
    try {
      const data = await analysisApi.getAnalyses(page, limit);
      setItems(data?.items || []);
      setPagination(data?.pagination || { page, limit, total: (data?.items || []).length });
    } catch (err) {
      setError(err.message || 'Failed to retrieve analysis history.');
    } finally {
      setLoading(false);
    }
  }, [initialPage, initialLimit]);

  useEffect(() => {
    fetchHistory(initialPage, initialLimit);
  }, [fetchHistory, initialPage, initialLimit]);

  return {
    items,
    pagination,
    loading,
    error,
    refresh: fetchHistory,
  };
}
