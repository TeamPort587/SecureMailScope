const API_BASE_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:3000';
const TOKEN_STORAGE_KEY = 'sms_auth_token';

export function getAuthToken() {
  return localStorage.getItem(TOKEN_STORAGE_KEY);
}

export function setAuthToken(token) {
  if (token) {
    localStorage.setItem(TOKEN_STORAGE_KEY, token);
  } else {
    localStorage.removeItem(TOKEN_STORAGE_KEY);
  }
}

/**
 * Universal request wrapper for communicating strictly with Node.js API Gateway.
 */
export async function apiClient(endpoint, options = {}) {
  const url = `${API_BASE_URL.replace(/\/$/, '')}${endpoint.startsWith('/') ? '' : '/'}${endpoint}`;

  const headers = {
    ...(options.headers || {}),
  };

  const token = getAuthToken();
  if (token && !headers['Authorization']) {
    headers['Authorization'] = `Bearer ${token}`;
  }

  // Do not set Content-Type if uploading FormData (let browser handle boundary)
  if (options.body && !(options.body instanceof FormData) && !headers['Content-Type']) {
    headers['Content-Type'] = 'application/json';
  }

  try {
    const response = await fetch(url, {
      ...options,
      headers,
    });

    // Handle 204 No Content
    if (response.status === 204) {
      return null;
    }

    // Handle blob downloads (e.g. export)
    const contentType = response.headers.get('content-type') || '';
    if (options.asBlob || contentType.includes('application/octet-stream')) {
      if (!response.ok) {
        throw new Error(`Export failed with HTTP status ${response.status}`);
      }
      return await response.blob();
    }

    const data = await response.json().catch(() => null);

    if (!response.ok) {
      const message =
        data?.error?.message ||
        data?.message ||
        (response.status === 401
          ? 'Authentication required. Please check your credentials.'
          : response.status === 403
          ? 'You do not have permission to view or export this analysis.'
          : response.status === 413
          ? 'Uploaded PCAP file is too large.'
          : response.status === 404
          ? 'The requested analysis was not found.'
          : `Server request failed (HTTP ${response.status})`);

      const error = new Error(message);
      error.status = response.status;
      error.data = data;
      throw error;
    }

    return data;
  } catch (err) {
    // If it's a TypeError: Failed to fetch, the Node gateway is likely down
    if (err.name === 'TypeError' && err.message.includes('fetch')) {
      const networkErr = new Error('Unable to connect to Node.js Gateway. Ensure the gateway service is running on ' + API_BASE_URL);
      networkErr.isNetworkError = true;
      throw networkErr;
    }
    throw err;
  }
}

export { API_BASE_URL };
