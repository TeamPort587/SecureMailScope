import { apiClient, setAuthToken, getAuthToken } from './client';

export const authApi = {
  async register(email, password) {
    const data = await apiClient('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
    if (data?.token) {
      setAuthToken(data.token);
    }
    return data;
  },

  async login(email, password) {
    const data = await apiClient('/api/auth/login', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });
    if (data?.token) {
      setAuthToken(data.token);
    }
    return data;
  },

  logout() {
    setAuthToken(null);
  },

  isAuthenticated() {
    return Boolean(getAuthToken());
  },
};
