import { apiClient, setAuthToken, getAuthToken } from './client';

const USER_EMAIL_KEY = 'sms_user_email';

export const authApi = {
  async register(email, password) {
    const data = await apiClient('/api/auth/register', {
      method: 'POST',
      body: JSON.stringify({ email, password }),
    });

    // Auto-login after successful registration
    if (data?.user) {
      return await this.login(email, password);
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
      if (data.user?.email) {
        localStorage.setItem(USER_EMAIL_KEY, data.user.email);
      }
    }
    return data;
  },

  logout() {
    setAuthToken(null);
    localStorage.removeItem(USER_EMAIL_KEY);
    localStorage.setItem('sms_manual_logout', 'true');
  },

  isAuthenticated() {
    return Boolean(getAuthToken());
  },

  getCurrentUserEmail() {
    return localStorage.getItem(USER_EMAIL_KEY);
  },
};
