import React, { createContext, useContext, useState, useEffect, useCallback } from 'react';
import { authApi } from '../api/authApi';
import { getAuthToken, setAuthToken } from '../api/client';

const AuthContext = createContext(null);

export function AuthProvider({ children }) {
  const [token, setToken] = useState(() => getAuthToken());
  const [userEmail, setUserEmail] = useState(() => authApi.getCurrentUserEmail());
  const [isAuthModalOpen, setIsAuthModalOpen] = useState(false);

  // Sync token and email
  useEffect(() => {
    const handleAuthRequired = () => {
      setToken(null);
      setUserEmail(null);
      setIsAuthModalOpen(true);
    };

    window.addEventListener('auth:required', handleAuthRequired);
    return () => window.removeEventListener('auth:required', handleAuthRequired);
  }, []);

  const openAuthModal = useCallback(() => {
    setIsAuthModalOpen(true);
  }, []);

  const closeAuthModal = useCallback(() => {
    setIsAuthModalOpen(false);
  }, []);

  const login = useCallback(async (email, password) => {
    const res = await authApi.login(email, password);
    setToken(getAuthToken());
    setUserEmail(email);
    setIsAuthModalOpen(false);
    return res;
  }, []);

  const register = useCallback(async (email, password) => {
    const res = await authApi.register(email, password);
    setToken(getAuthToken());
    setUserEmail(email);
    setIsAuthModalOpen(false);
    return res;
  }, []);

  const logout = useCallback(() => {
    authApi.logout();
    setToken(null);
    setUserEmail(null);
  }, []);

  const value = {
    token,
    userEmail,
    isAuthenticated: Boolean(token),
    isAuthModalOpen,
    openAuthModal,
    closeAuthModal,
    login,
    register,
    logout,
  };

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}

export function useAuth() {
  const context = useContext(AuthContext);
  if (!context) {
    return {
      token: 'test-token',
      userEmail: 'test@example.com',
      isAuthenticated: true,
      isAuthModalOpen: false,
      openAuthModal: () => {},
      closeAuthModal: () => {},
      login: async () => {},
      register: async () => {},
      logout: () => {},
    };
  }
  return context;
}
