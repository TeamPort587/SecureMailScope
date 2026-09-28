import React from 'react';
import { Routes, Route, useNavigate, useLocation } from 'react-router-dom';

import Navbar from './components/Navbar';
import Footer from './components/Footer';

import Dashboard from './pages/Dashboard';
import Analysis from './pages/Analysis';
import SessionPage from './pages/SessionPage';
import AnalysisOverview from './pages/AnalysisOverview';
import History from './pages/History';
import NotFound from './pages/NotFound';
import { useAuth } from './context/AuthContext';
import ProtectedRoute from './components/ProtectedRoute';
import Login from './pages/Login';
import { useAnalysis } from './hooks/useAnalysis';
import ScrollToTop from './components/ScrollToTop';

export default function App() {

  const analysisHook = useAnalysis();
  const navigate = useNavigate();
  const { logout, user } = useAuth();
  const location = useLocation();

  const handleSelectPreset = (presetData) => {
    analysisHook.loadPreset(presetData);
    if (presetData?.analysis_id) {
      navigate(`/analysis/${presetData.analysis_id}`);
      return;
    }
    navigate('/');
  };

  const handleResetAnalysis = () => {
    analysisHook.setAnalysis(null);
  };

  // Clear analysis on every login so dashboard always shows upload screen
  React.useEffect(() => {
    if (user) {
      analysisHook.setAnalysis(null);
    }
  }, [user]);

  return (

    <div className="min-h-screen bg-slate-50 dark:bg-slate-950 text-slate-900 dark:text-slate-100 transition-colors duration-200">
      <ScrollToTop />

      {/* Global Navbar */}
      <Navbar onLoadPreset={handleSelectPreset} onResetAnalysis={handleResetAnalysis} onLogout={logout} user={user} />

      {/* Main page content layout */}
      <div className="flex min-h-screen flex-col">

        {/* Page content */}
        <main className="flex-1 w-full flex flex-col">
                    <Routes>

            <Route path="/login" element={<Login />} />

            <Route
              path="/"
              element={<Dashboard analysisHook={analysisHook} />}
            />

            <Route
              path="/analysis"
              element={
                <ProtectedRoute>
                  <AnalysisOverview />
                </ProtectedRoute>
              }
            />

            <Route
              path="/analysis/:id"
              element={
                <ProtectedRoute allowDemo>
                  <Analysis />
                </ProtectedRoute>
              }
            />

            <Route
              path="/analysis/:id/session/:sessionId"
              element={
                <ProtectedRoute allowDemo>
                  <SessionPage />
                </ProtectedRoute>
              }
            />

            <Route
              path="/analysis/:id/sessions/:sessionId"
              element={
                <ProtectedRoute allowDemo>
                  <SessionPage />
                </ProtectedRoute>
              }
            />

            <Route
              path="/history"
              element={
                <ProtectedRoute>
                  <History />
                </ProtectedRoute>
              }
            />

            <Route path="*" element={<NotFound />} />

          </Routes>
        </main>

        {/* Footer */}
        <Footer />

      </div>

    </div>

  );

}