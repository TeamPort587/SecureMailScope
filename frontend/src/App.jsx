import React from 'react';
import { Routes, Route, useNavigate, useLocation } from 'react-router-dom';

import Navbar from './components/Navbar';
import Footer from './components/Footer';

import Dashboard from './pages/Dashboard';
import Analysis from './pages/Analysis';
import AnalysisOverview from './pages/AnalysisOverview';
import History from './pages/History';
import NotFound from './pages/NotFound';
import { useAuth } from './context/AuthContext';
import ProtectedRoute from './components/ProtectedRoute';
import Login from './pages/Login';
import { useAnalysis } from './hooks/useAnalysis';

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

    <div className="min-h-screen bg-slate-50 text-slate-900">

            {/* Sidebar — hidden on login */}
      {location.pathname !== '/login' && (
        <Navbar onLoadPreset={handleSelectPreset} onResetAnalysis={handleResetAnalysis} onLogout={logout} user={user} />
      )}

      {/* Right of sidebar */}
      <div className={`flex min-h-screen flex-col ${location.pathname !== '/login' ? 'md:ml-[220px]' : ''}`}>

        {/* Page content */}
        <main className="flex-1">
                    <Routes>

            <Route path="/login" element={<Login />} />

            <Route
              path="/"
              element={
                <ProtectedRoute>
                  <Dashboard analysisHook={analysisHook} />
                </ProtectedRoute>
              }
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
                <ProtectedRoute>
                  <Analysis />
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