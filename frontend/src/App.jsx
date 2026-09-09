import React from 'react';
import { Routes, Route, useNavigate } from 'react-router-dom';

import Navbar from './components/Navbar';
import Footer from './components/Footer';

import Dashboard from './pages/Dashboard';
import Analysis from './pages/Analysis';
import AnalysisOverview from './pages/AnalysisOverview';
import History from './pages/History';
import NotFound from './pages/NotFound';
<<<<<<< HEAD

import { useAuth } from './context/AuthContext';
import ProtectedRoute from './components/ProtectedRoute';
import Login from './pages/Login';

=======
import AuthModal from './components/AuthModal';
import { AuthProvider } from './context/AuthContext';
import { ThemeProvider } from './context/ThemeContext';
>>>>>>> fa4deee23e3439463fa2e7a7defb47a88ada3fbd
import { useAnalysis } from './hooks/useAnalysis';

function AppContent() {
  const analysisHook = useAnalysis();
  const navigate = useNavigate();
    const { logout, user } = useAuth();

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

  return (
    <div className="min-h-screen flex flex-col bg-slate-950 text-slate-100 selection:bg-brand-500 selection:text-white">
      {/* Shell Header */}
      <Navbar onSelectPreset={handleSelectPreset} />

      {/* Main Content Area */}
      <main className="flex-1">
        <Routes>
          <Route path="/" element={<Dashboard analysisHook={analysisHook} />} />
          <Route path="/analysis/:id" element={<Analysis />} />
          <Route path="/history" element={<History />} />
          <Route path="*" element={<NotFound />} />
        </Routes>
      </main>

      {/* Sidebar */}
      <Navbar onLoadPreset={handleSelectPreset} onResetAnalysis={handleResetAnalysis} onLogout={logout} user={user} />

      {/* Right of sidebar */}
            <div className="flex min-h-screen flex-col md:ml-[220px]">

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

      {/* Central Auth Modal */}
      <AuthModal />
    </div>

  );
}

export default function App() {
  return (
    <ThemeProvider>
      <AuthProvider>
        <AppContent />
      </AuthProvider>
    </ThemeProvider>
  );
}
