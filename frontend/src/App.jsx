import React from 'react';
import { Routes, Route, useNavigate } from 'react-router-dom';
import Navbar from './components/Navbar';
import Footer from './components/Footer';
import Dashboard from './pages/Dashboard';
import Analysis from './pages/Analysis';
import History from './pages/History';
import NotFound from './pages/NotFound';
import AuthModal from './components/AuthModal';
import { AuthProvider } from './context/AuthContext';
import { useAnalysis } from './hooks/useAnalysis';

function AppContent() {
  const analysisHook = useAnalysis();
  const navigate = useNavigate();

  const handleSelectPreset = (presetData) => {
    analysisHook.loadPreset(presetData);
    navigate('/');
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

      {/* Shell Footer */}
      <Footer />

      {/* Central Auth Modal */}
      <AuthModal />
    </div>
  );
}

export default function App() {
  return (
    <AuthProvider>
      <AppContent />
    </AuthProvider>
  );
}
