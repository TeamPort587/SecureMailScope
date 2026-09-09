import React from 'react';
import { Routes, Route, useNavigate } from 'react-router-dom';

import Navbar from './components/Navbar';
import Footer from './components/Footer';

import Dashboard from './pages/Dashboard';
import Analysis from './pages/Analysis';
import AnalysisOverview from './pages/AnalysisOverview';
import History from './pages/History';
import NotFound from './pages/NotFound';

import { useAnalysis } from './hooks/useAnalysis';

export default function App() {

  const analysisHook = useAnalysis();
  const navigate = useNavigate();

  const handleSelectPreset = (presetData) => {
    analysisHook.loadPreset(presetData);
    if (presetData?.analysis_id) {
      navigate(`/analysis/${presetData.analysis_id}`);
      return;
    }
    navigate('/');
  };

  return (

    <div className="min-h-screen bg-slate-50 text-slate-900">

      {/* Sidebar */}
      <Navbar onLoadPreset={handleSelectPreset} />

      {/* Right of sidebar */}
            <div className="flex min-h-screen flex-col md:ml-[220px]">

        {/* Page content */}
        <main className="flex-1">
          <Routes>

            <Route
              path="/"
              element={<Dashboard analysisHook={analysisHook} />}
            />

            <Route
              path="/analysis"
              element={<AnalysisOverview />}
            />

            <Route
              path="/analysis/:id"
              element={<Analysis />}
            />

            <Route
              path="/history"
              element={<History />}
            />

            <Route
              path="*"
              element={<NotFound />}
            />

          </Routes>
        </main>

        {/* Footer */}
        <Footer />

      </div>

    </div>

  );

}