import React from 'react';
import { describe, it, expect, vi, beforeEach } from 'vitest';
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { MemoryRouter, Route, Routes } from 'react-router-dom';
import Analysis from '../pages/Analysis';
import { analysisApi } from '../api/analysisApi';
import * as pdfGenerator from '../utils/pdfReportGenerator';
import mockAnalysis from '../mock/mockAnalysis.json';

vi.mock('../context/ThemeContext', () => ({
  useTheme: () => ({ isDark: false }),
}));

describe('Analysis Page Export Options (PDF & JSON)', () => {
  beforeEach(() => {
    vi.clearAllMocks();
  });

  it('renders both Generate PDF Report and Export JSON action buttons', async () => {
    vi.spyOn(analysisApi, 'getAnalysis').mockResolvedValue(mockAnalysis);

    render(
      <MemoryRouter initialEntries={[`/analysis/${mockAnalysis.analysis_id}`]}>
        <Routes>
          <Route path="/analysis/:id" element={<Analysis />} />
        </Routes>
      </MemoryRouter>
    );

    const pdfBtn = await screen.findByRole('button', { name: /generate pdf report/i });
    const jsonBtn = await screen.findByRole('button', { name: /export json/i });

    expect(pdfBtn).toBeInTheDocument();
    expect(jsonBtn).toBeInTheDocument();
  });

  it('triggers PDF generation when clicking Generate PDF Report', async () => {
    vi.spyOn(analysisApi, 'getAnalysis').mockResolvedValue(mockAnalysis);
    const pdfSpy = vi.spyOn(pdfGenerator, 'generatePdfReport').mockResolvedValue({
      filename: 'test.pdf',
      blob: new Blob(['pdf-data'], { type: 'application/pdf' }),
    });

    render(
      <MemoryRouter initialEntries={[`/analysis/${mockAnalysis.analysis_id}`]}>
        <Routes>
          <Route path="/analysis/:id" element={<Analysis />} />
        </Routes>
      </MemoryRouter>
    );

    const pdfBtn = await screen.findByRole('button', { name: /generate pdf report/i });
    fireEvent.click(pdfBtn);

    await waitFor(() => {
      expect(pdfSpy).toHaveBeenCalledTimes(1);
    });
  });

  it('triggers JSON export when clicking Export JSON', async () => {
    vi.spyOn(analysisApi, 'getAnalysis').mockResolvedValue(mockAnalysis);
    const exportJsonSpy = vi.spyOn(analysisApi, 'exportAnalysis').mockResolvedValue(
      new Blob([JSON.stringify(mockAnalysis)], { type: 'application/json' })
    );

    render(
      <MemoryRouter initialEntries={[`/analysis/${mockAnalysis.analysis_id}`]}>
        <Routes>
          <Route path="/analysis/:id" element={<Analysis />} />
        </Routes>
      </MemoryRouter>
    );

    const jsonBtn = await screen.findByRole('button', { name: /export json/i });
    fireEvent.click(jsonBtn);

    await waitFor(() => {
      expect(exportJsonSpy).toHaveBeenCalledWith(mockAnalysis.analysis_id);
    });
  });
});
