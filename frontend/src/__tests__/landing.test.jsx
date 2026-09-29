import React from 'react';
import { describe, it, expect, vi } from 'vitest';
import { render, screen, fireEvent } from '@testing-library/react';
import { BrowserRouter } from 'react-router-dom';

import HeroSection from '../components/landing/HeroSection';
import PipelineSection from '../components/landing/PipelineSection';
import FaqSection from '../components/landing/FaqSection';

describe('Landing Page Components', () => {
  describe('HeroSection', () => {
    it('renders bold uppercase headline and primary call-to-action', () => {
      const onScrollToUpload = vi.fn();
      render(
        <BrowserRouter>
          <HeroSection user={null} onScrollToUpload={onScrollToUpload} />
        </BrowserRouter>
      );

      expect(screen.getByText(/decode traffic,/i)).toBeInTheDocument();
      expect(screen.getByText(/isolate threats/i)).toBeInTheDocument();

      const analyzeBtn = screen.getByRole('button', { name: /analyze pcap/i });
      expect(analyzeBtn).toBeInTheDocument();

      fireEvent.click(analyzeBtn);
      expect(onScrollToUpload).toHaveBeenCalledTimes(1);

      // Verify sign in link for guest
      const signInLink = screen.getByRole('link', { name: /sign in/i });
      expect(signInLink).toBeInTheDocument();
      expect(signInLink).toHaveAttribute('href', '/login');
    });

    it('renders Security Workspace CTA when user is authenticated', () => {
      render(
        <BrowserRouter>
          <HeroSection user={{ email: 'analyst@test.local' }} onScrollToUpload={vi.fn()} />
        </BrowserRouter>
      );

      const analysisLink = screen.getByRole('link', { name: /security workspace/i });
      expect(analysisLink).toBeInTheDocument();
      expect(analysisLink).toHaveAttribute('href', '/analysis');
    });
  });

  describe('PipelineSection', () => {
    it('renders all 5 pipeline stages and switches active stage on tab click', () => {
      render(<PipelineSection />);

      expect(screen.getByText(/How SecureMailScope Inspects Traffic/i)).toBeInTheDocument();
      expect(screen.getAllByText(/Protocol Dissection/i).length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText(/Security Heuristics/i).length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText(/Anomaly Isolation/i).length).toBeGreaterThanOrEqual(1);
      expect(screen.getAllByText(/Remediation & Copilot/i).length).toBeGreaterThanOrEqual(1);

      // Default active stage is Stage 1
      expect(screen.getByText(/STAGE 01/i)).toBeInTheDocument();

      // Click Stage 4 (Anomaly Isolation)
      const stage4Buttons = screen.getAllByRole('button', { name: /Anomaly Isolation/i });
      fireEvent.click(stage4Buttons[0]);

      // Stage 4 should now be active
      expect(screen.getByText(/STAGE 04/i)).toBeInTheDocument();
      expect(screen.getAllByText(/Isolation Forest \(if-v1\)/i).length).toBeGreaterThanOrEqual(1);
    });
  });

  describe('FaqSection', () => {
    it('renders 7 security FAQs and toggles answers on click', () => {
      render(<FaqSection />);

      expect(screen.getByText(/Frequently Asked Questions/i)).toBeInTheDocument();
      expect(
        screen.getByText(/What packet capture file formats does SecureMailScope support\?/i)
      ).toBeInTheDocument();

      // Check first FAQ answer is initially visible
      expect(
        screen.getByText(/SecureMailScope natively supports standard \.pcap, \.pcapng, and \.cap/i)
      ).toBeInTheDocument();

      // Click second FAQ
      const faq2Button = screen.getByRole('button', {
        name: /How does SecureMailScope detect plaintext authentication leaks\?/i,
      });
      fireEvent.click(faq2Button);

      expect(
        screen.getByText(/The inspection engine tracks Layer 7 protocol handshakes/i)
      ).toBeInTheDocument();
    });
  });

  describe('Demo Presets Access & ProtectedRoute', () => {
    it('allows inspecting demo presets without logging in when allowDemo is true', async () => {
      const { default: ProtectedRoute } = await import('../components/ProtectedRoute');
      const { AuthProvider } = await import('../context/AuthContext');
      const { MemoryRouter, Routes, Route } = await import('react-router-dom');

      render(
        <AuthProvider>
          <MemoryRouter initialEntries={['/analysis/demo-vulnerable']}>
            <Routes>
              <Route
                path="/analysis/:id"
                element={
                  <ProtectedRoute allowDemo>
                    <div>Demo Analysis Content Rendered</div>
                  </ProtectedRoute>
                }
              />
              <Route path="/login" element={<div>Login Page</div>} />
            </Routes>
          </MemoryRouter>
        </AuthProvider>
      );

      expect(screen.getByText('Demo Analysis Content Rendered')).toBeInTheDocument();
      expect(screen.queryByText('Login Page')).not.toBeInTheDocument();
    });

    it('redirects to login when accessing a non-demo analysis while unauthenticated', async () => {
      const { default: ProtectedRoute } = await import('../components/ProtectedRoute');
      const { AuthProvider } = await import('../context/AuthContext');
      const { MemoryRouter, Routes, Route } = await import('react-router-dom');

      render(
        <AuthProvider>
          <MemoryRouter initialEntries={['/analysis/unknown-private-id-999']}>
            <Routes>
              <Route
                path="/analysis/:id"
                element={
                  <ProtectedRoute allowDemo>
                    <div>Private Analysis Content</div>
                  </ProtectedRoute>
                }
              />
              <Route path="/login" element={<div>Login Page</div>} />
            </Routes>
          </MemoryRouter>
        </AuthProvider>
      );

      expect(screen.getByText('Login Page')).toBeInTheDocument();
      expect(screen.queryByText('Private Analysis Content')).not.toBeInTheDocument();
    });
  });
});

