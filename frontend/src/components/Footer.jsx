import React from 'react';
import { Link, useLocation, useNavigate } from 'react-router-dom';
import { ExternalLink } from 'lucide-react';

export default function Footer() {
  const location = useLocation();
  const navigate = useNavigate();

  const handleScrollTo = (id) => (e) => {
    e.preventDefault();
    if (location.pathname === '/') {
      const el = document.getElementById(id);
      if (el) {
        el.scrollIntoView({ behavior: 'smooth' });
      } else if (id === 'top') {
        window.scrollTo({ top: 0, behavior: 'smooth' });
      }
    } else {
      navigate(`/#${id}`);
    }
  };

  return (
    <footer className="border-t border-slate-200/90 dark:border-slate-800 bg-white dark:bg-slate-900 transition-colors">
      <div className="mx-auto max-w-6xl px-4 py-10 sm:px-6 lg:px-8">
        <div className="grid grid-cols-1 gap-8 md:grid-cols-4">
          
          {/* BRAND COLUMN */}
          <div className="md:col-span-2">
            <Link
              to="/"
              onClick={handleScrollTo('top')}
              className="inline-flex items-center gap-2.5 group"
            >
              <img
                src="/new_sms_logo.png"
                alt="SecureMailScope"
                className="h-9 w-9 object-contain drop-shadow-sm transition-transform group-hover:scale-105"
              />
              <span className="text-lg font-extrabold tracking-tight text-slate-900 dark:text-white">
                Secure<span className="text-brand-600 dark:text-brand-400">Mail</span>Scope
              </span>
            </Link>

            <p className="mt-3 max-w-sm text-xs text-slate-600 dark:text-slate-400 leading-relaxed font-normal">
              High-fidelity deep packet inspection for email protocols. Detect plaintext credential leakage,
              evaluate cryptographic handshakes, and isolate anomalous outliers across SMTP, IMAP, and POP3.
            </p>
          </div>

          {/* NAVIGATION LINKS */}
          <div>
            <p className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white">
              Platform
            </p>
            <ul className="mt-3 space-y-2 text-xs">
              <li>
                <button
                  type="button"
                  onClick={handleScrollTo('top')}
                  className="text-slate-600 dark:text-slate-400 hover:text-brand-600 dark:hover:text-brand-400 transition-colors cursor-pointer"
                >
                  Home
                </button>
              </li>
              <li>
                <button
                  type="button"
                  onClick={handleScrollTo('pipeline-section')}
                  className="text-slate-600 dark:text-slate-400 hover:text-brand-600 dark:hover:text-brand-400 transition-colors cursor-pointer"
                >
                  Inspection Pipeline
                </button>
              </li>
              <li>
                <button
                  type="button"
                  onClick={handleScrollTo('upload-section')}
                  className="text-slate-600 dark:text-slate-400 hover:text-brand-600 dark:hover:text-brand-400 transition-colors cursor-pointer"
                >
                  Upload PCAP
                </button>
              </li>
              <li>
                <button
                  type="button"
                  onClick={handleScrollTo('faq-section')}
                  className="text-slate-600 dark:text-slate-400 hover:text-brand-600 dark:hover:text-brand-400 transition-colors cursor-pointer"
                >
                  FAQs
                </button>
              </li>
              <li>
                <Link
                  to="/analysis"
                  className="text-slate-600 dark:text-slate-400 hover:text-brand-600 dark:hover:text-brand-400 transition-colors"
                >
                  Security Workspace
                </Link>
              </li>
            </ul>
          </div>

          {/* PROTOCOLS & STANDARDS */}
          <div>
            <p className="text-xs font-bold uppercase tracking-wider text-slate-900 dark:text-white">
              Standards
            </p>
            <ul className="mt-3 space-y-2 text-xs">
              <li>
                <a
                  href="https://datatracker.ietf.org/doc/html/rfc3207"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-slate-600 dark:text-slate-400 hover:text-brand-600 dark:hover:text-brand-400 transition-colors"
                >
                  <span>RFC 3207 (SMTP STARTTLS)</span>
                  <ExternalLink className="h-3 w-3 text-slate-400" />
                </a>
              </li>
              <li>
                <a
                  href="https://datatracker.ietf.org/doc/html/rfc8314"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-slate-600 dark:text-slate-400 hover:text-brand-600 dark:hover:text-brand-400 transition-colors"
                >
                  <span>RFC 8314 (Mail TLS)</span>
                  <ExternalLink className="h-3 w-3 text-slate-400" />
                </a>
              </li>
              <li>
                <a
                  href="https://datatracker.ietf.org/doc/html/rfc2595"
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-slate-600 dark:text-slate-400 hover:text-brand-600 dark:hover:text-brand-400 transition-colors"
                >
                  <span>RFC 2595 (IMAP/POP3 TLS)</span>
                  <ExternalLink className="h-3 w-3 text-slate-400" />
                </a>
              </li>
              <li>
                <span className="font-mono text-[11px] text-slate-500 dark:text-slate-400">
                  Isolation Forest (if-v1)
                </span>
              </li>
            </ul>
          </div>

        </div>

        {/* BOTTOM ROW */}
        <div className="mt-10 border-t border-slate-100 dark:border-slate-800/80 pt-6 flex flex-col sm:flex-row items-center justify-between gap-3 text-xs text-slate-500 dark:text-slate-400">
          <p>© 2026 Team PORT587 · All rights reserved.</p>
          <p className="font-mono text-[11px]">SecureMailScope v0.1.0 · Local Forensic Analysis</p>
        </div>
      </div>
    </footer>
  );
}