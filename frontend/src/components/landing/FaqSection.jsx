import React, { useState } from 'react';
import { ChevronDown, HelpCircle, ShieldCheck } from 'lucide-react';

const FAQS = [
  {
    id: 'faq-1',
    question: 'What packet capture file formats does SecureMailScope support?',
    answer:
      'SecureMailScope natively supports standard .pcap, .pcapng, and .cap network capture files up to 100MB. These captures can be collected using Wireshark, tcpdump, TShark, or Zeek from network taps, SPAN ports, firewall captures, or host-level packet dumps.',
  },
  {
    id: 'faq-2',
    question: 'How does SecureMailScope detect plaintext authentication leaks?',
    answer:
      'The inspection engine tracks Layer 7 protocol handshakes. If commands such as "AUTH PLAIN", "AUTH LOGIN", or cleartext password transmissions are sent over an unencrypted TCP stream or prior to the completion of a valid STARTTLS handshake, SecureMailScope flags it immediately as a CRITICAL security finding, extracting the affected stream index and client/server endpoints.',
  },
  {
    id: 'faq-3',
    question: 'Does SecureMailScope decrypt TLS payloads or require private keys?',
    answer:
      'No. SecureMailScope is designed for passive and privacy-preserving network security inspection without needing private keys or breaking TLS encryption. It evaluates the security posture through protocol command parsing, STARTTLS negotiation flags, TLS Client/Server Hello handshakes, cipher suite offerings, TLS version negotiation, and certificate metadata.',
  },
  {
    id: 'faq-4',
    question: 'How does the Isolation Forest anomaly detection model work?',
    answer:
      'SecureMailScope extracts a 30-dimensional feature vector per TCP stream (including inter-packet arrival times, packet size distributions, byte entropy, command cadences, and session durations). An unsupervised Isolation Forest algorithm (model if-v1) identifies sessions that structurally diverge from normal traffic baselines, generating decision scores and isolating volumetric, timing, or protocol outliers.',
  },
  {
    id: 'faq-5',
    question: 'What email protocols and ports are actively inspected?',
    answer:
      'The engine reconstructs and inspects SMTP (port 25 for server-to-server MTA transfer, port 587 for mail submission, port 465 for SMTPS), IMAP (port 143 for STARTTLS, port 993 for IMAPS), and POP3 (port 110 for STARTTLS, port 995 for POP3S). Both implicit TLS and explicit opportunistic STARTTLS upgrades are dissected.',
  },
  {
    id: 'faq-6',
    question: 'How does the AI Security Copilot assist in triage and remediation?',
    answer:
      'The AI Security Copilot integrates an intelligent LLM engine (or secure fallback heuristics) with zero external data leakage. Security analysts can ask natural language questions about specific findings, request exact configuration hardening templates for mail servers (Postfix, Dovecot, Exim, Sendmail), or generate specialized Wireshark display filters to isolate culprit packets.',
  },
  {
    id: 'faq-7',
    question: 'Is my uploaded network capture data secure and private?',
    answer:
      'Yes. Uploaded PCAPs are analyzed locally in your instance. All parsing and anomaly isolation occur in isolated processing pipelines. Captures and analysis artifacts are associated strictly with authenticated analyst accounts, and no network traffic or credentials are ever transmitted to third-party cloud services.',
  },
];

export default function FaqSection() {
  const [openId, setOpenId] = useState('faq-1');

  const toggle = (id) => {
    setOpenId((prev) => (prev === id ? null : id));
  };

  return (
    <section id="faq-section" className="py-12 sm:py-16 lg:py-20 border-t border-slate-200/80 dark:border-slate-800/80">
      <div className="mx-auto max-w-4xl px-4 sm:px-6 lg:px-8">
        
        {/* HEADER */}
        <div className="text-center max-w-2xl mx-auto">
          <div className="inline-flex items-center gap-2 rounded-full border border-slate-200 dark:border-slate-800 bg-white dark:bg-slate-850 px-3 py-1 text-xs font-semibold text-slate-700 dark:text-slate-300">
            <HelpCircle className="h-3.5 w-3.5 text-brand-600 dark:text-brand-400" />
            <span>Got Questions?</span>
          </div>

          <h2 className="mt-3.5 text-2xl sm:text-3xl font-bold tracking-tight text-slate-900 dark:text-white">
            Frequently Asked Questions
          </h2>

          <p className="mt-2 text-sm text-slate-600 dark:text-slate-400">
            Everything you need to know about PCAP parsing, protocol standards, TLS posture, and anomaly detection.
          </p>
        </div>

        {/* ACCORDION LIST */}
        <div className="mt-10 space-y-3">
          {FAQS.map((faq, idx) => {
            const isOpen = openId === faq.id;

            return (
              <div
                key={faq.id}
                className={`rounded-2xl border transition-all duration-200 overflow-hidden bg-white dark:bg-slate-900 ${
                  isOpen
                    ? 'border-brand-400 dark:border-brand-600 shadow-sm ring-1 ring-brand-500/10'
                    : 'border-slate-200/90 dark:border-slate-800 hover:border-slate-300 dark:hover:border-slate-700'
                }`}
              >
                <button
                  type="button"
                  onClick={() => toggle(faq.id)}
                  aria-expanded={isOpen}
                  className="flex w-full items-center justify-between gap-4 p-4 sm:p-5 text-left cursor-pointer select-none"
                >
                  <div className="flex items-center gap-3">
                    <span className="font-mono text-xs font-bold text-slate-400 dark:text-slate-500">
                      0{idx + 1}
                    </span>
                    <span className="text-sm sm:text-base font-semibold text-slate-900 dark:text-white">
                      {faq.question}
                    </span>
                  </div>

                  <span
                    className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-lg border transition-transform duration-200 ${
                      isOpen
                        ? 'rotate-180 border-brand-300 dark:border-brand-600 bg-brand-50 dark:bg-brand-950/60 text-brand-600 dark:text-brand-400'
                        : 'border-slate-200 dark:border-slate-700 bg-slate-50 dark:bg-slate-800 text-slate-500 dark:text-slate-400'
                    }`}
                  >
                    <ChevronDown className="h-4 w-4" />
                  </span>
                </button>

                {isOpen && (
                  <div className="border-t border-slate-100 dark:border-slate-800 px-4 sm:px-5 pb-5 pt-3.5 animate-in fade-in duration-150">
                    <p className="text-xs sm:text-sm text-slate-600 dark:text-slate-300 leading-relaxed pl-6 sm:pl-7">
                      {faq.answer}
                    </p>
                  </div>
                )}
              </div>
            );
          })}
        </div>

      </div>
    </section>
  );
}
