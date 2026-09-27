const logger = require('../utils/logger');

/**
 * Copilot Prompt Engineering Service.
 *
 * Builds grounded system prompts from analysis telemetry and generates
 * context-aware suggested questions based on detected findings.
 */

// ============================================================================
// SUGGESTED QUESTION RULES
// ============================================================================

/**
 * Mapping of finding types to suggested questions.
 * Each rule has a `match` function that checks findings and a `question` string.
 */
const QUESTION_RULES = [
  {
    id: 'auth_before_tls',
    match: (findings) =>
      findings.some(
        (f) =>
          f.finding_type === 'auth_before_tls' ||
          f.title?.toLowerCase().includes('authentication') &&
          f.title?.toLowerCase().includes('before')
      ),
    question:
      'How do I enforce STARTTLS before authentication in Postfix to prevent credential exposure?',
  },
  {
    id: 'deprecated_tls',
    match: (findings) =>
      findings.some(
        (f) =>
          f.finding_type === 'deprecated_tls' ||
          f.finding_type === 'weak_tls_version' ||
          f.title?.toLowerCase().includes('tls 1.0') ||
          f.title?.toLowerCase().includes('tls 1.1') ||
          f.title?.toLowerCase().includes('deprecated')
      ),
    question:
      'Why is TLS 1.0/1.1 vulnerable and what are the compliance implications under RFC 8996?',
  },
  {
    id: 'weak_cipher',
    match: (findings) =>
      findings.some(
        (f) =>
          f.finding_type === 'weak_cipher' ||
          f.finding_type === 'weak_cipher_suite' ||
          f.title?.toLowerCase().includes('cipher')
      ),
    question:
      'Which modern cipher suites should I whitelist in Postfix and Dovecot to comply with RFC 7525?',
  },
  {
    id: 'self_signed_cert',
    match: (findings) =>
      findings.some(
        (f) =>
          f.finding_type === 'self_signed_cert' ||
          f.finding_type === 'self_signed_certificate' ||
          f.title?.toLowerCase().includes('self-signed') ||
          f.title?.toLowerCase().includes('self signed')
      ),
    question:
      'What are the risks of self-signed certificates and how do I deploy proper CA-signed certs for my mail server?',
  },
  {
    id: 'missing_starttls',
    match: (findings) =>
      findings.some(
        (f) =>
          f.finding_type === 'missing_starttls' ||
          f.finding_type === 'no_starttls' ||
          f.title?.toLowerCase().includes('starttls') &&
          (f.title?.toLowerCase().includes('missing') ||
            f.title?.toLowerCase().includes('not'))
      ),
    question:
      'How do I configure mandatory STARTTLS in Postfix so plaintext connections are rejected?',
  },
  {
    id: 'plaintext_auth',
    match: (findings) =>
      findings.some(
        (f) =>
          f.finding_type === 'plaintext_auth' ||
          f.finding_type === 'cleartext_credentials' ||
          f.title?.toLowerCase().includes('plaintext') ||
          f.title?.toLowerCase().includes('cleartext')
      ),
    question:
      'What is the risk of plaintext authentication (CWE-319) and how do I enforce encrypted auth mechanisms?',
  },
  {
    id: 'weak_key',
    match: (findings) =>
      findings.some(
        (f) =>
          f.finding_type === 'weak_key' ||
          f.finding_type === 'small_key_size' ||
          f.title?.toLowerCase().includes('key size') ||
          f.title?.toLowerCase().includes('1024-bit')
      ),
    question:
      'What minimum key sizes does NIST SP 800-52r2 recommend, and how do I regenerate my mail server certificates?',
  },
];

/**
 * Default question always included.
 */
const EXECUTIVE_SUMMARY_QUESTION =
  'Generate an Executive Summary of this capture for leadership';

/**
 * General fallback questions when not enough finding-specific ones exist.
 */
const GENERAL_QUESTIONS = [
  'What are the key security best practices for hardening an email server?',
  'How does STARTTLS differ from implicit TLS (port 465 vs 587)?',
  'What MITRE ATT&CK techniques are relevant to the findings in this capture?',
  'What compliance frameworks (PCI DSS, HIPAA, SOC 2) are affected by these findings?',
  'How do I set up certificate pinning for my mail infrastructure?',
];

// ============================================================================
// PUBLIC API
// ============================================================================

/**
 * Generate exactly 4 context-aware suggested questions based on analysis findings.
 *
 * @param {Array} findings - Array of finding objects from the analysis
 * @param {object} risk - Risk object with level, score, etc.
 * @returns {string[]} - Exactly 4 suggested questions
 */
function generateSuggestedQuestions(findings = [], risk = null) {
  const matched = [];

  // Check each rule against findings
  for (const rule of QUESTION_RULES) {
    if (rule.match(findings)) {
      matched.push(rule.question);
    }
  }

  // Always include executive summary
  const suggestions = [];
  const used = new Set();

  // Add up to 3 finding-specific questions
  for (const q of matched) {
    if (suggestions.length >= 3) break;
    suggestions.push(q);
    used.add(q);
  }

  // Always add executive summary as the last question
  suggestions.push(EXECUTIVE_SUMMARY_QUESTION);

  // If we have fewer than 4, pad with general questions
  let generalIdx = 0;
  while (suggestions.length < 4 && generalIdx < GENERAL_QUESTIONS.length) {
    const q = GENERAL_QUESTIONS[generalIdx];
    if (!used.has(q)) {
      suggestions.splice(suggestions.length - 1, 0, q); // Insert before executive summary
      used.add(q);
    }
    generalIdx++;
  }

  return suggestions.slice(0, 4);
}

/**
 * Build a grounded system prompt by injecting analysis telemetry.
 *
 * The system prompt provides the model with the full context of the analysis
 * so every response is grounded in actual PCAP data, not generic advice.
 *
 * @param {object} analysisData
 * @param {object} analysisData.analysis - Analysis metadata (filename, status, etc.)
 * @param {Array}  analysisData.sessions - Session objects
 * @param {Array}  analysisData.findings - Finding objects
 * @param {object} analysisData.risk - Risk assessment object
 * @param {Array}  analysisData.recommendations - Recommendation objects
 * @returns {string} - Complete system prompt with injected telemetry
 */
function buildSystemPrompt(analysisData) {
  const { analysis, sessions, findings, risk, recommendations } = analysisData;

  // --- Build telemetry sections ---

  // 1. Overview
  const overviewLines = [];
  if (analysis?.filename) {
    overviewLines.push(`Capture File: ${analysis.filename}`);
  }
  if (risk) {
    overviewLines.push(
      `Overall Risk: ${risk.level || 'UNKNOWN'} (score: ${risk.score ?? 'N/A'})`
    );
    if (risk.model_version) {
      overviewLines.push(`Risk Model: ${risk.model_version}`);
    }
  }
  overviewLines.push(`Total Sessions: ${sessions?.length || 0}`);
  overviewLines.push(`Total Findings: ${findings?.length || 0}`);

  // 2. Session summary
  const sessionLines = [];
  if (sessions && sessions.length > 0) {
    const protocols = [...new Set(sessions.map((s) => s.protocol).filter(Boolean))];
    const ports = [...new Set(sessions.map((s) => s.server_port || s.dst_port).filter(Boolean))];
    const encModes = [...new Set(sessions.map((s) => s.security?.encryption_mode).filter(Boolean))];
    const tlsVersions = [...new Set(sessions.map((s) => s.tls?.version).filter(Boolean))];

    sessionLines.push(`Protocols: ${protocols.join(', ') || 'None detected'}`);
    sessionLines.push(`Ports: ${ports.join(', ')}`);
    sessionLines.push(`Encryption Modes: ${encModes.join(', ') || 'None'}`);
    if (tlsVersions.length > 0) {
      sessionLines.push(`TLS Versions: ${tlsVersions.join(', ')}`);
    }

    // Flag notable session attributes
    const authBeforeTls = sessions.filter(
      (s) => s.security?.authentication_before_tls === true
    );
    if (authBeforeTls.length > 0) {
      sessionLines.push(
        `⚠ ${authBeforeTls.length} session(s) have authentication before TLS upgrade`
      );
    }
  }

  // 3. Findings detail
  const findingLines = [];
  if (findings && findings.length > 0) {
    findings.forEach((f, idx) => {
      findingLines.push(
        `  ${idx + 1}. [${(f.severity || 'INFO').toUpperCase()}] ${f.title || f.finding_type}`
      );
      if (f.description) {
        findingLines.push(`     ${f.description}`);
      }
    });
  }

  // 4. Recommendations
  const recLines = [];
  if (recommendations && recommendations.length > 0) {
    recommendations.forEach((r, idx) => {
      recLines.push(
        `  ${idx + 1}. [${(r.priority || 'MEDIUM').toUpperCase()}] ${r.title}`
      );
    });
  }

  // --- Compose final prompt ---
  const sections = [
    `You are analyzing the following PCAP capture. Ground ALL your responses in this data.`,
    '',
    '=== ANALYSIS OVERVIEW ===',
    ...overviewLines,
  ];

  if (sessionLines.length > 0) {
    sections.push('', '=== SESSION TELEMETRY ===', ...sessionLines);
  }

  if (findingLines.length > 0) {
    sections.push('', '=== SECURITY FINDINGS ===', ...findingLines);
  }

  if (recLines.length > 0) {
    sections.push('', '=== RECOMMENDATIONS ===', ...recLines);
  }

  sections.push(
    '',
    '=== INSTRUCTIONS ===',
    'Answer the user\'s question using the telemetry above.',
    'Cite specific sessions, findings, or CWE/RFC references where relevant.',
    'Provide actionable configuration directives (Postfix main.cf, Dovecot dovecot.conf) when applicable.',
    'Use markdown formatting for clarity.'
  );

  return sections.join('\n');
}

module.exports = {
  generateSuggestedQuestions,
  buildSystemPrompt,
  QUESTION_RULES,
  EXECUTIVE_SUMMARY_QUESTION,
};
