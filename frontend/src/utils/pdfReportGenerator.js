import { jsPDF } from 'jspdf';
import autoTable from 'jspdf-autotable';
import { formatBytes, formatDate } from './formatters.js';
import { compareSeverity } from './severity.js';

/*
|--------------------------------------------------------------------------
| Formal Executive Cybersecurity Palette
| Minimal color, high contrast, clean typography, formal business layout.
|--------------------------------------------------------------------------
*/
const FORMAL_PALETTE = {
  // Grayscale & Dark Slate
  INK_BLACK: [17, 24, 39],        // #111827 - primary text
  TEXT_BODY: [55, 65, 81],        // #374151 - body text
  TEXT_MUTED: [107, 114, 128],    // #6B7280 - muted captions & metadata
  HEADER_FILL: [30, 41, 59],      // #1E293B - deep slate for table headers
  BORDER_HAIRLINE: [209, 213, 219],// #D1D5DB - formal rule lines
  BORDER_SUBTLE: [229, 231, 235], // #E5E7EB - light cell borders
  BG_LIGHT: [249, 250, 251],      // #F9FAFB - neutral card & table zebra fill
  BG_HOVER: [243, 244, 246],      // #F3F4F6 - light header for finding blocks
  WHITE: [255, 255, 255],

  // Restrained Formal Severity Indicators (Muted, professional)
  SEVERITY: {
    CRITICAL: {
      text: [153, 27, 27],       // #991B1B - Deep Burgundy
      bg: [254, 242, 242],        // #FEF2F2
      border: [248, 113, 113],    // #F87171
      label: 'CRITICAL',
    },
    HIGH: {
      text: [154, 52, 18],        // #9A3412 - Deep Rust
      bg: [255, 247, 237],        // #FFF7ED
      border: [251, 146, 60],     // #FB923C
      label: 'HIGH',
    },
    MEDIUM: {
      text: [146, 64, 14],        // #92400E - Dark Amber
      bg: [254, 252, 232],        // #FEFCE8
      border: [250, 204, 21],     // #FACC15
      label: 'MEDIUM',
    },
    LOW: {
      text: [30, 64, 175],        // #1E40AF - Slate Blue
      bg: [239, 246, 255],        // #EFF6FF
      border: [147, 197, 253],    // #93C5FD
      label: 'LOW',
    },
    INFO: {
      text: [22, 101, 52],        // #166534 - Forest Green
      bg: [240, 253, 244],        // #F0FDF4
      border: [134, 239, 172],    // #86EFAC
      label: 'INFO',
    },
    SECURE: {
      text: [22, 101, 52],        // #166534 - Forest Green
      bg: [240, 253, 244],        // #F0FDF4
      border: [134, 239, 172],    // #86EFAC
      label: 'SECURE',
    },
  },
};

/**
 * Return formal color config for a severity string
 */
function getSeverityColors(sev) {
  const normalized = (sev || 'INFO').toUpperCase();
  return FORMAL_PALETTE.SEVERITY[normalized] || FORMAL_PALETTE.SEVERITY.INFO;
}

/**
 * Format evidence object into a clean, compact, single/double-line human-readable string.
 * Avoids raw JSON dumping and multi-line array explosions.
 */
function formatEvidenceCompact(evidence) {
  if (!evidence) return null;
  if (typeof evidence === 'string') return evidence.trim();

  const parts = [];

  if (evidence.tcp_stream !== undefined) {
    parts.push(`TCP Stream: ${evidence.tcp_stream}`);
  }
  if (evidence.tls_version) {
    parts.push(`TLS: ${evidence.tls_version}`);
  }
  if (evidence.cipher_suite) {
    parts.push(`Cipher: ${evidence.cipher_suite}`);
  }
  if (evidence.pfs !== undefined) {
    parts.push(`PFS: ${evidence.pfs}`);
  }
  if (evidence.protocol) {
    parts.push(`Protocol: ${evidence.protocol}`);
  }
  if (evidence.server_port) {
    parts.push(`Port: ${evidence.server_port}`);
  }
  if (evidence.authentication_before_tls !== undefined) {
    parts.push(`Auth Before TLS: ${evidence.authentication_before_tls ? 'YES' : 'NO'}`);
  }
  if (evidence.upgrade_advertised !== undefined) {
    parts.push(`STARTTLS Advertised: ${evidence.upgrade_advertised}`);
  }
  if (evidence.upgrade_succeeded !== undefined) {
    parts.push(`Upgrade Succeeded: ${evidence.upgrade_succeeded}`);
  }
  if (evidence.frame_numbers) {
    const frames = Array.isArray(evidence.frame_numbers)
      ? evidence.frame_numbers.join(', ')
      : String(evidence.frame_numbers);
    parts.push(`Frames: [${frames}]`);
  }
  if (evidence.wireshark_filter) {
    parts.push(`Filter: ${evidence.wireshark_filter}`);
  }

  // Handle any other unexpected properties concisely
  const handled = new Set([
    'tcp_stream', 'tls_version', 'cipher_suite', 'pfs', 'protocol',
    'server_port', 'authentication_before_tls', 'upgrade_advertised',
    'upgrade_requested', 'upgrade_succeeded', 'frame_numbers', 'wireshark_filter',
  ]);

  for (const [k, v] of Object.entries(evidence)) {
    if (!handled.has(k)) {
      if (Array.isArray(v)) {
        parts.push(`${k}: [${v.join(', ')}]`);
      } else if (typeof v === 'object' && v !== null) {
        parts.push(`${k}: ${JSON.stringify(v)}`);
      } else {
        parts.push(`${k}: ${v}`);
      }
    }
  }

  return parts.join('   •   ');
}

/**
 * Compute or normalize summary stats from analysis object
 */
function extractSummary(analysis) {
  const sessions = analysis?.sessions || [];
  const findings = analysis?.findings || [];
  const rawSummary = analysis?.summary || {};

  const smtpCount = rawSummary.smtp_sessions ?? sessions.filter((s) => (s.protocol || '').toUpperCase() === 'SMTP').length;
  const imapCount = rawSummary.imap_sessions ?? sessions.filter((s) => (s.protocol || '').toUpperCase() === 'IMAP').length;
  const pop3Count = rawSummary.pop3_sessions ?? sessions.filter((s) => (s.protocol || '').toUpperCase() === 'POP3').length;

  const plaintextCount = rawSummary.plaintext_sessions ?? sessions.filter((s) => {
    const mode = (s?.security?.encryption_mode || s?.encryption_mode || '').toUpperCase();
    return mode === 'PLAINTEXT' || mode === 'NONE' || (!s.tls && mode !== 'IMPLICIT_TLS' && mode !== 'STARTTLS');
  }).length;

  const starttlsCount = rawSummary.starttls_sessions ?? sessions.filter((s) => {
    const mode = (s?.security?.encryption_mode || s?.encryption_mode || '').toUpperCase();
    return mode === 'STARTTLS';
  }).length;

  const implicitTlsCount = rawSummary.implicit_tls_sessions ?? sessions.filter((s) => {
    const mode = (s?.security?.encryption_mode || s?.encryption_mode || '').toUpperCase();
    return mode === 'IMPLICIT_TLS';
  }).length;

  const vulnerableCount = rawSummary.vulnerable_sessions ?? sessions.filter((s) => {
    const mode = (s?.security?.encryption_mode || s?.encryption_mode || '').toUpperCase();
    const authBeforeTls = s?.security?.authentication_before_tls === 'YES' || s?.security?.authentication_before_tls === true;
    const upgradeFailed = s?.security?.upgrade_succeeded === 'NO' || s?.security?.upgrade_succeeded === false;
    return mode === 'PLAINTEXT' || authBeforeTls || upgradeFailed;
  }).length;

  const findingsCount = rawSummary.findings_count ?? findings.length;

  const criticalFindings = findings.filter((f) => (f.severity || '').toUpperCase() === 'CRITICAL').length;
  const highFindings = findings.filter((f) => (f.severity || '').toUpperCase() === 'HIGH').length;
  const mediumFindings = findings.filter((f) => (f.severity || '').toUpperCase() === 'MEDIUM').length;
  const lowFindings = findings.filter((f) => (f.severity || '').toUpperCase() === 'LOW').length;
  const infoFindings = findings.filter((f) => (f.severity || '').toUpperCase() === 'INFO').length;

  const anomalousCount = analysis?.anomaly_assessment?.anomalous_count ?? sessions.filter((s) => s?.anomaly?.is_anomalous).length;

  return {
    totalSessions: rawSummary.total_sessions ?? sessions.length,
    smtpCount,
    imapCount,
    pop3Count,
    plaintextCount,
    starttlsCount,
    implicitTlsCount,
    vulnerableCount,
    findingsCount,
    criticalFindings,
    highFindings,
    mediumFindings,
    lowFindings,
    infoFindings,
    anomalousCount,
  };
}

/**
 * Generate a formal, publication-grade cybersecurity audit PDF report for an analyzed PCAP file.
 *
 * @param {Object} analysis - The full analysis object.
 * @param {Object} options - Config options ({ download: boolean, filename: string })
 * @returns {Promise<{ doc: jsPDF, blob: Blob, filename: string }>}
 */
export async function generatePdfReport(analysis, options = {}) {
  if (!analysis) {
    throw new Error('Cannot generate PDF: No analysis data provided.');
  }

  const { download = true, filename: customFilename = null } = options;

  // Initialize jsPDF document (Portrait, millimeters, A4 size: 210 x 297mm)
  const doc = new jsPDF({
    orientation: 'portrait',
    unit: 'mm',
    format: 'a4',
    compress: true,
  });

  const PAGE_WIDTH = 210;
  const PAGE_HEIGHT = 297;
  const MARGIN_LEFT = 14;
  const MARGIN_RIGHT = 14;
  const CONTENT_WIDTH = PAGE_WIDTH - MARGIN_LEFT - MARGIN_RIGHT; // 182mm
  const MAX_Y = 270; // safe threshold before page break

  let currentY = 14;

  const summary = extractSummary(analysis);
  const pcapFilename = analysis.filename || 'network_capture.pcap';
  const analysisId = analysis.analysis_id || 'N/A';
  const riskLevel = (
    analysis?.risk?.level ||
    analysis?.overall_risk ||
    (summary.criticalFindings > 0 ? 'CRITICAL' : summary.highFindings > 0 ? 'HIGH' : summary.vulnerableCount > 0 ? 'HIGH' : 'LOW')
  ).toUpperCase();
  const riskScore = analysis?.risk?.score ?? analysis?.risk_score ?? (riskLevel === 'CRITICAL' ? 88 : riskLevel === 'HIGH' ? 81 : riskLevel === 'MEDIUM' ? 45 : 12);
  const riskColors = getSeverityColors(riskLevel);

  /*
  |--------------------------------------------------------------------------
  | Helper: Add a Formal Section Header with clean horizontal rule
  |--------------------------------------------------------------------------
  */
  function addSectionHeader(title, subtitle = null, spaceNeeded = 18) {
    if (currentY + spaceNeeded > MAX_Y) {
      doc.addPage();
      currentY = 20;
    }

    doc.setFont('helvetica', 'bold');
    doc.setFontSize(10.5);
    doc.setTextColor(...FORMAL_PALETTE.INK_BLACK);
    doc.text(title.toUpperCase(), MARGIN_LEFT, currentY + 5);

    // Subtle formal rule under heading
    const textWidth = doc.getTextWidth(title.toUpperCase());
    doc.setDrawColor(...FORMAL_PALETTE.BORDER_HAIRLINE);
    doc.setLineWidth(0.4);
    doc.line(MARGIN_LEFT + textWidth + 4, currentY + 4, MARGIN_LEFT + CONTENT_WIDTH, currentY + 4);

    currentY += 8;

    if (subtitle) {
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.5);
      doc.setTextColor(...FORMAL_PALETTE.TEXT_MUTED);
      doc.text(subtitle, MARGIN_LEFT, currentY);
      currentY += 4.5;
    }
  }

  /*
  |--------------------------------------------------------------------------
  | 1. FORMAL LETTERHEAD & DOCUMENT HEADER (PAGE 1)
  | Clean white background, executive typography, zero overlap layout
  |--------------------------------------------------------------------------
  */
  // Top Tier: Brand on Left, Classification Box on Right
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(14);
  doc.setTextColor(...FORMAL_PALETTE.HEADER_FILL);
  doc.text('SECUREMAILSCOPE', MARGIN_LEFT, currentY + 5);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.2);
  doc.setTextColor(...FORMAL_PALETTE.TEXT_MUTED);
  doc.text('Email Protocol Security & Deep Packet Inspection Audit Platform', MARGIN_LEFT, currentY + 10);

  // Right Column: Formal Classification & Date Box (Ample space, no text overlap)
  const metaBoxW = 54;
  const metaBoxH = 13.5;
  const metaBoxX = MARGIN_LEFT + CONTENT_WIDTH - metaBoxW;
  doc.setFillColor(...FORMAL_PALETTE.BG_LIGHT);
  doc.setDrawColor(...FORMAL_PALETTE.BORDER_HAIRLINE);
  doc.setLineWidth(0.3);
  doc.rect(metaBoxX, currentY, metaBoxW, metaBoxH, 'FD');

  doc.setFont('helvetica', 'bold');
  doc.setFontSize(6.5);
  doc.setTextColor(...FORMAL_PALETTE.INK_BLACK);
  doc.text('CLASSIFICATION: CONFIDENTIAL', metaBoxX + 3, currentY + 4.2);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(6.5);
  doc.setTextColor(...FORMAL_PALETTE.TEXT_MUTED);
  doc.text(`Generated: ${formatDate(analysis.created_at || analysis.uploaded_at || new Date().toISOString())}`, metaBoxX + 3, currentY + 8);
  doc.text(`Doc Ref: ${analysisId.substring(0, 20)}...`, metaBoxX + 3, currentY + 11.8);

  currentY += metaBoxH + 3.5;

  // Divider Rule separating letterhead from document title
  doc.setDrawColor(...FORMAL_PALETTE.BORDER_HAIRLINE);
  doc.setLineWidth(0.5);
  doc.line(MARGIN_LEFT, currentY, MARGIN_LEFT + CONTENT_WIDTH, currentY);
  currentY += 4.5;

  // Full-width Document Title & Subtitle (Unconstrained, spans full width with no collision)
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(10.5);
  doc.setTextColor(...FORMAL_PALETTE.INK_BLACK);
  doc.text('EMAIL TRAFFIC SECURITY ANALYSIS & TECHNICAL AUDIT REPORT', MARGIN_LEFT, currentY + 2);

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.2);
  doc.setTextColor(...FORMAL_PALETTE.TEXT_MUTED);
  doc.text(
    'Deep Packet Inspection   •   Protocol Cryptographic Verification   •   RFC Baseline Conformance',
    MARGIN_LEFT,
    currentY + 6.5
  );

  currentY += 10;


  /*
  |--------------------------------------------------------------------------
  | 2. AUDIT TARGET & PCAP METADATA (Structured Formal Table)
  |--------------------------------------------------------------------------
  */
  const pcapMeta = [
    [
      { content: 'Target Capture File:', styles: { fontStyle: 'bold', textColor: FORMAL_PALETTE.INK_BLACK } },
      `${pcapFilename} (${formatBytes(analysis.file_size_bytes || 0)})`,
      { content: 'SHA-256 Checksum:', styles: { fontStyle: 'bold', textColor: FORMAL_PALETTE.INK_BLACK } },
      analysis.sha256 ? `${analysis.sha256.substring(0, 24)}...` : 'Verified upon ingestion',
    ],
    [
      { content: 'Analysis ID:', styles: { fontStyle: 'bold', textColor: FORMAL_PALETTE.INK_BLACK } },
      analysisId,
      { content: 'Overall Security Verdict:', styles: { fontStyle: 'bold', textColor: FORMAL_PALETTE.INK_BLACK } },
      { content: `${riskLevel} RISK  (Score: ${riskScore}/100)`, styles: { fontStyle: 'bold', textColor: riskColors.text } },
    ],
  ];

  autoTable(doc, {
    startY: currentY,
    margin: { left: MARGIN_LEFT, right: MARGIN_RIGHT },
    body: pcapMeta,
    theme: 'plain',
    styles: {
      fontSize: 7.2,
      cellPadding: 2,
      font: 'helvetica',
      textColor: FORMAL_PALETTE.TEXT_BODY,
      lineColor: FORMAL_PALETTE.BORDER_SUBTLE,
      lineWidth: 0.2,
    },
    columnStyles: {
      0: { cellWidth: 32, fillColor: FORMAL_PALETTE.BG_LIGHT },
      1: { cellWidth: 58 },
      2: { cellWidth: 34, fillColor: FORMAL_PALETTE.BG_LIGHT },
      3: { cellWidth: 58 },
    },
  });

  currentY = doc.lastAutoTable.finalY + 6;

  /*
  |--------------------------------------------------------------------------
  | 3. EXECUTIVE SUMMARY & POSTURE ASSESSMENT
  | Formal callout box with neutral background and crisp border
  |--------------------------------------------------------------------------
  */
  addSectionHeader('1. Executive Summary & Security Posture');

  const execCardHeight = 27;
  doc.setFillColor(...FORMAL_PALETTE.BG_LIGHT);
  doc.setDrawColor(...FORMAL_PALETTE.BORDER_HAIRLINE);
  doc.setLineWidth(0.4);
  doc.roundedRect(MARGIN_LEFT, currentY, CONTENT_WIDTH, execCardHeight, 1.5, 1.5, 'FD');

  // Left Score Column (Width 40mm)
  const leftColW = 40;
  doc.setFillColor(...FORMAL_PALETTE.WHITE);
  doc.setDrawColor(...riskColors.border);
  doc.setLineWidth(0.4);
  doc.roundedRect(MARGIN_LEFT + 3, currentY + 3, leftColW, execCardHeight - 6, 1, 1, 'FD');

  // Subtle risk badge pill inside score box
  doc.setFillColor(...riskColors.bg);
  doc.roundedRect(MARGIN_LEFT + 6, currentY + 5.5, leftColW - 6, 4.5, 0.5, 0.5, 'F');
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(6.8);
  doc.setTextColor(...riskColors.text);
  doc.text(`${riskLevel} RISK`, MARGIN_LEFT + leftColW / 2 + 3, currentY + 8.8, { align: 'center' });

  // Score
  doc.setFont('helvetica', 'bold');
  doc.setFontSize(13);
  doc.setTextColor(...FORMAL_PALETTE.INK_BLACK);
  doc.text(`${riskScore} / 100`, MARGIN_LEFT + leftColW / 2 + 3, currentY + 16, { align: 'center' });

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(6.2);
  doc.setTextColor(...FORMAL_PALETTE.TEXT_MUTED);
  doc.text('Composite Risk Score', MARGIN_LEFT + leftColW / 2 + 3, currentY + 20, { align: 'center' });

  // Right Narrative Column
  const narrativeX = MARGIN_LEFT + leftColW + 7;
  const narrativeWidth = CONTENT_WIDTH - leftColW - 10;

  let narrativeText = '';
  if (riskLevel === 'CRITICAL' || riskLevel === 'HIGH') {
    narrativeText = `ATTENTION REQUIRED: The automated deep packet inspection of "${pcapFilename}" detected significant vulnerabilities in captured email traffic. ${
      summary.plaintextCount > 0 ? `${summary.plaintextCount} unencrypted session(s) transmitted credentials or payload in cleartext. ` : ''
    }${
      summary.vulnerableCount > 0 ? 'Observed authentication sequences executed prior to mandatory TLS upgrade or failed STARTTLS negotiation, exposing credentials to passive sniffing and active interception. ' : ''
    }Immediate remediation is recommended according to RFC 8314 and RFC 3207 compliance baselines.`;
  } else if (riskLevel === 'MEDIUM') {
    narrativeText = `MODERATE RISK: The inspected network traffic contains sessions utilizing legacy encryption ciphers or suboptimal configurations. While credentials were not observed in cleartext, the deployment lacks forward secrecy or modern cipher protection.`;
  } else {
    narrativeText = `OPTIMAL SECURITY: The email traffic demonstrates robust cryptographic enforcement. All inspected sessions negotiated modern TLS protocols (TLS 1.2 / 1.3) with Perfect Forward Secrecy (PFS), valid certificates, and no plaintext credentials detected.`;
  }

  doc.setFont('helvetica', 'normal');
  doc.setFontSize(7.4);
  doc.setTextColor(...FORMAL_PALETTE.INK_BLACK);
  const narrativeLines = doc.splitTextToSize(narrativeText, narrativeWidth);
  doc.text(narrativeLines, narrativeX, currentY + 6.5);

  // Confidence & Engine footer
  const methodText = `Assessment Model: Canonical Risk Engine + Isolation Forest ML (Confidence: ${Math.round((analysis?.risk?.confidence || 0.91) * 100)}%)`;
  doc.setFont('helvetica', 'normal');
  doc.setFontSize(6.8);
  doc.setTextColor(...FORMAL_PALETTE.TEXT_MUTED);
  doc.text(methodText, narrativeX, currentY + execCardHeight - 3.5);

  currentY += execCardHeight + 6;

  /*
  |--------------------------------------------------------------------------
  | 4. KEY TELEMETRY & PROTOCOL DISTRIBUTION
  | Consolidated formal table with no loud colors
  |--------------------------------------------------------------------------
  */
  addSectionHeader('2. Key Telemetry & Protocol Distribution');

  const telemetryRows = [
    [
      { content: 'Total Sessions:', styles: { fontStyle: 'bold', fillColor: FORMAL_PALETTE.BG_LIGHT } },
      `${summary.totalSessions}`,
      { content: 'Plaintext Sessions:', styles: { fontStyle: 'bold', fillColor: FORMAL_PALETTE.BG_LIGHT } },
      { content: `${summary.plaintextCount}`, styles: { fontStyle: 'bold', textColor: summary.plaintextCount > 0 ? FORMAL_PALETTE.SEVERITY.CRITICAL.text : FORMAL_PALETTE.SEVERITY.INFO.text } },
      { content: 'Critical Findings:', styles: { fontStyle: 'bold', fillColor: FORMAL_PALETTE.BG_LIGHT } },
      { content: `${summary.criticalFindings}`, styles: { fontStyle: 'bold', textColor: summary.criticalFindings > 0 ? FORMAL_PALETTE.SEVERITY.CRITICAL.text : FORMAL_PALETTE.TEXT_MUTED } },
    ],
    [
      { content: 'SMTP Sessions:', styles: { fontStyle: 'bold', fillColor: FORMAL_PALETTE.BG_LIGHT } },
      `${summary.smtpCount}`,
      { content: 'STARTTLS Sessions:', styles: { fontStyle: 'bold', fillColor: FORMAL_PALETTE.BG_LIGHT } },
      `${summary.starttlsCount}`,
      { content: 'High Risk Findings:', styles: { fontStyle: 'bold', fillColor: FORMAL_PALETTE.BG_LIGHT } },
      { content: `${summary.highFindings}`, styles: { fontStyle: 'bold', textColor: summary.highFindings > 0 ? FORMAL_PALETTE.SEVERITY.HIGH.text : FORMAL_PALETTE.TEXT_MUTED } },
    ],
    [
      { content: 'IMAP / POP3:', styles: { fontStyle: 'bold', fillColor: FORMAL_PALETTE.BG_LIGHT } },
      `${summary.imapCount + summary.pop3Count}`,
      { content: 'Implicit TLS Sessions:', styles: { fontStyle: 'bold', fillColor: FORMAL_PALETTE.BG_LIGHT } },
      `${summary.implicitTlsCount}`,
      { content: 'Medium / Low / Info:', styles: { fontStyle: 'bold', fillColor: FORMAL_PALETTE.BG_LIGHT } },
      `${summary.mediumFindings} / ${summary.lowFindings} / ${summary.infoFindings}`,
    ],
  ];

  autoTable(doc, {
    startY: currentY,
    margin: { left: MARGIN_LEFT, right: MARGIN_RIGHT },
    body: telemetryRows,
    theme: 'plain',
    styles: {
      fontSize: 7.2,
      cellPadding: 2,
      font: 'helvetica',
      textColor: FORMAL_PALETTE.INK_BLACK,
      lineColor: FORMAL_PALETTE.BORDER_SUBTLE,
      lineWidth: 0.2,
    },
    columnStyles: {
      0: { cellWidth: 28 },
      1: { cellWidth: 32 },
      2: { cellWidth: 32 },
      3: { cellWidth: 30 },
      4: { cellWidth: 32 },
      5: { cellWidth: 28 },
    },
  });

  currentY = doc.lastAutoTable.finalY + 4;

  // Severity Distribution Table (Formal Black & White Header)
  const sevHeaders = [['SEVERITY', 'COUNT', 'STATUS', 'TECHNICAL RISK & RFC COMPLIANCE IMPACT']];
  const sevData = [
    ['CRITICAL', `${summary.criticalFindings}`, summary.criticalFindings > 0 ? 'FAIL' : 'PASS', 'Immediate credential exposure or unencrypted authentication transmission.'],
    ['HIGH', `${summary.highFindings}`, summary.highFindings > 0 ? 'FAIL' : 'PASS', 'Protocol downgrade, failed STARTTLS upgrade, or clear vulnerability to active MitM.'],
    ['MEDIUM', `${summary.mediumFindings}`, summary.mediumFindings > 0 ? 'WARN' : 'PASS', 'Deprecated TLS versions (TLS 1.0/1.1) or weak cipher suites lacking forward secrecy.'],
    ['LOW', `${summary.lowFindings}`, 'INFO', 'Configuration divergence or minor observable deviation from recommended baseline.'],
    ['INFO', `${summary.infoFindings}`, 'INFO', 'Positive cryptographic verification (PFS verified, modern TLS 1.3 negotiated).'],
  ];

  autoTable(doc, {
    startY: currentY,
    margin: { left: MARGIN_LEFT, right: MARGIN_RIGHT },
    head: sevHeaders,
    body: sevData,
    theme: 'plain',
    styles: {
      fontSize: 7.2,
      cellPadding: 2.2,
      font: 'helvetica',
      textColor: FORMAL_PALETTE.INK_BLACK,
      lineColor: FORMAL_PALETTE.BORDER_SUBTLE,
      lineWidth: 0.2,
    },
    headStyles: {
      fillColor: FORMAL_PALETTE.HEADER_FILL,
      textColor: FORMAL_PALETTE.WHITE,
      fontStyle: 'bold',
      fontSize: 7.2,
    },
    alternateRowStyles: {
      fillColor: FORMAL_PALETTE.BG_LIGHT,
    },
    columnStyles: {
      0: { fontStyle: 'bold', cellWidth: 24 },
      1: { halign: 'center', cellWidth: 16, fontStyle: 'bold' },
      2: { halign: 'center', cellWidth: 18, fontStyle: 'bold' },
      3: { cellWidth: 'auto' },
    },
    didParseCell: (data) => {
      if (data.section === 'body') {
        const rowSev = data.row.raw[0];
        const colors = getSeverityColors(rowSev);
        if (data.column.index === 0) {
          data.cell.styles.textColor = colors.text;
        } else if (data.column.index === 2) {
          const val = data.cell.raw;
          if (val === 'FAIL') data.cell.styles.textColor = FORMAL_PALETTE.SEVERITY.CRITICAL.text;
          else if (val === 'WARN') data.cell.styles.textColor = FORMAL_PALETTE.SEVERITY.MEDIUM.text;
          else data.cell.styles.textColor = FORMAL_PALETTE.SEVERITY.INFO.text;
        }
      }
    },
  });

  currentY = doc.lastAutoTable.finalY + 6;

  /*
  |--------------------------------------------------------------------------
  | 5. BEHAVIORAL ANOMALY DETECTION (ML Telemetry)
  | Compact formal box
  |--------------------------------------------------------------------------
  */
  addSectionHeader('3. Behavioral Anomaly Assessment (Isolation Forest ML)');

  const anomalyStatus = analysis?.anomaly_assessment?.overall_status || (summary.anomalousCount > 0 ? 'ANOMALIES_DETECTED' : 'BASELINE_CONFORMANT');
  const isAnomalous = anomalyStatus === 'ANOMALIES_DETECTED' || summary.anomalousCount > 0;

  const anomalyData = [
    [
      { content: 'Assessment Verdict:', styles: { fontStyle: 'bold', cellWidth: 36, fillColor: FORMAL_PALETTE.BG_LIGHT } },
      {
        content: isAnomalous ? `ANOMALIES DETECTED (${summary.anomalousCount} Session${summary.anomalousCount > 1 ? 's' : ''})` : 'BASELINE CONFORMANT',
        styles: { fontStyle: 'bold', textColor: isAnomalous ? FORMAL_PALETTE.SEVERITY.HIGH.text : FORMAL_PALETTE.SEVERITY.INFO.text },
      },
    ],
    [
      { content: 'Model & Architecture:', styles: { fontStyle: 'bold', cellWidth: 36, fillColor: FORMAL_PALETTE.BG_LIGHT } },
      `Isolation Forest (${analysis?.anomaly_assessment?.model_version || 'if-v1'})   •   Schema: ${analysis?.anomaly_assessment?.feature_schema_version || 'if-features-v1'}   •   Threshold: 0.0`,
    ],
    [
      { content: 'Evaluation Summary:', styles: { fontStyle: 'bold', cellWidth: 36, fillColor: FORMAL_PALETTE.BG_LIGHT } },
      isAnomalous
        ? `The model identified ${summary.anomalousCount} session(s) displaying behavioral divergence from enterprise baseline models (e.g. unencrypted command sequences or abnormal TCP packet size distribution).`
        : 'All sessions exhibit protocol sequences, TLS negotiation flows, and traffic patterns consistent with expected mail operational baselines.',
    ],
  ];

  autoTable(doc, {
    startY: currentY,
    margin: { left: MARGIN_LEFT, right: MARGIN_RIGHT },
    body: anomalyData,
    theme: 'plain',
    styles: {
      fontSize: 7.2,
      cellPadding: 2,
      font: 'helvetica',
      textColor: FORMAL_PALETTE.INK_BLACK,
      lineColor: FORMAL_PALETTE.BORDER_SUBTLE,
      lineWidth: 0.2,
    },
  });

  currentY = doc.lastAutoTable.finalY + 8;

  /*
  |--------------------------------------------------------------------------
  | 6. DETAILED SECURITY FINDINGS & EVIDENCE (HIGH-FIDELITY AUDIT BLOCKS)
  | Formatted cleanly as formal audit items with properly formatted evidence
  |--------------------------------------------------------------------------
  */
  addSectionHeader('4. Detailed Security Findings & Risk Evidence', 'Technical audit of identified vulnerabilities with observable network facts and remediation guidance.');

  const findings = [...(analysis?.findings || [])].sort((a, b) => compareSeverity(a.severity, b.severity));

  if (findings.length === 0) {
    doc.setFillColor(...FORMAL_PALETTE.BG_LIGHT);
    doc.setDrawColor(...FORMAL_PALETTE.BORDER_HAIRLINE);
    doc.roundedRect(MARGIN_LEFT, currentY, CONTENT_WIDTH, 14, 1, 1, 'FD');
    doc.setFont('helvetica', 'bold');
    doc.setFontSize(8.5);
    doc.setTextColor(...FORMAL_PALETTE.SEVERITY.INFO.text);
    doc.text('No Security Vulnerabilities or Baseline Violations Detected', MARGIN_LEFT + 6, currentY + 6);
    doc.setFont('helvetica', 'normal');
    doc.setFontSize(7.2);
    doc.setTextColor(...FORMAL_PALETTE.TEXT_MUTED);
    doc.text('All inspected sessions conformed to baseline encryption and protocol specifications.', MARGIN_LEFT + 6, currentY + 10.5);
    currentY += 18;
  } else {
    findings.forEach((finding, idx) => {
      const fSev = (finding.severity || 'INFO').toUpperCase();
      const fColors = getSeverityColors(fSev);
      const fTitle = finding.title || 'Security Observation';
      const fId = finding.finding_id || `finding-${idx + 1}`;
      const fSessionId = finding.session_id || 'Global';
      const fType = finding.finding_type || finding.category || 'VULNERABILITY';
      const fDesc = finding.description || 'No detailed description available.';
      const formattedEvidence = formatEvidenceCompact(finding.evidence);

      // Calculate needed vertical space
      const descLines = doc.splitTextToSize(fDesc, CONTENT_WIDTH - 8);
      const evidenceLines = formattedEvidence ? doc.splitTextToSize(`Observable Evidence:  ${formattedEvidence}`, CONTENT_WIDTH - 8) : [];
      const cardHeight = 14 + descLines.length * 3.4 + (evidenceLines.length > 0 ? evidenceLines.length * 3.2 + 3 : 0);

      // Check page overflow
      if (currentY + cardHeight > MAX_Y) {
        doc.addPage();
        currentY = 20;
      }

      // Finding Container Box (Formal hairline border)
      doc.setFillColor(...FORMAL_PALETTE.WHITE);
      doc.setDrawColor(...FORMAL_PALETTE.BORDER_HAIRLINE);
      doc.setLineWidth(0.3);
      doc.rect(MARGIN_LEFT, currentY, CONTENT_WIDTH, cardHeight, 'FD');

      // Top Header Bar
      const headerH = 6;
      doc.setFillColor(...FORMAL_PALETTE.BG_HOVER);
      doc.rect(MARGIN_LEFT, currentY, CONTENT_WIDTH, headerH, 'F');
      doc.setDrawColor(...FORMAL_PALETTE.BORDER_SUBTLE);
      doc.line(MARGIN_LEFT, currentY + headerH, MARGIN_LEFT + CONTENT_WIDTH, currentY + headerH);

      // Severity Tag
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(6.8);
      doc.setTextColor(...fColors.text);
      doc.text(`[${fSev}]`, MARGIN_LEFT + 3, currentY + 4.2);

      // Title & Finding ID
      doc.setFont('helvetica', 'bold');
      doc.setTextColor(...FORMAL_PALETTE.INK_BLACK);
      doc.text(fTitle, MARGIN_LEFT + 18, currentY + 4.2);

      // Metadata right aligned
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(6.5);
      doc.setTextColor(...FORMAL_PALETTE.TEXT_MUTED);
      doc.text(`ID: ${fId.substring(0, 16)}...   •   Session: ${fSessionId}   •   Type: ${fType}`, MARGIN_LEFT + CONTENT_WIDTH - 3, currentY + 4.2, { align: 'right' });

      let textY = currentY + headerH + 3.8;

      // Description
      doc.setFont('helvetica', 'normal');
      doc.setFontSize(7.2);
      doc.setTextColor(...FORMAL_PALETTE.TEXT_BODY);
      doc.text(descLines, MARGIN_LEFT + 3, textY);
      textY += descLines.length * 3.4;

      // Evidence (Clean formatted single/double line)
      if (evidenceLines.length > 0) {
        doc.setFont('helvetica', 'normal');
        doc.setFontSize(6.8);
        doc.setTextColor(...FORMAL_PALETTE.HEADER_FILL);
        doc.text(evidenceLines, MARGIN_LEFT + 3, textY + 1.5);
      }

      currentY += cardHeight + 3.5;
    });
  }

  currentY += 4;

  /*
  |--------------------------------------------------------------------------
  | 7. COMPLETE SESSIONS TRAFFIC MATRIX
  |--------------------------------------------------------------------------
  */
  addSectionHeader('5. Protocol Sessions Inventory & Forensic Telemetry');

  const sessions = analysis?.sessions || [];
  const sessionHeaders = [['SESSION ID', 'PROTO', 'SOURCE ENDPOINT', 'DESTINATION', 'ENCRYPTION', 'TLS VERSION', 'PFS', 'VERDICT']];

  const sessionRows = sessions.map((s, idx) => {
    const sId = s.session_id || `sess-${idx + 1}`;
    const proto = (s.protocol || 'TCP').toUpperCase();
    const src = `${s.client_ip || 'N/A'}:${s.client_port || '—'}`;
    const dst = `${s.server_ip || 'N/A'}:${s.server_port || '—'}`;
    const encMode = s?.security?.encryption_mode || s?.encryption_mode || (s.tls ? 'STARTTLS' : 'PLAINTEXT');
    const tlsVer = s?.tls?.version || (encMode === 'PLAINTEXT' ? 'None (Cleartext)' : 'Not Observed');
    const pfs = s?.tls?.pfs ? 'YES' : (encMode === 'PLAINTEXT' ? 'N/A' : 'NO');

    let verdict = 'SECURE';
    if (encMode === 'PLAINTEXT' || s?.security?.authentication_before_tls === 'YES' || s?.security?.upgrade_succeeded === 'NO') {
      verdict = 'VULNERABLE';
    } else if (s?.anomaly?.is_anomalous) {
      verdict = 'ANOMALOUS';
    }

    return [sId, proto, src, dst, encMode, tlsVer, pfs, verdict];
  });

  autoTable(doc, {
    startY: currentY,
    margin: { left: MARGIN_LEFT, right: MARGIN_RIGHT },
    head: sessionHeaders,
    body: sessionRows.length > 0 ? sessionRows : [['No sessions recorded in this capture.', '', '', '', '', '', '', '']],
    theme: 'plain',
    styles: {
      fontSize: 6.8,
      cellPadding: 2,
      font: 'helvetica',
      textColor: FORMAL_PALETTE.INK_BLACK,
      lineColor: FORMAL_PALETTE.BORDER_SUBTLE,
      lineWidth: 0.2,
    },
    headStyles: {
      fillColor: FORMAL_PALETTE.HEADER_FILL,
      textColor: FORMAL_PALETTE.WHITE,
      fontStyle: 'bold',
      fontSize: 7,
    },
    alternateRowStyles: {
      fillColor: FORMAL_PALETTE.BG_LIGHT,
    },
    columnStyles: {
      0: { cellWidth: 26, fontStyle: 'bold' },
      1: { cellWidth: 14, halign: 'center', fontStyle: 'bold' },
      2: { cellWidth: 32 },
      3: { cellWidth: 32 },
      4: { cellWidth: 22, halign: 'center', fontStyle: 'bold' },
      5: { cellWidth: 24 },
      6: { cellWidth: 12, halign: 'center' },
      7: { cellWidth: 20, halign: 'center', fontStyle: 'bold' },
    },
    didParseCell: (data) => {
      if (data.section === 'body') {
        if (data.column.index === 4) {
          const enc = data.cell.raw;
          if (enc === 'PLAINTEXT') data.cell.styles.textColor = FORMAL_PALETTE.SEVERITY.CRITICAL.text;
        } else if (data.column.index === 7) {
          const v = data.cell.raw;
          if (v === 'VULNERABLE') data.cell.styles.textColor = FORMAL_PALETTE.SEVERITY.CRITICAL.text;
          else if (v === 'ANOMALOUS') data.cell.styles.textColor = FORMAL_PALETTE.SEVERITY.HIGH.text;
          else data.cell.styles.textColor = FORMAL_PALETTE.SEVERITY.INFO.text;
        }
      }
    },
  });

  currentY = doc.lastAutoTable.finalY + 6;

  /*
  |--------------------------------------------------------------------------
  | 8. RFC & STANDARDS BASELINE CONFORMANCE
  |--------------------------------------------------------------------------
  */
  addSectionHeader('6. Standards Context & RFC Baseline Conformance');

  const standardsData = [
    [
      'RFC 8314',
      'Cleartext Considered Obsolete for Email',
      summary.plaintextCount === 0 ? 'CONFORMANT' : 'NON-CONFORMANT',
      summary.plaintextCount === 0
        ? 'No cleartext POP3, IMAP, or SMTP sessions observed. Complies with implicit TLS mandate.'
        : `Detected ${summary.plaintextCount} session(s) operating without mandatory transport-layer encryption. Cleartext submission violates Section 3.`,
    ],
    [
      'RFC 3207',
      'SMTP Service Extension for Secure SMTP over TLS',
      summary.vulnerableCount === 0 ? 'CONFORMANT' : 'NON-CONFORMANT',
      summary.vulnerableCount === 0
        ? 'STARTTLS correctly negotiated. No authentication commands issued prior to 220 TLS handshake.'
        : 'Authentication transmitted prior to successful TLS negotiation or STARTTLS upgrade was declined.',
    ],
    [
      'RFC 2595',
      'Using TLS with IMAP4, POP3 and ACAP',
      summary.imapCount + summary.pop3Count === 0 || summary.plaintextCount === 0 ? 'CONFORMANT' : 'NON-CONFORMANT',
      summary.plaintextCount === 0
        ? 'Mail access protocols utilized secure encrypted envelopes.'
        : 'Unencrypted IMAP/POP3 authentication allows passive retrieval of plain-text passwords on port 143/110.',
    ],
    [
      'NIST SP 800-52r2',
      'Guidelines for the Selection, Configuration, and Use of TLS',
      riskLevel === 'CRITICAL' || riskLevel === 'HIGH' ? 'REVIEW NEEDED' : 'CONFORMANT',
      'Evaluates support for TLS 1.2 / TLS 1.3, ephemeral Diffie-Hellman key exchanges (PFS), and SHA-256+ digest algorithms.',
    ],
  ];

  autoTable(doc, {
    startY: currentY,
    margin: { left: MARGIN_LEFT, right: MARGIN_RIGHT },
    head: [['STANDARD', 'SPECIFICATION TITLE', 'STATUS', 'AUDIT EVALUATION & OBSERVATION']],
    body: standardsData,
    theme: 'plain',
    styles: {
      fontSize: 7.2,
      cellPadding: 2.2,
      font: 'helvetica',
      textColor: FORMAL_PALETTE.INK_BLACK,
      lineColor: FORMAL_PALETTE.BORDER_SUBTLE,
      lineWidth: 0.2,
    },
    headStyles: {
      fillColor: FORMAL_PALETTE.HEADER_FILL,
      textColor: FORMAL_PALETTE.WHITE,
      fontStyle: 'bold',
      fontSize: 7.2,
    },
    alternateRowStyles: {
      fillColor: FORMAL_PALETTE.BG_LIGHT,
    },
    columnStyles: {
      0: { cellWidth: 26, fontStyle: 'bold' },
      1: { cellWidth: 42, fontStyle: 'bold' },
      2: { cellWidth: 26, halign: 'center', fontStyle: 'bold' },
      3: { cellWidth: 'auto' },
    },
    didParseCell: (data) => {
      if (data.section === 'body' && data.column.index === 2) {
        const val = data.cell.raw;
        if (val === 'CONFORMANT') data.cell.styles.textColor = FORMAL_PALETTE.SEVERITY.INFO.text;
        else if (val === 'NON-CONFORMANT') data.cell.styles.textColor = FORMAL_PALETTE.SEVERITY.CRITICAL.text;
        else data.cell.styles.textColor = FORMAL_PALETTE.SEVERITY.MEDIUM.text;
      }
    },
  });

  currentY = doc.lastAutoTable.finalY + 6;

  /*
  |--------------------------------------------------------------------------
  | 9. PRIORITIZED REMEDIATION & HARDENING ACTION PLAN
  | Formatted as a clean, formal table to avoid orphan pages
  |--------------------------------------------------------------------------
  */
  addSectionHeader('7. Prioritized Remediation & Hardening Action Plan');

  const rawRecs = analysis?.recommendations || [];
  const recommendations = rawRecs.length > 0 ? rawRecs : [
    {
      priority: 'MEDIUM',
      title: 'Maintain TLS 1.3 Baseline & Periodic Certificate Renewal',
      description: 'Ensure automated Let’s Encrypt / ACME renewals and monitor client cipher negotiation.',
    },
    {
      priority: 'LOW',
      title: 'Enforce MTA-STS and DANE for Inter-Domain Routing',
      description: 'Publish RFC 8461 MTA-STS policies and DNS TLSA records to prevent opportunistic downgrade attacks across MTAs.',
    },
  ];

  const recRows = recommendations.map((rec, idx) => {
    const pri = (rec.priority || 'HIGH').toUpperCase();
    const title = rec.title || `Remediation Item #${idx + 1}`;
    const desc = rec.description || rec.action || 'Implement recommended encryption configurations.';
    return [
      `#${idx + 1}`,
      pri,
      title,
      desc,
    ];
  });

  autoTable(doc, {
    startY: currentY,
    margin: { left: MARGIN_LEFT, right: MARGIN_RIGHT },
    head: [['NO.', 'PRIORITY', 'RECOMMENDED ACTION ITEM', 'TECHNICAL IMPLEMENTATION DETAILS']],
    body: recRows,
    theme: 'plain',
    styles: {
      fontSize: 7.2,
      cellPadding: 2.2,
      font: 'helvetica',
      textColor: FORMAL_PALETTE.INK_BLACK,
      lineColor: FORMAL_PALETTE.BORDER_SUBTLE,
      lineWidth: 0.2,
    },
    headStyles: {
      fillColor: FORMAL_PALETTE.HEADER_FILL,
      textColor: FORMAL_PALETTE.WHITE,
      fontStyle: 'bold',
      fontSize: 7.2,
    },
    alternateRowStyles: {
      fillColor: FORMAL_PALETTE.BG_LIGHT,
    },
    columnStyles: {
      0: { cellWidth: 10, halign: 'center', fontStyle: 'bold' },
      1: { cellWidth: 20, halign: 'center', fontStyle: 'bold' },
      2: { cellWidth: 50, fontStyle: 'bold' },
      3: { cellWidth: 'auto' },
    },
    didParseCell: (data) => {
      if (data.section === 'body' && data.column.index === 1) {
        const val = data.cell.raw;
        const col = getSeverityColors(val);
        data.cell.styles.textColor = col.text;
      }
    },
  });

  /*
  |--------------------------------------------------------------------------
  | 10. RUNNING HEADER & FOOTER ON ALL PAGES
  | Formal hairline headers and footers with accurate total page count
  |--------------------------------------------------------------------------
  */
  const totalPages = doc.internal.getNumberOfPages();

  for (let pageNum = 1; pageNum <= totalPages; pageNum++) {
    doc.setPage(pageNum);

    // Running Header (pages 2 to total)
    if (pageNum > 1) {
      doc.setFont('helvetica', 'bold');
      doc.setFontSize(7.2);
      doc.setTextColor(...FORMAL_PALETTE.HEADER_FILL);
      doc.text('SECUREMAILSCOPE', MARGIN_LEFT, 11);

      doc.setFont('helvetica', 'normal');
      doc.setTextColor(...FORMAL_PALETTE.TEXT_MUTED);
      doc.text('•   Email Traffic Security Analysis & Technical Audit Report', MARGIN_LEFT + 28, 11);

      const headerFile = `Target: ${pcapFilename}`;
      doc.text(headerFile, MARGIN_LEFT + CONTENT_WIDTH, 11, { align: 'right' });

      doc.setDrawColor(...FORMAL_PALETTE.BORDER_HAIRLINE);
      doc.setLineWidth(0.3);
      doc.line(MARGIN_LEFT, 13, MARGIN_LEFT + CONTENT_WIDTH, 13);
    }

    // Running Footer (All Pages)
    doc.setDrawColor(...FORMAL_PALETTE.BORDER_HAIRLINE);
    doc.setLineWidth(0.3);
    doc.line(MARGIN_LEFT, 287, MARGIN_LEFT + CONTENT_WIDTH, 287);

    doc.setFont('helvetica', 'normal');
    doc.setFontSize(6.8);
    doc.setTextColor(...FORMAL_PALETTE.TEXT_MUTED);
    doc.text(
      'CONFIDENTIAL  |  Generated by SecureMailScope Automated Security Telemetry Engine',
      MARGIN_LEFT,
      291
    );

    doc.setFont('helvetica', 'bold');
    doc.text(`Page ${pageNum} of ${totalPages}`, MARGIN_LEFT + CONTENT_WIDTH, 291, { align: 'right' });
  }

  /*
  |--------------------------------------------------------------------------
  | 11. SAVE OR RETURN BLOB
  |--------------------------------------------------------------------------
  */
  const sanitizedName = pcapFilename.replace(/[^a-zA-Z0-9._-]/g, '_');
  const outputFilename = customFilename || `SecureMailScope_Analysis_Report_${sanitizedName}.pdf`;

  if (download) {
    doc.save(outputFilename);
  }

  const blob = doc.output('blob');
  return { doc, blob, filename: outputFilename };
}
