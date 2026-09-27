const fs = require('fs');
const path = require('path');
const { execFile } = require('child_process');
const crypto = require('crypto');
const logger = require('../utils/logger');
const { AppError } = require('../utils/errors');

class SessionExportError extends AppError {
  constructor(message = 'Failed to export session capture.') {
    super(message, 500, 'SESSION_EXPORT_FAILED');
  }
}

/**
 * Locate tshark executable if available.
 */
function findTshark() {
  if (process.env.TSHARK_PATH && fs.existsSync(process.env.TSHARK_PATH)) {
    return process.env.TSHARK_PATH;
  }

  if (process.platform === 'win32') {
    const defaultWinPath = 'C:\\Program Files\\Wireshark\\tshark.exe';
    if (fs.existsSync(defaultWinPath)) {
      return defaultWinPath;
    }
  }

  return 'tshark'; // Rely on system PATH
}

/**
 * Compute SHA-256 hash of a file synchronously/stream.
 */
function computeFileSha256(filePath) {
  return new Promise((resolve, reject) => {
    const hash = crypto.createHash('sha256');
    const stream = fs.createReadStream(filePath);
    stream.on('data', (chunk) => hash.update(chunk));
    stream.on('end', () => resolve(hash.digest('hex')));
    stream.on('error', (err) => reject(err));
  });
}

/**
 * Run a child process and return promise.
 */
function runCommand(bin, args) {
  return new Promise((resolve, reject) => {
    execFile(bin, args, { maxBuffer: 50 * 1024 * 1024 }, (err, stdout, stderr) => {
      if (err) {
        return reject(new Error(`${err.message}: ${stderr}`));
      }
      resolve({ stdout, stderr });
    });
  });
}

/**
 * Export packets belonging to a TCP stream into a standalone PCAP file.
 *
 * @param {string} sourcePcapPath - Path to original PCAP/PCAPNG
 * @param {number} tcpStream - TCP stream index
 * @param {string} targetPcapPath - Destination path for extracted PCAP
 * @returns {Promise<Object>} Export metadata
 */
async function exportSessionPcap(sourcePcapPath, tcpStream, targetPcapPath) {
  const startTime = Date.now();
  logger.info('Session export started', {
    sourcePcapPath,
    tcpStream,
    targetPcapPath,
  });

  if (!fs.existsSync(sourcePcapPath)) {
    logger.error('Source capture not found for export', { sourcePcapPath });
    throw new SessionExportError(`Source PCAP file not found: ${path.basename(sourcePcapPath)}`);
  }

  const targetDir = path.dirname(path.resolve(targetPcapPath));
  if (!fs.existsSync(targetDir)) {
    fs.mkdirSync(targetDir, { recursive: true });
  }

  let packetCount = 0;
  let usedBackend = 'none';

  // Try TShark first
  try {
    const tsharkBin = findTshark();
    const filter = `tcp.stream == ${tcpStream}`;
    await runCommand(tsharkBin, ['-r', sourcePcapPath, '-Y', filter, '-w', targetPcapPath]);

    // Check packet count
    const countRes = await runCommand(tsharkBin, [
      '-r',
      targetPcapPath,
      '-T',
      'fields',
      '-e',
      'frame.number',
    ]);
    packetCount = countRes.stdout.split('\n').filter((l) => l.trim()).length;
    usedBackend = 'tshark';
  } catch (tsharkErr) {
    logger.warn('TShark session export failed, falling back to python exporter', {
      error: tsharkErr.message,
      tcpStream,
    });

    // Fallback: Python session exporter
    try {
      const pythonBin = process.env.PYTHON_BIN || (process.platform === 'win32' ? '.venv\\Scripts\\python.exe' : 'python3');
      const projectRoot = path.resolve(__dirname, '../../../');
      await runCommand(pythonBin, [
        '-m',
        'analysis.session_engine.exporter',
        sourcePcapPath,
        targetPcapPath,
        String(tcpStream),
      ], { cwd: projectRoot });

      usedBackend = 'python';
    } catch (pyErr) {
      logger.error('Python exporter also failed', { error: pyErr.message });
      throw new SessionExportError(
        `Failed to extract TCP stream ${tcpStream}: ${pyErr.message}`
      );
    }
  }

  if (!fs.existsSync(targetPcapPath) || fs.statSync(targetPcapPath).size === 0) {
    throw new SessionExportError(
      `No packets extracted or empty file produced for TCP stream ${tcpStream}.`
    );
  }

  const fileSizeBytes = fs.statSync(targetPcapPath).size;
  const sourceSha256 = await computeFileSha256(sourcePcapPath);
  const targetSha256 = await computeFileSha256(targetPcapPath);
  const durationMs = Date.now() - startTime;

  logger.info('Session export completed', {
    tcpStream,
    packetCount,
    fileSizeBytes,
    usedBackend,
    durationMs,
  });

  return {
    tcp_stream: tcpStream,
    packet_count: packetCount,
    file_size_bytes: fileSizeBytes,
    source_pcap_sha256: sourceSha256,
    extracted_pcap_sha256: targetSha256,
    wireshark_filter: `tcp.stream == ${tcpStream}`,
    target_pcap_path: targetPcapPath,
  };
}

module.exports = {
  exportSessionPcap,
  SessionExportError,
};
