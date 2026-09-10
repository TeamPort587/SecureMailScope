const ALLOWED_EXTENSIONS = ['.pcap', '.pcapng'];
const MAX_FILE_SIZE_BYTES = 100 * 1024 * 1024; // 100MB

/**
 * Validates a PCAP file selected for upload.
 * Note: Frontend validation improves UX; backend validation remains authoritative.
 */
export function validatePcapFile(file) {
  if (!file) {
    return { valid: false, error: 'Please select a packet capture file.' };
  }

  const filename = file.name || '';
  const lowerName = filename.toLowerCase();
  const hasValidExt = ALLOWED_EXTENSIONS.some((ext) => lowerName.endsWith(ext));

  if (!hasValidExt) {
    return {
      valid: false,
      error: `Invalid file extension. Only ${ALLOWED_EXTENSIONS.join(' and ')} files are supported.`,
    };
  }

  if (file.size <= 0) {
    return {
      valid: false,
      error: 'Selected file is empty (0 bytes).',
    };
  }

  if (file.size > MAX_FILE_SIZE_BYTES) {
    return {
      valid: false,
      error: `File size exceeds the 100 MB limit (Selected: ${(file.size / (1024 * 1024)).toFixed(1)} MB).`,
    };
  }

  return { valid: true, error: null };
}
