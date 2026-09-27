/**
 * Standards Context and Configuration Comparison Service for Node Gateway.
 *
 * Implements authoritative guidance comparison (RFC 9325, RFC 8996, RFC 8314, NIST SP 800-52/57)
 * to evaluate where an observed session configuration sits relative to preferred industry configurations.
 */

const RFC_9325 = {
  name: 'RFC 9325',
  title: 'Recommendations for Secure Use of Transport Layer Security (TLS) and Datagram Transport Layer Security (DTLS)',
  section: 'Section 3.1.1 (Protocol Versions) & Section 4.2 (Cipher Suites)',
  url: 'https://datatracker.ietf.org/doc/html/rfc9325',
  published_date: '2022-11',
  effective_status: 'CURRENT',
};

const RFC_8996 = {
  name: 'RFC 8996',
  title: 'Deprecating TLS 1.0 and TLS 1.1',
  section: 'Section 1 (Introduction & Formal Deprecation)',
  url: 'https://datatracker.ietf.org/doc/html/rfc8996',
  published_date: '2021-03',
  effective_status: 'CURRENT',
};

const RFC_8314 = {
  name: 'RFC 8314',
  title: 'Cleartext Considered Obsolete: Use of Transport Layer Security (TLS) for Email Submission and Access',
  section: 'Section 3 (Cleartext Obsolete) & Section 4.1 / 5.1 (Implicit TLS Recommendation)',
  url: 'https://datatracker.ietf.org/doc/html/rfc8314',
  published_date: '2018-05',
  effective_status: 'CURRENT',
};

const NIST_SP800_52 = {
  name: 'NIST SP 800-52 Rev. 2',
  title: 'Guidelines for the Selection, Configuration, and Use of Transport Layer Security (TLS) Implementations',
  section: 'Section 3.1 (Protocol Versions) & Section 3.3 (Certificate Key Strengths)',
  url: 'https://csrc.nist.gov/pubs/sp/800/52/r2/final',
  published_date: '2019-08',
  effective_status: 'SUBJECT_TO_PERIODIC_REVIEW',
};

const NIST_SP800_57 = {
  name: 'NIST SP 800-57 Part 1 Rev. 5',
  title: 'Recommendation for Key Management: Part 1 – General',
  section: 'Table 2: Comparable security strengths of symmetric and asymmetric algorithms',
  url: 'https://csrc.nist.gov/pubs/sp/800/57/pt1/r5/final',
  published_date: '2020-05',
  effective_status: 'CURRENT',
};

/**
 * Generate complete standards context comparison results for a session.
 *
 * @param {Object} session - Reconstructed session object
 * @returns {Array<Object>} List of ComparisonResult objects
 */
function evaluateSessionStandards(session) {
  if (!session) return [];

  // If already attached and non-empty, use existing
  if (Array.isArray(session.standards_context) && session.standards_context.length > 0) {
    return session.standards_context;
  }

  const results = [];
  const isPlaintext = session.security?.encryption_mode === 'PLAINTEXT';
  const hasTls = Boolean(session.tls && session.tls.version);

  // 1. Email Encryption Mode (RFC 8314)
  results.push(evaluateEmailEncryptionMode(session));

  // 2. TLS Version (RFC 9325 / RFC 8996)
  results.push(evaluateTlsVersion(session, isPlaintext, hasTls));

  // 3. Cipher Suite Modernity (RFC 9325)
  if (hasTls && session.tls?.cipher_suite) {
    results.push(evaluateCipherSuite(session.tls.cipher_suite));
  }

  // 4. Forward Secrecy / PFS (RFC 9325)
  if (hasTls && session.tls) {
    results.push(evaluateForwardSecrecy(session.tls.pfs));
  }

  // 5. Certificate Key Strength & Validity (NIST SP 800-52 / 57)
  if (!isPlaintext && session.certificate) {
    const keyStrength = evaluateKeyStrength(session.certificate);
    if (keyStrength) results.push(keyStrength);

    const validity = evaluateCertificateValidity(session.certificate, session.start_time);
    if (validity) results.push(validity);
  }

  return results;
}

function evaluateEmailEncryptionMode(session) {
  const mode = session.security?.encryption_mode || 'UNKNOWN';
  const port = session.server_port || session.service_port || 'unknown';

  const options = [
    {
      value: 'PLAINTEXT',
      label: 'Cleartext / Plaintext',
      status: 'DEPRECATED',
      description: 'Obsolete. Exposes credentials and message data to passive capture (RFC 8314 Sec 3).',
    },
    {
      value: 'STARTTLS',
      label: 'STARTTLS (Opportunistic)',
      status: 'ACCEPTABLE',
      description: 'Acceptable in-band upgrade, but vulnerable to active MITM stripping attacks without strict enforcement.',
    },
    {
      value: 'IMPLICIT_TLS',
      label: 'Implicit TLS (Dedicated Port)',
      status: 'PREFERRED',
      description: 'Preferred by RFC 8314; TLS is negotiated immediately upon TCP connection, eliminating stripping risks.',
    },
  ];

  let status = 'UNKNOWN';
  let observed = 'Unknown / Indeterminate';
  let rationale = 'Transport security mode could not be definitively determined from capture.';

  const normalizedMode = String(mode).toUpperCase();
  if (normalizedMode === 'IMPLICIT_TLS' || normalizedMode === 'IMPLICIT') {
    status = 'PREFERRED';
    observed = 'Implicit TLS (Dedicated Port)';
    rationale = `The session connected via Implicit TLS on port ${port}. RFC 8314 Section 4.1 & 5.1 explicitly prefers Implicit TLS over STARTTLS for mail submission and access because it eliminates STARTTLS-stripping vulnerabilities entirely.`;
  } else if (normalizedMode === 'STARTTLS') {
    status = 'ACCEPTABLE';
    observed = 'STARTTLS (In-Band Upgrade)';
    rationale = `The session negotiated TLS via the STARTTLS upgrade command on port ${port}. While acceptable and widely deployed, RFC 8314 prefers Implicit TLS (ports 465, 993, 995) to prevent active protocol-downgrade attacks.`;
  } else if (normalizedMode === 'PLAINTEXT' || normalizedMode === 'CLEARTEXT') {
    status = 'DEPRECATED';
    observed = 'Plaintext (Cleartext)';
    rationale = `The ${session.protocol || 'email'} session was unencrypted. RFC 8314 Section 3 declares cleartext email transmission obsolete due to plaintext credential and payload exposure.`;
  }

  return {
    field: 'email_encryption_mode',
    label: 'Email Transport Encryption Mode',
    observed,
    status,
    preferred: ['Implicit TLS (Dedicated Port)'],
    visualization: 'ordered_spectrum',
    options,
    profile: 'email-security',
    profile_name: 'Email Security (RFC 8314)',
    rationale,
    sources: [RFC_8314],
  };
}

function evaluateTlsVersion(session, isPlaintext, hasTls) {
  const options = [
    {
      value: 'TLS 1.0',
      label: 'TLS 1.0',
      status: 'DEPRECATED',
      description: 'Formally deprecated by RFC 8996; vulnerable to CBC timing and downgrade attacks.',
    },
    {
      value: 'TLS 1.1',
      label: 'TLS 1.1',
      status: 'DEPRECATED',
      description: 'Formally deprecated by RFC 8996; lacks support for current AEAD cipher suites.',
    },
    {
      value: 'TLS 1.2',
      label: 'TLS 1.2',
      status: 'ACCEPTABLE',
      description: 'Acceptable baseline under RFC 9325 when configured with AEAD ciphers and forward secrecy.',
    },
    {
      value: 'TLS 1.3',
      label: 'TLS 1.3',
      status: 'PREFERRED',
      description: 'Preferred modern version offering 1-RTT handshakes and mandatory modern cryptography.',
    },
  ];

  if (isPlaintext) {
    return {
      field: 'tls_version',
      label: 'TLS Protocol Version',
      observed: 'PLAINTEXT (None)',
      status: 'DEPRECATED',
      preferred: ['TLS 1.3'],
      visualization: 'ordered_spectrum',
      options,
      profile: 'ietf-modern-tls',
      profile_name: 'IETF Modern TLS (RFC 9325)',
      rationale: 'Unencrypted plaintext communication is obsolete. RFC 9325 and RFC 8314 require TLS for email transport.',
      sources: [RFC_9325, RFC_8996],
    };
  }

  if (!hasTls || !session.tls?.version) {
    return {
      field: 'tls_version',
      label: 'TLS Protocol Version',
      observed: 'UNKNOWN',
      status: 'UNKNOWN',
      preferred: ['TLS 1.3'],
      visualization: 'ordered_spectrum',
      options,
      profile: 'ietf-modern-tls',
      profile_name: 'IETF Modern TLS (RFC 9325)',
      rationale: 'Insufficient handshake packets were observed to establish the negotiated TLS version.',
      sources: [RFC_9325],
    };
  }

  const version = session.tls.version.trim();
  const vUpper = version.toUpperCase();
  let status = 'UNKNOWN';
  let rationale = `Observed version (${version}) is unclassified under current profiles.`;

  if (vUpper.includes('1.3')) {
    status = 'PREFERRED';
    rationale = 'TLS 1.3 is the preferred protocol version under RFC 9325, providing simplified modern cryptographic options and enhanced privacy.';
  } else if (vUpper.includes('1.2')) {
    status = 'ACCEPTABLE';
    rationale = 'TLS 1.2 is acceptable under RFC 9325 when configured with AEAD cipher suites and forward secrecy. TLS 1.3 is preferred for modern deployments.';
  } else if (/1\.[01]|SSL/.test(vUpper)) {
    status = 'DEPRECATED';
    rationale = `${version} is formally deprecated by RFC 8996. It lacks support for modern AEAD ciphers and is vulnerable to known protocol downgrade attacks.`;
  }

  return {
    field: 'tls_version',
    label: 'TLS Protocol Version',
    observed: version,
    status,
    preferred: ['TLS 1.3'],
    visualization: 'ordered_spectrum',
    options,
    profile: 'ietf-modern-tls',
    profile_name: 'IETF Modern TLS (RFC 9325)',
    rationale,
    sources: [RFC_9325, RFC_8996],
  };
}

function evaluateCipherSuite(cipher) {
  const cUpper = cipher.toUpperCase();
  const options = [
    {
      value: 'LEGACY_INSECURE',
      label: 'Legacy / Insecure',
      status: 'DEPRECATED',
      description: 'Broken or weak ciphers: RC4, 3DES, DES, EXPORT, NULL.',
    },
    {
      value: 'CBC_MODE',
      label: 'CBC Mode (Non-AEAD)',
      status: 'NOT_RECOMMENDED',
      description: 'AES-CBC suites susceptible to padding oracle and timing attacks (RFC 9325 Sec 4.2.2).',
    },
    {
      value: 'AEAD_MODERN',
      label: 'AEAD (GCM / Poly1305)',
      status: 'PREFERRED',
      description: 'Authenticated Encryption with Associated Data (AES-GCM, ChaCha20-Poly1305) required by RFC 9325.',
    },
  ];

  const isLegacy = /RC4|3DES|DES|NULL|EXPORT|MD5/.test(cUpper);
  const isAead = /GCM|CHACHA20|POLY1305|CCM/.test(cUpper);
  const isCbc = cUpper.includes('CBC');

  let status = 'ACCEPTABLE';
  let category = 'Standard Cipher';
  let rationale = `Negotiated cipher suite (${cipher}) is functional but AEAD suites are preferred.`;

  if (isLegacy) {
    status = 'DEPRECATED';
    category = 'Legacy / Insecure';
    rationale = `The cipher suite (${cipher}) utilizes obsolete algorithms explicitly prohibited by RFC 9325 Section 4.2.1.`;
  } else if (isAead) {
    status = 'PREFERRED';
    category = 'AEAD (GCM / Poly1305)';
    rationale = `The negotiated cipher suite (${cipher}) provides Authenticated Encryption with Associated Data (AEAD), satisfying RFC 9325 Section 4.2.1 recommendations.`;
  } else if (isCbc) {
    status = 'NOT_RECOMMENDED';
    category = 'CBC Mode (Non-AEAD)';
    rationale = `The negotiated cipher suite (${cipher}) relies on CBC mode encryption. RFC 9325 Section 4.2.2 advises against CBC ciphers due to padding oracle vulnerabilities.`;
  }

  return {
    field: 'cipher_suite',
    label: 'Cipher Suite Classification',
    observed: `${cipher} (${category})`,
    status,
    preferred: ['AEAD (GCM / Poly1305)'],
    visualization: 'categorical_spectrum',
    options,
    profile: 'ietf-modern-tls',
    profile_name: 'IETF Modern TLS (RFC 9325)',
    rationale,
    sources: [RFC_9325],
    metadata: { raw_cipher: cipher, category },
  };
}

function evaluateForwardSecrecy(pfsStatus) {
  const options = [
    {
      value: 'NO_PFS',
      label: 'No Forward Secrecy',
      status: 'NOT_RECOMMENDED',
      description: 'Static RSA key exchange; compromised server private key allows retroactive decryption of recorded traffic.',
    },
    {
      value: 'PFS',
      label: 'Forward Secrecy (PFS)',
      status: 'PREFERRED',
      description: 'Ephemeral key exchange (ECDHE / DHE); session keys cannot be retroactively derived.',
    },
  ];

  let status = 'UNKNOWN';
  let observed = 'Unknown / Incomplete Handshake';
  let rationale = 'Passive capture did not observe sufficient key exchange parameters to determine forward secrecy standing.';

  if (pfsStatus === 'YES') {
    status = 'PREFERRED';
    observed = 'Forward Secrecy Observed (PFS)';
    rationale = 'The session negotiated ephemeral key exchange (e.g. ECDHE), ensuring forward secrecy as mandated by RFC 9325 Section 3.4.2.';
  } else if (pfsStatus === 'NO') {
    status = 'NOT_RECOMMENDED';
    observed = 'No Forward Secrecy';
    rationale = 'The session does not provide perfect forward secrecy. RFC 9325 Section 3.4.2 mandates forward secrecy so that past traffic remains protected if the server private key is ever compromised.';
  }

  return {
    field: 'pfs',
    label: 'Forward Secrecy (PFS)',
    observed,
    status,
    preferred: ['Forward Secrecy (PFS)'],
    visualization: 'capability_comparison',
    options,
    profile: 'ietf-modern-tls',
    profile_name: 'IETF Modern TLS (RFC 9325)',
    rationale,
    sources: [RFC_9325],
  };
}

function evaluateKeyStrength(certificate) {
  if (certificate.visibility === 'NOT_OBSERVABLE') {
    return {
      field: 'certificate_key_strength',
      label: 'Certificate Key Strength',
      observed: 'Not Observable (Encrypted in TLS 1.3)',
      status: 'NOT_OBSERVABLE',
      preferred: ['RSA 3072 / 4096-bit', 'EC P-256 / P-384'],
      visualization: 'status_assessment',
      options: [],
      profile: 'nist-tls-guidance',
      profile_name: 'NIST Guidance (SP 800-52 Rev. 2 / SP 800-57)',
      rationale: 'In TLS 1.3, the server certificate message is encrypted in flight. Passive network inspection cannot inspect the public key algorithm without session decryption keys. This is an expected privacy property of TLS 1.3.',
      sources: [NIST_SP800_52, NIST_SP800_57],
    };
  }

  const keyType = (certificate.key_type || 'RSA').toUpperCase();
  const keySize = certificate.key_size || 2048;

  const options = [
    {
      value: 'RSA_UNDER_2048',
      label: 'RSA < 2048-bit',
      status: 'DEPRECATED',
      description: 'Legacy / Obsolete. Disallowed by NIST SP 800-57 after 2013 due to insufficient factoring resistance.',
    },
    {
      value: 'RSA_2048',
      label: 'RSA 2048-bit',
      status: 'ACCEPTABLE',
      description: '112-bit security strength; acceptable under NIST SP 800-52 Rev. 2 through 2030.',
    },
    {
      value: 'RSA_3072_PLUS',
      label: 'RSA >= 3072-bit / EC P-256+',
      status: 'PREFERRED',
      description: '128-bit+ security strength; preferred for modern infrastructure and post-2030 longevity.',
    },
  ];

  let status = 'ACCEPTABLE';
  let observed = `${keyType} ${keySize}-bit`;
  let rationale = `Observed key algorithm (${keyType}) with ${keySize}-bit key size.`;

  if (keyType.includes('EC') || keyType === 'ECDSA') {
    if (keySize >= 256) {
      status = 'PREFERRED';
      observed = `EC ${keySize}-bit (ECDSA)`;
      rationale = `Elliptic-curve key of ${keySize} bits provides >= 128-bit security strength, equivalent to RSA-3072+. Preferred under NIST SP 800-52 Rev. 2 Section 3.3.`;
    } else {
      status = 'NOT_RECOMMENDED';
      observed = `EC ${keySize}-bit (ECDSA)`;
      rationale = `Elliptic-curve key below 256 bits (${keySize} bits) does not satisfy the 128-bit minimum security strength.`;
    }
  } else if (keyType === 'RSA') {
    if (keySize < 2048) {
      status = 'DEPRECATED';
      observed = `RSA ${keySize}-bit`;
      rationale = `RSA keys smaller than 2048 bits (${keySize} bits) provide less than 112 bits of security and were disallowed by NIST SP 800-57 after 2013.`;
    } else if (keySize === 2048) {
      status = 'ACCEPTABLE';
      observed = 'RSA 2048-bit';
      rationale = 'RSA 2048-bit provides 112-bit security strength, which is acceptable through 2030 under NIST SP 800-52 Rev. 2. RSA-3072+ or EC P-256 is preferred for greater longevity.';
    } else {
      status = 'PREFERRED';
      observed = `RSA ${keySize}-bit`;
      rationale = `RSA ${keySize}-bit provides >= 128-bit security strength, aligning with NIST SP 800-57 recommendations for long-term protection.`;
    }
  }

  return {
    field: 'certificate_key_strength',
    label: 'Certificate Key Strength',
    observed,
    status,
    preferred: ['RSA >= 3072-bit / EC P-256+'],
    visualization: 'ordered_spectrum',
    options,
    profile: 'nist-tls-guidance',
    profile_name: 'NIST Guidance (SP 800-52 Rev. 2 / SP 800-57)',
    rationale,
    sources: [NIST_SP800_52, NIST_SP800_57],
  };
}

function evaluateCertificateValidity(certificate, startTime) {
  if (certificate.visibility === 'NOT_OBSERVABLE') {
    return {
      field: 'certificate_validity',
      label: 'Certificate Validity Period',
      observed: 'Not Observable (Encrypted in TLS 1.3)',
      status: 'NOT_OBSERVABLE',
      preferred: ['Valid at Session Timestamp'],
      visualization: 'status_assessment',
      options: [],
      profile: 'nist-tls-guidance',
      profile_name: 'NIST Guidance (SP 800-52 Rev. 2)',
      rationale: 'Certificate validity period cannot be established because TLS 1.3 encrypts certificate metadata in flight.',
      sources: [NIST_SP800_52],
    };
  }

  const refTime = startTime ? new Date(startTime) : new Date();
  const validFrom = certificate.valid_from ? new Date(certificate.valid_from) : null;
  const validUntil = certificate.valid_until ? new Date(certificate.valid_until) : null;

  const options = [
    {
      value: 'NOT_YET_VALID',
      label: 'Not Yet Valid',
      status: 'NOT_RECOMMENDED',
      description: 'Session capture timestamp preceded the certificate notBefore date.',
    },
    {
      value: 'VALID_DURING_CAPTURE',
      label: 'Valid During Capture',
      status: 'RECOMMENDED',
      description: 'Session capture timestamp is within the certificate validity window [notBefore, notAfter].',
    },
    {
      value: 'EXPIRED_AT_CAPTURE',
      label: 'Expired at Capture',
      status: 'DEPRECATED',
      description: 'Session capture timestamp succeeded the certificate notAfter expiration date.',
    },
  ];

  let status = 'UNKNOWN';
  let observed = 'Validity Window Indeterminate';
  let rationale = 'Certificate timestamps could not be extracted from passive capture.';

  if (validUntil && validUntil < refTime) {
    status = 'DEPRECATED';
    observed = `Expired at Capture Time (${certificate.valid_until})`;
    rationale = `The certificate validity period ended on ${certificate.valid_until}, which preceded the session capture time. Expired certificates fail authentication under NIST SP 800-52 Rev. 2 Section 3.1.`;
  } else if (validFrom && validFrom > refTime) {
    status = 'NOT_RECOMMENDED';
    observed = `Not Yet Valid at Capture Time (${certificate.valid_from})`;
    rationale = `The certificate valid_from date (${certificate.valid_from}) was after the session capture time.`;
  } else if (validFrom && validUntil) {
    status = 'RECOMMENDED';
    observed = 'Valid During Session Capture';
    rationale = `The certificate was valid when the session was recorded. Validity period spans ${certificate.valid_from.slice(0, 10)} to ${certificate.valid_until.slice(0, 10)}, encompassing the session capture.`;
  }

  return {
    field: 'certificate_validity',
    label: 'Certificate Validity Period',
    observed,
    status,
    preferred: ['Valid During Capture'],
    visualization: 'status_assessment',
    options,
    profile: 'nist-tls-guidance',
    profile_name: 'NIST Guidance (SP 800-52 Rev. 2)',
    rationale,
    sources: [NIST_SP800_52],
  };
}

module.exports = {
  evaluateSessionStandards,
  evaluateEmailEncryptionMode,
  evaluateTlsVersion,
  evaluateCipherSuite,
  evaluateForwardSecrecy,
  evaluateKeyStrength,
  evaluateCertificateValidity,
};
