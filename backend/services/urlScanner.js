/**
 * URL Scanner Service
 * Performs: DNS lookup, SSL validation, HTTP header inspection,
 * redirect chain analysis, suspicious pattern detection, risk scoring
 */

'use strict';

const dns   = require('dns').promises;
const https = require('https');
const http  = require('http');
const url   = require('url');

// ─── CONSTANTS ─────────────────────────────────────────────

// URL shortener domains (redirect obfuscation)
const URL_SHORTENERS = new Set([
  'bit.ly','tinyurl.com','t.co','goo.gl','ow.ly','buff.ly','rebrand.ly',
  'is.gd','cli.gs','pic.gd','short.to','go2l.ink','x.co','prettylinkpro.com',
  'lnkd.in','db.tt','qr.ae','adf.ly','bitly.com','cutt.ly','u.to',
  'bc.vc','j.mp','ift.tt','su.pr','twit.ac','ff.im',
]);

// Suspicious TLDs commonly used in phishing
const SUSPICIOUS_TLDS = new Set([
  '.xyz','.tk','.ml','.ga','.cf','.gq','.top','.club','.work',
  '.icu','.cyou','.buzz','.vip','.live','.online','.tech',
]);

// Security-critical HTTP headers
const SECURITY_HEADERS = [
  'strict-transport-security',
  'x-frame-options',
  'x-content-type-options',
  'content-security-policy',
  'x-xss-protection',
  'referrer-policy',
];

// Phishing URL path patterns
const SUSPICIOUS_PATH_PATTERNS = [
  /login/i, /signin/i, /verify/i, /secure/i, /account/i,
  /banking/i, /update/i, /confirm/i, /validate/i, /password/i,
  /credential/i, /paypal/i, /apple/i, /microsoft/i, /amazon/i,
  /google/i, /netflix/i, /facebook/i, /instagram/i, /support/i,
];

// ─── MAIN SCAN FUNCTION ────────────────────────────────────
async function scanUrl(targetUrl) {
  const parsed    = new URL(targetUrl);
  const hostname  = parsed.hostname;

  let threatScore        = 0;
  let dnsStatus          = 'UNRESOLVED';
  let sslValid           = null;
  let certificateIssuer  = 'N/A';
  let redirects          = 0;
  let suspiciousKeywords = [];
  let httpHeaders        = {};
  const riskFactors      = [];

  // ── 1. HTTP vs HTTPS detection ─────────────────────────
  if (parsed.protocol === 'http:') {
    threatScore += 25;
    riskFactors.push('No HTTPS – data transmitted in plaintext');
    sslValid = false;
  }

  // ── 2. DNS Lookup ──────────────────────────────────────
  try {
    const addresses = await dns.resolve4(hostname);
    if (addresses && addresses.length > 0) {
      dnsStatus = 'RESOLVED';
    } else {
      dnsStatus = 'NO_RECORDS';
      threatScore += 20;
      riskFactors.push('Domain has no DNS A records');
    }
  } catch (dnsErr) {
    dnsStatus = 'UNRESOLVED';
    threatScore += 30;
    riskFactors.push(`DNS resolution failed: ${dnsErr.code || dnsErr.message}`);
  }

  // ── 3. Punycode / IDN homograph detection ─────────────
  // Attackers use Internationalized Domain Names to mimic trusted sites
  if (hostname.startsWith('xn--') || hostname.includes('.xn--')) {
    threatScore += 35;
    riskFactors.push('Punycode (xn--) domain detected – likely IDN homograph attack');
    suspiciousKeywords.push('punycode-domain');
  }

  // ── 4. URL Shortener detection ────────────────────────
  if (URL_SHORTENERS.has(hostname) || URL_SHORTENERS.has(hostname.replace('www.', ''))) {
    threatScore += 20;
    riskFactors.push('URL shortener detected – true destination is obfuscated');
    suspiciousKeywords.push('url-shortener');
  }

  // ── 5. Suspicious TLD ─────────────────────────────────
  const domainParts = hostname.split('.');
  const tld = '.' + domainParts[domainParts.length - 1];
  if (SUSPICIOUS_TLDS.has(tld)) {
    threatScore += 15;
    riskFactors.push(`Suspicious TLD "${tld}" commonly used in phishing campaigns`);
    suspiciousKeywords.push(`tld:${tld}`);
  }

  // ── 6. Brand impersonation (domain + subdomain analysis) ─
  const BRANDS = ['paypal','amazon','apple','microsoft','google','netflix','facebook',
                  'instagram','twitter','linkedin','stripe','coinbase','binance','chase',
                  'wellsfargo','citibank','bankofamerica','irs','gov'];
  const fullHost = hostname.toLowerCase();
  BRANDS.forEach(brand => {
    // If brand name appears in subdomain but NOT as the root domain
    if (fullHost.includes(brand) && !fullHost.endsWith(`${brand}.com`) && !fullHost.endsWith(`${brand}.org`)) {
      threatScore += 30;
      riskFactors.push(`Brand name "${brand}" appears in domain/subdomain – possible spoofing`);
      suspiciousKeywords.push(`brand-spoof:${brand}`);
    }
  });

  // ── 7. Suspicious path patterns ──────────────────────
  const path = parsed.pathname + parsed.search;
  SUSPICIOUS_PATH_PATTERNS.forEach(pat => {
    if (pat.test(path)) {
      const matchStr = path.match(pat)?.[0];
      if (!suspiciousKeywords.includes(`path:${matchStr}`)) {
        threatScore += 8;
        suspiciousKeywords.push(`path:${matchStr}`);
      }
    }
  });

  // ── 8. Excessive subdomains ───────────────────────────
  if (domainParts.length > 4) {
    threatScore += 15;
    riskFactors.push(`Excessive subdomain depth (${domainParts.length} labels) – obfuscation tactic`);
    suspiciousKeywords.push('excessive-subdomains');
  }

  // ── 9. SSL Certificate + HTTP Headers + Redirect Count ─
  if (parsed.protocol === 'https:') {
    const sslResult = await checkSSLAndHeaders(targetUrl);
    sslValid         = sslResult.sslValid;
    certificateIssuer= sslResult.certificateIssuer;
    httpHeaders      = sslResult.headers;
    redirects        = sslResult.redirects;

    if (!sslValid) {
      threatScore += 40;
      riskFactors.push('SSL certificate invalid, expired, or self-signed');
    } else {
      // Check cert issuer – self-signed certs have no recognized CA
      if (certificateIssuer.toLowerCase().includes('unknown') ||
          certificateIssuer.toLowerCase().includes('self')) {
        threatScore += 20;
        riskFactors.push('Self-signed certificate – not issued by trusted CA');
      }
    }

    // Excessive redirects
    if (redirects > 3) {
      threatScore += 15;
      riskFactors.push(`Excessive redirect chain (${redirects} redirects) – destination obfuscation`);
    }

    // Missing critical security headers
    const missingHeaders = SECURITY_HEADERS.filter(h => !httpHeaders[h]);
    if (missingHeaders.length >= 4) {
      threatScore += 10;
      riskFactors.push(`Missing ${missingHeaders.length} security headers: ${missingHeaders.join(', ')}`);
    }
  }

  // ── 10. Numeric IP as hostname ───────────────────────
  if (/^(\d{1,3}\.){3}\d{1,3}$/.test(hostname)) {
    threatScore += 30;
    riskFactors.push('IP address used instead of domain name – avoids domain reputation checks');
    suspiciousKeywords.push('ip-host');
  }

  // ── 11. Very long URL ─────────────────────────────────
  if (targetUrl.length > 200) {
    threatScore += 10;
    riskFactors.push('Unusually long URL – may contain obfuscated parameters');
    suspiciousKeywords.push('long-url');
  }

  // Clamp score to 0–100
  threatScore = Math.min(100, Math.max(0, threatScore));

  return {
    threatScore,
    dnsStatus,
    sslValid,
    certificateIssuer,
    redirects,
    suspiciousKeywords: [...new Set(suspiciousKeywords)],
    httpHeaders,
    riskFactors,
    hostname,
  };
}

// ─── SSL + HEADERS CHECK ───────────────────────────────────
function checkSSLAndHeaders(targetUrl, maxRedirects = 5) {
  return new Promise((resolve) => {
    let redirectCount = 0;
    let sslValid      = false;
    let certIssuer    = 'N/A';

    const request = (currentUrl) => {
      const parsedUrl = url.parse(currentUrl);
      const isHttps   = parsedUrl.protocol === 'https:';
      const lib       = isHttps ? https : http;

      const options = {
        hostname:           parsedUrl.hostname,
        port:               parsedUrl.port || (isHttps ? 443 : 80),
        path:               parsedUrl.path || '/',
        method:             'HEAD', // HEAD only – we don't need body
        timeout:            8000,
        rejectUnauthorized: true, // we want to detect invalid certs
        headers: {
          'User-Agent': 'PhishGuard-SecurityScanner/2.0',
          'Accept':     '*/*',
        },
      };

      const req = lib.request(options, (res) => {
        const statusCode = res.statusCode;
        const headers    = res.headers || {};

        // Follow redirects
        if ([301,302,303,307,308].includes(statusCode) && headers.location) {
          if (redirectCount < maxRedirects) {
            redirectCount++;
            let nextUrl = headers.location;
            // Resolve relative redirect
            if (!nextUrl.startsWith('http')) {
              nextUrl = `${parsedUrl.protocol}//${parsedUrl.hostname}${nextUrl}`;
            }
            request(nextUrl);
          } else {
            resolve({ sslValid, certificateIssuer: certIssuer, headers: headers, redirects: redirectCount });
          }
          return;
        }

        resolve({
          sslValid:           sslValid,
          certificateIssuer:  certIssuer,
          headers:            headers,
          redirects:          redirectCount,
        });
      });

      // Capture SSL certificate info
      req.on('socket', (socket) => {
        socket.on('secureConnect', () => {
          try {
            const cert = socket.getPeerCertificate(true);
            if (cert && cert.subject) {
              sslValid  = socket.authorized;
              certIssuer = cert.issuer?.O || cert.issuer?.CN || 'Unknown';
              // Check expiry
              const expiry = new Date(cert.valid_to);
              if (expiry < new Date()) {
                sslValid  = false;
                certIssuer += ' [EXPIRED]';
              }
            } else {
              sslValid  = false;
              certIssuer = 'No Certificate';
            }
          } catch {
            sslValid  = false;
            certIssuer = 'Certificate Error';
          }
        });
      });

      req.on('error', (err) => {
        // TLS errors indicate invalid cert
        if (err.code === 'CERT_HAS_EXPIRED' || err.code === 'DEPTH_ZERO_SELF_SIGNED_CERT' ||
            err.code === 'SELF_SIGNED_CERT_IN_CHAIN' || err.code === 'ERR_TLS_CERT_ALTNAME_INVALID' ||
            err.message?.includes('certificate')) {
          sslValid  = false;
          certIssuer = err.code || 'Invalid Certificate';
        }
        resolve({
          sslValid:           sslValid,
          certificateIssuer:  certIssuer,
          headers:            {},
          redirects:          redirectCount,
        });
      });

      req.on('timeout', () => {
        req.destroy();
        resolve({
          sslValid:           sslValid,
          certificateIssuer:  certIssuer || 'Timeout',
          headers:            {},
          redirects:          redirectCount,
        });
      });

      req.end();
    };

    request(targetUrl);
  });
}

module.exports = { scanUrl };
