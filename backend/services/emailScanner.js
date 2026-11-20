/**
 * Email Scanner Service
 * Performs: keyword detection, URL extraction,
 * header analysis, urgency/social-engineering pattern detection
 */

'use strict';

const { scanUrl } = require('./urlScanner');

// ─── SUSPICIOUS KEYWORDS ──────────────────────────────────
// Each entry: { pattern, weight, category }
const PHISHING_KEYWORDS = [
  // Urgency / pressure tactics
  { pattern: /urgent/gi,                weight: 8,  category: 'urgency' },
  { pattern: /act\s+now/gi,             weight: 8,  category: 'urgency' },
  { pattern: /immediately/gi,           weight: 7,  category: 'urgency' },
  { pattern: /limited\s+time/gi,        weight: 7,  category: 'urgency' },
  { pattern: /expires?\s+soon/gi,       weight: 7,  category: 'urgency' },
  { pattern: /within\s+\d+\s+hours/gi,  weight: 9,  category: 'urgency' },
  { pattern: /24\s+hours/gi,            weight: 6,  category: 'urgency' },

  // Account threats
  { pattern: /account\s+suspended/gi,   weight: 15, category: 'account-threat' },
  { pattern: /account\s+(will\s+be\s+)?terminated/gi, weight: 15, category: 'account-threat' },
  { pattern: /suspended/gi,             weight: 10, category: 'account-threat' },
  { pattern: /unusual\s+activity/gi,    weight: 10, category: 'account-threat' },
  { pattern: /unauthorized\s+access/gi, weight: 10, category: 'account-threat' },
  { pattern: /your\s+account\s+has\s+been/gi, weight: 12, category: 'account-threat' },

  // Credential harvesting CTAs
  { pattern: /click\s+here/gi,          weight: 10, category: 'cta-phishing' },
  { pattern: /verify\s+(now|your|account|identity)/gi, weight: 12, category: 'cta-phishing' },
  { pattern: /confirm\s+(your|now|identity|account)/gi, weight: 10, category: 'cta-phishing' },
  { pattern: /update\s+(your\s+)?payment/gi, weight: 15, category: 'cta-phishing' },
  { pattern: /enter\s+your\s+(details|credentials|password)/gi, weight: 15, category: 'cta-phishing' },
  { pattern: /reset\s+your\s+password/gi, weight: 8, category: 'cta-phishing' },
  { pattern: /login\s+immediately/gi,   weight: 12, category: 'cta-phishing' },

  // Financial lures
  { pattern: /prize/gi,                 weight: 8,  category: 'lure' },
  { pattern: /free\s+gift/gi,           weight: 10, category: 'lure' },
  { pattern: /you\s+have\s+won/gi,      weight: 12, category: 'lure' },
  { pattern: /congratulations/gi,       weight: 5,  category: 'lure' },
  { pattern: /tax\s+refund/gi,          weight: 10, category: 'lure' },
  { pattern: /wire\s+transfer/gi,       weight: 12, category: 'bec' },
  { pattern: /invoice\s+attached/gi,    weight: 10, category: 'bec' },
  { pattern: /bank\s+account/gi,        weight: 8,  category: 'financial' },

  // PII harvesting
  { pattern: /social\s+security/gi,     weight: 15, category: 'pii' },
  { pattern: /credit\s+card/gi,         weight: 10, category: 'pii' },
  { pattern: /date\s+of\s+birth/gi,     weight: 8,  category: 'pii' },
  { pattern: /mother'?s?\s+maiden/gi,   weight: 10, category: 'pii' },

  // Generic impersonation signals
  { pattern: /dear\s+customer/gi,       weight: 8,  category: 'impersonation' },
  { pattern: /dear\s+user/gi,           weight: 6,  category: 'impersonation' },
  { pattern: /dear\s+member/gi,         weight: 6,  category: 'impersonation' },
  { pattern: /password\s+expired/gi,    weight: 10, category: 'account-threat' },
];

// Regex to extract URLs from email body
const URL_REGEX = /https?:\/\/[^\s<>"'\]\[{}|\\^`]+/gi;

// Regex to extract email sender
const FROM_REGEX = /^from:\s*(.+)$/im;

// ─── MAIN EMAIL SCAN FUNCTION ─────────────────────────────
async function scanEmail(emailContent) {
  let threatScore        = 0;
  const suspiciousKeywords = [];
  const riskFactors        = [];

  // ── 1. Keyword Detection ──────────────────────────────
  const foundKeywords = new Set();
  PHISHING_KEYWORDS.forEach(({ pattern, weight, category }) => {
    const matches = emailContent.match(pattern);
    if (matches) {
      matches.forEach(m => foundKeywords.add(m.toLowerCase().trim()));
      threatScore += weight;
      riskFactors.push(`[${category.toUpperCase()}] Pattern detected: "${matches[0]}"`);
    }
  });
  suspiciousKeywords.push(...Array.from(foundKeywords));

  // ── 2. URL Extraction ─────────────────────────────────
  const rawUrls = emailContent.match(URL_REGEX) || [];
  // Deduplicate and limit to 5 URLs to avoid abuse
  const extractedUrls = [...new Set(rawUrls)].slice(0, 5);

  // ── 3. URL Count heuristic ────────────────────────────
  if (extractedUrls.length > 3) {
    threatScore += 10;
    riskFactors.push(`Excessive link count (${extractedUrls.length}) – mass phishing indicator`);
  }

  // ── 4. Mismatch: display text vs href ─────────────────
  const hrefMismatch = /<a[^>]+href=["']([^"']+)["'][^>]*>([^<]+)<\/a>/gi;
  let mismatchMatch;
  while ((mismatchMatch = hrefMismatch.exec(emailContent)) !== null) {
    const href    = mismatchMatch[1];
    const display = mismatchMatch[2].trim();
    if (display.startsWith('http') && !href.includes(display.replace(/https?:\/\//,''))) {
      threatScore += 15;
      riskFactors.push(`Link text/href mismatch: displays "${display}" but links to "${href}"`);
      suspiciousKeywords.push('href-mismatch');
    }
  }

  // ── 5. Sender domain analysis ─────────────────────────
  const fromMatch = emailContent.match(FROM_REGEX);
  if (fromMatch) {
    const fromHeader = fromMatch[1];
    const senderResult = analyzeSender(fromHeader);
    if (senderResult.suspicious) {
      threatScore += senderResult.weight;
      riskFactors.push(...senderResult.reasons);
      senderResult.keywords.forEach(k => suspiciousKeywords.push(k));
    }
  }

  // ── 6. Scan embedded URLs (up to 3 to stay fast) ─────
  let urlScanSummary = {};
  const urlsToScan  = extractedUrls.slice(0, 3);
  let urlMaxScore   = 0;
  let dnsStatus     = 'N/A';
  let sslValid      = null;
  let certIssuer    = 'N/A';
  let redirects     = 0;

  for (const u of urlsToScan) {
    try {
      const result = await scanUrl(u);
      if (result.threatScore > urlMaxScore) {
        urlMaxScore = result.threatScore;
        dnsStatus   = result.dnsStatus;
        sslValid    = result.sslValid;
        certIssuer  = result.certificateIssuer;
        redirects   = result.redirects;
        urlScanSummary = result;
      }
      // Add URL keywords to overall list
      if (result.suspiciousKeywords?.length) {
        result.suspiciousKeywords.forEach(k => suspiciousKeywords.push(`[url] ${k}`));
      }
      if (result.riskFactors?.length) {
        result.riskFactors.forEach(f => riskFactors.push(`[url:${u}] ${f}`));
      }
    } catch {
      // URL scan failed – treat as suspicious
      threatScore += 5;
    }
  }

  // Blend URL threat score into overall score (50% weight for URLs)
  if (urlMaxScore > 0) {
    threatScore += Math.round(urlMaxScore * 0.5);
  }

  // Clamp to 0–100
  threatScore = Math.min(100, Math.max(0, threatScore));

  return {
    threatScore,
    dnsStatus,
    sslValid,
    certificateIssuer: certIssuer,
    redirects,
    suspiciousKeywords: [...new Set(suspiciousKeywords)],
    extractedUrls,
    riskFactors,
    urlScanSummary,
  };
}

// ─── SENDER ANALYSIS ──────────────────────────────────────
function analyzeSender(fromHeader) {
  const result = {
    suspicious: false,
    weight:     0,
    reasons:    [],
    keywords:   [],
  };

  // Extract email address
  const emailMatch = fromHeader.match(/[a-zA-Z0-9._%+\-]+@([a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})/);
  if (!emailMatch) return result;

  const emailAddr  = emailMatch[0].toLowerCase();
  const domain     = emailMatch[1].toLowerCase();

  // Homoglyph / typosquat patterns in sender domain
  const BRAND_DOMAINS = [
    ['paypal.com', 'paypa1', 'paypai', 'paypa1.com', 'pay-pal.com'],
    ['apple.com', 'appl3.com', 'apple-support.com', 'applesupport.com'],
    ['microsoft.com', 'micros0ft.com', 'microsoft-support.com'],
    ['amazon.com', 'amaz0n.com', 'amazon-security.com'],
    ['google.com', 'g00gle.com', 'google-security.com'],
    ['netflix.com', 'netfl1x.com', 'netflix-support.com'],
    ['irs.gov', 'irs-refund.com', 'irs.com'],
    ['chase.com', 'chase-bank.com', 'chasesecure.com'],
    ['bankofamerica.com', 'bankofamerica-security.com'],
  ];

  BRAND_DOMAINS.forEach(([real, ...fakes]) => {
    fakes.forEach(fake => {
      if (domain.includes(fake.replace('.com','')) && domain !== real) {
        result.suspicious = true;
        result.weight    += 30;
        result.reasons.push(`Sender domain "${domain}" impersonates ${real} (typosquatting/homoglyph)`);
        result.keywords.push(`sender-spoof:${real}`);
      }
    });
    // Check if sender claims to be a brand but domain doesn't match
    const brandName = real.split('.')[0];
    if (fromHeader.toLowerCase().includes(brandName) && !domain.endsWith(real)) {
      result.suspicious = true;
      result.weight    += 20;
      result.reasons.push(`Display name claims to be "${brandName}" but domain is "${domain}"`);
      result.keywords.push('sender-display-spoof');
    }
  });

  // Free email providers sending "official" communications
  const FREE_PROVIDERS = ['gmail.com','yahoo.com','hotmail.com','outlook.com','aol.com','protonmail.com'];
  if (FREE_PROVIDERS.some(p => domain === p)) {
    // Check if the display name claims to be a business
    if (/support|security|service|team|official|alert|noreply|no-reply/i.test(fromHeader)) {
      result.suspicious = true;
      result.weight    += 15;
      result.reasons.push(`Official-sounding sender name from free email provider "${domain}"`);
      result.keywords.push('free-provider-impersonation');
    }
  }

  // Random-looking local part (bot-generated)
  const localPart = emailAddr.split('@')[0];
  if (/^[a-z0-9]{20,}$/.test(localPart) || /^\d{10,}@/.test(emailAddr)) {
    result.suspicious = true;
    result.weight    += 10;
    result.reasons.push('Random/bot-generated sender address detected');
    result.keywords.push('bot-sender');
  }

  return result;
}

module.exports = { scanEmail };
