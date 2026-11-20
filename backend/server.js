/**
 * PHISH-GUARD – Express Backend Server
 * Production-grade Node.js security auditor
 *
 * Architecture:
 *   POST /scan-url   → DNS + SSL + Headers + AI analysis
 *   POST /scan-email → Keyword extraction + URL scan + AI analysis
 */

'use strict';

require('dotenv').config();

const express        = require('express');
const cors           = require('cors');
const helmet         = require('helmet');
const rateLimit      = require('express-rate-limit');
const validator      = require('validator');

const { scanUrl }    = require('./services/urlScanner');
const { scanEmail }  = require('./services/emailScanner');
const { aiAnalyze }  = require('./services/aiAnalyzer');

const app  = express();
const PORT = process.env.PORT || 3000;

// ─── SECURITY MIDDLEWARE ───────────────────────────────────

// Helmet adds security-relevant HTTP headers
app.use(helmet({
  crossOriginResourcePolicy: { policy: 'cross-origin' },
}));

// CORS – restrict to allowed origins in production
const allowedOrigins = (process.env.ALLOWED_ORIGINS || 'http://localhost:5500,http://127.0.0.1:5500,http://localhost:3001')
  .split(',')
  .map(s => s.trim());

app.use(cors({
  origin: (origin, callback) => {
    // Allow requests with no origin (same-origin, curl, Postman) in dev
    if (!origin || process.env.NODE_ENV !== 'production') return callback(null, true);
    if (allowedOrigins.includes(origin)) return callback(null, true);
    return callback(new Error(`CORS: origin ${origin} not allowed`));
  },
  methods:          ['POST', 'OPTIONS'],
  allowedHeaders:   ['Content-Type'],
  optionsSuccessStatus: 200,
}));

// Parse JSON bodies (max 50kb to prevent DoS)
app.use(express.json({ limit: '50kb' }));
app.use(express.urlencoded({ extended: false, limit: '50kb' }));

// ─── RATE LIMITING ─────────────────────────────────────────
// General limiter: 100 requests per 15 min per IP
const generalLimiter = rateLimit({
  windowMs:   15 * 60 * 1000,
  max:        100,
  standardHeaders: true,
  legacyHeaders:   false,
  message:    { error: 'Too many requests. Please try again later.' },
});

// Scan limiter: 20 scans per 5 min per IP (AI calls are expensive)
const scanLimiter = rateLimit({
  windowMs:   5 * 60 * 1000,
  max:        20,
  standardHeaders: true,
  legacyHeaders:   false,
  message:    { error: 'Scan rate limit reached. Wait 5 minutes.' },
});

app.use(generalLimiter);

// ─── HEALTH CHECK ──────────────────────────────────────────
app.get('/health', (req, res) => {
  res.json({
    status:  'ok',
    service: 'phish-guard-backend',
    version: '2.0.0',
    time:    new Date().toISOString(),
  });
});

// ─── POST /scan-url ────────────────────────────────────────
app.post('/scan-url', scanLimiter, async (req, res) => {
  try {
    const { url } = req.body;

    // ── Input Validation & Sanitization ──
    if (!url || typeof url !== 'string') {
      return res.status(400).json({ error: 'Missing required field: url' });
    }

    const sanitized = url.trim().substring(0, 2048); // max URL length

    if (!validator.isURL(sanitized, {
      protocols:       ['http', 'https'],
      require_protocol: true,
      allow_underscores: true,
    })) {
      return res.status(400).json({ error: 'Invalid URL format. Must start with http:// or https://' });
    }

    // Block localhost / private ranges in production
    if (process.env.NODE_ENV === 'production') {
      const hostname = new URL(sanitized).hostname;
      if (/^(localhost|127\.|10\.|192\.168\.|172\.(1[6-9]|2\d|3[0-1])\.|0\.0\.0\.0)/.test(hostname)) {
        return res.status(400).json({ error: 'Scanning private/local addresses is not allowed.' });
      }
    }

    console.log(`[ScanURL] ${new Date().toISOString()} | ${sanitized} | IP: ${req.ip}`);

    // ── Perform Security Analysis ──
    const scanData = await scanUrl(sanitized);

    // ── AI Forensic Analysis ──
    const aiResult = await aiAnalyze({
      type:      'url',
      target:    sanitized,
      scanData,
    });

    // ── Build Response ──
    const response = {
      threatScore:        scanData.threatScore,
      dnsStatus:          scanData.dnsStatus,
      sslValid:           scanData.sslValid,
      certificateIssuer:  scanData.certificateIssuer,
      redirects:          scanData.redirects,
      suspiciousKeywords: scanData.suspiciousKeywords,
      httpHeaders:        scanData.httpHeaders,
      aiAnalysis:         aiResult.analysis,
      scanId:             generateScanId(),
      timestamp:          new Date().toISOString(),
    };

    return res.json(response);

  } catch (err) {
    console.error('[ScanURL Error]', err.message);
    return res.status(500).json({
      error:   'Scan failed. The target may be unreachable.',
      details: process.env.NODE_ENV !== 'production' ? err.message : undefined,
    });
  }
});

// ─── POST /scan-email ──────────────────────────────────────
app.post('/scan-email', scanLimiter, async (req, res) => {
  try {
    const { emailContent } = req.body;

    // ── Input Validation & Sanitization ──
    if (!emailContent || typeof emailContent !== 'string') {
      return res.status(400).json({ error: 'Missing required field: emailContent' });
    }
    if (emailContent.trim().length < 20) {
      return res.status(400).json({ error: 'Email content too short to analyze.' });
    }
    // Limit email size
    const sanitized = emailContent.trim().substring(0, 50000);

    console.log(`[ScanEmail] ${new Date().toISOString()} | ${sanitized.length} chars | IP: ${req.ip}`);

    // ── Perform Email Analysis ──
    const scanData = await scanEmail(sanitized);

    // ── AI Forensic Analysis ──
    const aiResult = await aiAnalyze({
      type:      'email',
      target:    sanitized.substring(0, 1000), // send first 1000 chars for AI context
      scanData,
    });

    // ── Build Response ──
    const response = {
      threatScore:        scanData.threatScore,
      dnsStatus:          scanData.dnsStatus,
      sslValid:           scanData.sslValid,
      certificateIssuer:  scanData.certificateIssuer,
      redirects:          scanData.redirects,
      suspiciousKeywords: scanData.suspiciousKeywords,
      extractedUrls:      scanData.extractedUrls,
      aiAnalysis:         aiResult.analysis,
      scanId:             generateScanId(),
      timestamp:          new Date().toISOString(),
    };

    return res.json(response);

  } catch (err) {
    console.error('[ScanEmail Error]', err.message);
    return res.status(500).json({
      error:   'Email scan failed.',
      details: process.env.NODE_ENV !== 'production' ? err.message : undefined,
    });
  }
});

// ─── 404 HANDLER ───────────────────────────────────────────
app.use((req, res) => {
  res.status(404).json({ error: 'Endpoint not found.' });
});

// ─── GLOBAL ERROR HANDLER ──────────────────────────────────
app.use((err, req, res, _next) => {
  console.error('[GlobalError]', err.message);
  res.status(500).json({ error: 'Internal server error.' });
});

// ─── UTILS ─────────────────────────────────────────────────
function generateScanId() {
  return 'SID-' + Date.now().toString(36).toUpperCase() + '-' +
    Math.random().toString(36).substring(2, 6).toUpperCase();
}

// ─── START SERVER ──────────────────────────────────────────
app.listen(PORT, () => {
  console.log(`
╔══════════════════════════════════════════╗
║  PHISH-GUARD Backend v2.0                ║
║  Server running on port ${PORT}              ║
║  Environment: ${(process.env.NODE_ENV || 'development').padEnd(26)}║
║  AI Engine: Gemini Pro                   ║
╚══════════════════════════════════════════╝
  `);
});

module.exports = app; // for testing
