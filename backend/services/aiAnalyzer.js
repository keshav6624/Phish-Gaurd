/**
 * AI Forensic Analyzer Service
 * Uses Google Gemini Pro via @google/generative-ai SDK
 * Generates human-readable forensic security analysis
 *
 * SECURITY: API key is loaded from server-side .env ONLY
 * and is NEVER sent to or exposed in the frontend.
 */

'use strict';

const { GoogleGenerativeAI } = require('@google/generative-ai');

// Lazily initialize the client to avoid crash on missing key at startup
let genAI  = null;
let model  = null;

function getModel() {
  if (!model) {
    const apiKey = process.env.GEMINI_API_KEY;
    if (!apiKey) {
      throw new Error('GEMINI_API_KEY is not set in environment variables.');
    }
    genAI = new GoogleGenerativeAI(apiKey);
    model = genAI.getGenerativeModel({
      model: 'gemini-1.5-flash-pro', // Use flash for speed; swap to gemini-1.5-pro for depth
      generationConfig: {
        temperature:     0.3,  // Low temperature = consistent, factual responses
        maxOutputTokens: 600,
        topK:            10,
        topP:            0.8,
      },
      safetySettings: [
        // Allow security-related content
        { category: 'HARM_CATEGORY_HARASSMENT',        threshold: 'BLOCK_ONLY_HIGH' },
        { category: 'HARM_CATEGORY_HATE_SPEECH',       threshold: 'BLOCK_ONLY_HIGH' },
        { category: 'HARM_CATEGORY_DANGEROUS_CONTENT', threshold: 'BLOCK_ONLY_HIGH' },
        { category: 'HARM_CATEGORY_SEXUALLY_EXPLICIT', threshold: 'BLOCK_ONLY_HIGH' },
      ],
    });
  }
  return model;
}

// ─── MAIN AI ANALYZE FUNCTION ─────────────────────────────
async function aiAnalyze({ type, target, scanData }) {
  // If no API key, return a rule-based fallback analysis
  if (!process.env.GEMINI_API_KEY) {
    console.warn('[AI] GEMINI_API_KEY not set – using fallback analysis.');
    return { analysis: buildFallbackAnalysis(type, scanData) };
  }

  const prompt = buildPrompt(type, target, scanData);

  try {
    const m      = getModel();
    const result = await m.generateContent(prompt);
    const text   = result.response.text();

    if (!text || text.trim().length < 20) {
      return { analysis: buildFallbackAnalysis(type, scanData) };
    }

    return { analysis: text.trim() };

  } catch (err) {
    console.error('[AI Error]', err.message);
    // Never crash the scan because of AI failure – return fallback
    return { analysis: buildFallbackAnalysis(type, scanData) };
  }
}

// ─── PROMPT BUILDER ───────────────────────────────────────
function buildPrompt(type, target, scanData) {
  const {
    threatScore, dnsStatus, sslValid, certificateIssuer,
    redirects, suspiciousKeywords = [], riskFactors = [], extractedUrls = [],
  } = scanData;

  const sharedContext = `
Threat Score: ${threatScore}/100
DNS Status: ${dnsStatus}
SSL Valid: ${sslValid === true ? 'Yes' : sslValid === false ? 'No' : 'N/A'}
Certificate Issuer: ${certificateIssuer || 'N/A'}
Redirects: ${redirects}
Suspicious Indicators: ${suspiciousKeywords.slice(0, 15).join(', ') || 'None'}
Risk Factors Detected: 
${riskFactors.slice(0, 10).map(f => `  - ${f}`).join('\n') || '  None'}
`.trim();

  if (type === 'url') {
    return `You are a senior cybersecurity analyst specializing in phishing forensics and threat intelligence. Analyze this URL scan report and provide a concise, expert forensic assessment.

TARGET URL: ${target}

SCAN DATA:
${sharedContext}

INSTRUCTIONS:
- Write 3-4 paragraphs of forensic analysis
- Explain WHY each detected risk factor is dangerous (not just what it is)
- Reference specific phishing attack techniques by name (e.g., IDN homograph attack, typosquatting, SSL stripping, redirect chain obfuscation)
- Conclude with a clear risk verdict and recommended user action
- Write as a professional forensic analyst, not as a generic chatbot
- Do NOT use markdown headers or bullet points in your response
- Be specific to the data provided, not generic`;

  } else {
    return `You are a senior cybersecurity analyst specializing in phishing email forensics and social engineering. Analyze this email scan report.

EMAIL EXCERPT: ${target.substring(0, 500)}

SCAN DATA:
${sharedContext}
Extracted URLs: ${extractedUrls.join(', ') || 'None'}

INSTRUCTIONS:
- Write 3-4 paragraphs of forensic analysis
- Explain the specific social engineering tactics used (urgency manipulation, authority impersonation, fear-based CTAs, credential harvesting)
- Reference attacker TTPs by name (e.g., BEC attack, vishing setup, advance-fee fraud, credential phishing)
- Identify which keywords/phrases are most dangerous and why
- Conclude with a clear risk verdict and recommended user action
- Write as a professional forensic analyst, not as a generic chatbot
- Do NOT use markdown headers or bullet points in your response
- Be specific to the data provided, not generic`;
  }
}

// ─── RULE-BASED FALLBACK ANALYSIS ────────────────────────
function buildFallbackAnalysis(type, scanData) {
  const { threatScore, suspiciousKeywords = [], riskFactors = [], dnsStatus, sslValid } = scanData;
  let level = threatScore <= 30 ? 'LOW RISK' : threatScore <= 65 ? 'MODERATE RISK' : 'HIGH RISK';

  let analysis = `[AI Forensic Analysis – Rule-Based Fallback]\n\n`;
  analysis += `Threat Assessment: ${level} (Score: ${threatScore}/100)\n\n`;

  if (riskFactors.length > 0) {
    analysis += `Key Risk Factors Identified:\n`;
    riskFactors.slice(0, 6).forEach(f => { analysis += `• ${f}\n`; });
    analysis += '\n';
  }

  if (!sslValid && sslValid !== null) {
    analysis += `SSL Certificate Issue: The target lacks a valid SSL certificate. This is a critical red flag – legitimate services always use HTTPS with certificates from trusted Certificate Authorities (CAs). An invalid or missing certificate may indicate an SSL stripping attack or a quickly-spun-up phishing infrastructure.\n\n`;
  }

  if (dnsStatus === 'UNRESOLVED') {
    analysis += `DNS Resolution Failure: The domain could not be resolved. This may indicate a recently registered phishing domain, a typosquatted domain designed to trap users who type URLs, or a domain that has already been taken down by registrars due to abuse reports.\n\n`;
  }

  if (suspiciousKeywords.length > 0) {
    analysis += `Social Engineering Indicators: The presence of keywords such as "${suspiciousKeywords.slice(0,3).join('", "')}" are hallmarks of social engineering and phishing attacks. Threat actors use urgency, fear, and authority impersonation to bypass rational decision-making and force immediate action.\n\n`;
  }

  analysis += `Recommendation: ${
    threatScore <= 30
      ? 'No significant threats detected. This appears to be a legitimate target, but always exercise caution.'
      : threatScore <= 65
      ? 'Multiple risk indicators detected. Do NOT provide credentials or personal information. Verify legitimacy through official channels.'
      : 'HIGH PROBABILITY PHISHING. Do NOT click links, provide credentials, or download attachments. Report this to your security team and relevant authorities.'
  }`;

  return analysis;
}

module.exports = { aiAnalyze };
