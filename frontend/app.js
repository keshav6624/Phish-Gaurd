/**
 * PHISH-GUARD – Frontend Application Logic
 * Production-grade Vanilla JS
 * Uses fetch API (AJAX) to communicate with Express backend
 */

'use strict';

// ─── CONFIG ───────────────────────────────────────────────
const API_BASE = 'http://localhost:3000'; // Change to your deployed backend URL

// Keyword tooltips – explain WHY each phrase is dangerous
const KEYWORD_TOOLTIPS = {
  'urgent':             'Creates artificial time pressure to bypass rational thinking.',
  'verify now':         'Phishing tactic: forces immediate action before victim can verify legitimacy.',
  'account suspended':  'Fear-inducing claim used to trick users into clicking malicious links.',
  'click here':         'Vague call-to-action that hides the true destination URL.',
  'update payment':     'Harvests financial credentials by impersonating legitimate services.',
  'confirm your':       'Credential harvesting tactic that mimics account verification flows.',
  'limited time':       'Urgency tactic designed to pressure victims into hasty decisions.',
  'verify your account':'Classic phishing lure used in banking and email account attacks.',
  'suspended':          'Triggers fear of losing access, prompting impulsive link clicks.',
  'unusual activity':   'Mimics legitimate security alerts to trick users into re-authentication.',
  'login immediately':  'Forces immediate action; used in credential phishing campaigns.',
  'password expired':   'Forces re-authentication on a fake page to steal credentials.',
  'dear customer':      'Generic salutation indicating a mass phishing campaign without personalization.',
  'free gift':          'Lure tactic used to steal personal information in exchange for false rewards.',
  'you have won':       'Classic social engineering bait used in advance-fee and lottery scams.',
  'wire transfer':      'Associated with BEC (Business Email Compromise) financial fraud.',
  'act now':            'Pressure tactic that discourages deliberate verification.',
  'prize':              'Associated with advance-fee fraud and personal data harvesting.',
  'bank account':       'Targets financial credentials in credential harvesting campaigns.',
  'social security':    'High-value PII targeted in government impersonation phishing.',
  'tax refund':         'Common lure in IRS/HMRC impersonation phishing attacks.',
  'invoice attached':   'Common BEC vector; malicious attachments can deliver malware.',
  'reset your password':'Account takeover vector; redirects to credential harvesting pages.',
};

// ─── STATE ─────────────────────────────────────────────────
let currentTab = 'url';
let lastResult = null;

// ─── TAB SWITCHING ──────────────────────────────────────────
function switchTab(tab) {
  currentTab = tab;
  document.querySelectorAll('.tab').forEach(t => {
    t.classList.toggle('active', t.dataset.tab === tab);
  });
  document.querySelectorAll('.tab-content').forEach(c => {
    c.classList.toggle('active', c.id === `tab-${tab}`);
  });
}

// ─── CLEAR INPUT ───────────────────────────────────────────
function clearInput(id) {
  document.getElementById(id).value = '';
  document.getElementById(id).focus();
}

// ─── TOGGLE COLLAPSIBLE SECTIONS ───────────────────────────
function toggleSection(bodyId) {
  const body = document.getElementById(bodyId);
  const collapsed = body.classList.toggle('collapsed');
  // Find collapse icon sibling
  const collapseIcon = body.previousElementSibling?.querySelector('.collapse-icon');
  if (collapseIcon) collapseIcon.classList.toggle('up', collapsed);
}

// ─── SHOW / HIDE PANELS ────────────────────────────────────
function showPanel(id) {
  ['results-empty', 'results-scanning', 'results-data'].forEach(p => {
    document.getElementById(p).classList.toggle('hidden', p !== id);
  });
}

// ─── PROGRESS ANIMATION ────────────────────────────────────
let progressInterval = null;
const STEP_SEQUENCE = ['step-dns', 'step-ssl', 'step-headers', 'step-keywords', 'step-ai'];
const STEP_LABELS   = {
  'step-dns':      ['RESOLVING...', 'RESOLVED'],
  'step-ssl':      ['VALIDATING...','VALIDATED'],
  'step-headers':  ['INSPECTING...','INSPECTED'],
  'step-keywords': ['SCANNING...', 'SCANNED'],
  'step-ai':       ['ANALYZING...', 'COMPLETE'],
};
const STEP_PERCENTS = [10, 28, 48, 68, 90];

function animateProgress(targetPercent, onDone) {
  const bar     = document.getElementById('progress-bar');
  const pct     = document.getElementById('progress-percent');
  let current   = parseInt(bar.style.width) || 0;
  clearInterval(progressInterval);

  progressInterval = setInterval(() => {
    if (current < targetPercent) {
      current = Math.min(current + 1, targetPercent);
      bar.style.width = current + '%';
      pct.textContent  = current + '%';
    } else {
      clearInterval(progressInterval);
      if (onDone) onDone();
    }
  }, 18);
}

function setStepState(stepId, state /* 'active'|'done'|'error' */) {
  const el      = document.getElementById(stepId);
  const dotEl   = el.querySelector('.step-dot');
  const statEl  = el.querySelector('.step-status');
  const labels  = STEP_LABELS[stepId];

  el.className  = 'step ' + state;

  if (state === 'active') {
    dotEl.textContent  = '◌';
    statEl.textContent = labels[0];
  } else if (state === 'done') {
    dotEl.textContent  = '●';
    statEl.textContent = labels[1];
  } else if (state === 'error') {
    dotEl.textContent  = '✕';
    statEl.textContent = 'FAILED';
  }
}

// Fake animated step progression (visual feedback while waiting for API)
function runScanAnimation(doneCallback) {
  let step = 0;
  STEP_SEQUENCE.forEach(s => setStepState(s, ''));

  function next() {
    if (step > 0) setStepState(STEP_SEQUENCE[step - 1], 'done');
    if (step < STEP_SEQUENCE.length) {
      setStepState(STEP_SEQUENCE[step], 'active');
      animateProgress(STEP_PERCENTS[step], () => {
        step++;
        if (step < STEP_SEQUENCE.length) {
          setTimeout(next, 400 + Math.random() * 300);
        } else {
          // Hold at 90% until real response
        }
      });
    }
  }
  next();
}

// ─── SCAN ENTRY POINT ──────────────────────────────────────
async function startScan() {
  const scanBtn = document.getElementById('scan-btn');

  // Collect input based on active tab
  let input, type;
  if (currentTab === 'url') {
    input = document.getElementById('url-input').value.trim();
    type  = 'url';
    if (!input) { showToast('⚠ Please enter a URL to scan.'); return; }
    if (!input.startsWith('http://') && !input.startsWith('https://')) {
      input = 'https://' + input;
      document.getElementById('url-input').value = input;
    }
  } else {
    input = document.getElementById('email-input').value.trim();
    type  = 'email';
    if (!input) { showToast('⚠ Please paste email content to scan.'); return; }
    if (input.length < 20) { showToast('⚠ Email content too short to analyze.'); return; }
  }

  // UI: show scanning state
  scanBtn.classList.add('loading');
  scanBtn.querySelector('.scan-btn-text').textContent = 'SCANNING...';

  const scanId = 'SID-' + Math.floor(Math.random() * 999999).toString().padStart(6, '0');
  document.getElementById('scan-id').textContent = scanId;
  document.getElementById('scan-target-display').textContent = input.length > 80
    ? input.substring(0, 80) + '...' : input;

  // Reset progress
  document.getElementById('progress-bar').style.width = '0%';
  document.getElementById('progress-percent').textContent = '0%';

  showPanel('results-scanning');
  runScanAnimation();

  try {
    const endpoint = type === 'url' ? '/scan-url' : '/scan-email';
    const body     = type === 'url' ? { url: input } : { emailContent: input };

    const res = await fetch(`${API_BASE}${endpoint}`, {
      method:  'POST',
      headers: { 'Content-Type': 'application/json' },
      body:    JSON.stringify(body),
    });

    if (!res.ok) {
      const err = await res.json().catch(() => ({ error: 'Server error' }));
      throw new Error(err.error || `HTTP ${res.status}`);
    }

    const data = await res.json();
    lastResult = { ...data, input, type };

    // Complete all steps visually
    STEP_SEQUENCE.forEach(s => setStepState(s, 'done'));
    animateProgress(100, () => {
      setTimeout(() => renderResults(data, type, input), 600);
    });

  } catch (err) {
    // Mark last active step as error
    const activeStep = document.querySelector('.step.active');
    if (activeStep) activeStep.className = 'step error';
    document.querySelector('.step.active .step-status')?.textContent;
    showToast(`⚠ Error: ${err.message}`);
    console.error('[PhishGuard] Scan error:', err);
    // Return to empty state after delay
    setTimeout(resetScan, 3000);
  } finally {
    scanBtn.classList.remove('loading');
    scanBtn.querySelector('.scan-btn-text').textContent = 'INITIATE SECURITY SCAN';
  }
}

// ─── RENDER RESULTS ────────────────────────────────────────
function renderResults(data, type, originalInput) {
  const { threatScore, dnsStatus, sslValid, certificateIssuer,
          redirects, suspiciousKeywords, aiAnalysis } = data;

  // ── Threat Meter ──
  animateMeter(threatScore);
  document.getElementById('threat-score-number').textContent = threatScore;

  // Verdict
  const badge  = document.getElementById('verdict-badge');
  const detail = document.getElementById('verdict-detail');
  if (threatScore <= 30) {
    badge.textContent  = '✓ SAFE';
    badge.className    = 'verdict-badge safe';
    detail.textContent = 'No significant threats detected. Exercise standard caution.';
  } else if (threatScore <= 65) {
    badge.textContent  = '⚠ SUSPICIOUS';
    badge.className    = 'verdict-badge warn';
    detail.textContent = 'Multiple risk indicators detected. Proceed with extreme caution.';
  } else {
    badge.textContent  = '✕ DANGER';
    badge.className    = 'verdict-badge danger';
    detail.textContent = 'High probability phishing/malicious activity. Do not proceed.';
  }

  // ── Stats Grid ──
  const dnsEl       = document.getElementById('stat-dns-val');
  const sslEl       = document.getElementById('stat-ssl-val');
  const issuerEl    = document.getElementById('stat-issuer-val');
  const redirectsEl = document.getElementById('stat-redirects-val');

  dnsEl.textContent = dnsStatus || 'N/A';
  dnsEl.className   = 'stat-value ' + (dnsStatus === 'RESOLVED' ? 'ok' : 'bad');

  sslEl.textContent = sslValid === true ? 'VALID' : sslValid === false ? 'INVALID' : 'N/A';
  sslEl.className   = 'stat-value ' + (sslValid === true ? 'ok' : sslValid === false ? 'bad' : '');

  issuerEl.textContent = certificateIssuer || 'N/A';
  issuerEl.className   = 'stat-value stat-small';

  const redCount = redirects || 0;
  redirectsEl.textContent = redCount;
  redirectsEl.className   = 'stat-value ' + (redCount === 0 ? 'ok' : redCount <= 2 ? 'warn' : 'bad');

  // ── Suspicious Keywords ──
  const kSection   = document.getElementById('keywords-section');
  const kContainer = document.getElementById('keywords-container');
  kContainer.innerHTML = '';

  if (suspiciousKeywords && suspiciousKeywords.length > 0) {
    kSection.style.display = '';
    suspiciousKeywords.forEach(kw => {
      const tag = document.createElement('span');
      tag.className = 'keyword-tag';
      const tooltip = KEYWORD_TOOLTIPS[kw.toLowerCase()] || 'Commonly found in phishing and social engineering attacks.';
      tag.innerHTML = `
        ⚠ ${escapeHtml(kw)}
        <span class="tooltip">${escapeHtml(tooltip)}</span>
      `;
      kContainer.appendChild(tag);
    });
  } else {
    kSection.style.display = 'none';
  }

  // ── Email highlighted body ──
  const emailSection = document.getElementById('email-body-section');
  if (type === 'email') {
    emailSection.style.display = '';
    const highlighted = highlightEmailContent(originalInput, suspiciousKeywords || []);
    document.getElementById('highlighted-email').innerHTML = highlighted;
  } else {
    emailSection.style.display = 'none';
  }

  // ── AI Analysis ──
  const aiContent = document.getElementById('ai-content');
  aiContent.textContent = aiAnalysis || 'No AI analysis available.';

  showPanel('results-data');
}

// ─── THREAT METER ANIMATION ────────────────────────────────
function animateMeter(score) {
  const arc    = document.getElementById('meter-arc');
  const needle = document.getElementById('meter-needle');
  const total  = 251.2; // arc perimeter

  // Color based on score
  let color;
  if (score <= 30)      color = '#00e676';  // safe
  else if (score <= 65) color = '#ffb830';  // warning
  else                  color = '#ff3860';  // danger

  arc.style.stroke = color;
  document.getElementById('threat-score-number').style.color = color;

  let current = 0;
  const interval = setInterval(() => {
    if (current >= score) { clearInterval(interval); return; }
    current = Math.min(current + 1, score);

    // Arc: offset from total down to (total - (current/100 * total))
    const offset = total - (current / 100) * total;
    arc.style.strokeDashoffset = offset;

    // Needle: from -90deg (left) to +90deg (right), centered at score 50
    const angle = (current / 100) * 180 - 90;
    needle.setAttribute('transform', `rotate(${angle}, 100, 100)`);
  }, 15);
}

// ─── HIGHLIGHT EMAIL CONTENT ───────────────────────────────
function highlightEmailContent(text, keywords) {
  let escaped = escapeHtml(text);

  // Highlight URLs first
  escaped = escaped.replace(
    /(https?:\/\/[^\s&quot;&lt;&gt;"']+)/gi,
    '<span class="highlight-url">$1</span>'
  );

  // Highlight suspicious keywords
  keywords.forEach(kw => {
    const tooltip = KEYWORD_TOOLTIPS[kw.toLowerCase()] || 'Phishing indicator';
    const safeKw  = escapeRegex(escapeHtml(kw));
    const re      = new RegExp(`(${safeKw})`, 'gi');
    escaped = escaped.replace(re, `<span class="highlight-keyword" title="${tooltip}">$1</span>`);
  });

  return escaped;
}

// ─── COPY REPORT ───────────────────────────────────────────
function copyReport() {
  if (!lastResult) return;
  const { threatScore, dnsStatus, sslValid, certificateIssuer,
          redirects, suspiciousKeywords, aiAnalysis, input, type } = lastResult;

  const report = `
PHISH-GUARD FORENSIC REPORT
=============================
Scan Type   : ${type.toUpperCase()}
Target      : ${input}
Threat Score: ${threatScore}/100
Verdict     : ${threatScore <= 30 ? 'SAFE' : threatScore <= 65 ? 'SUSPICIOUS' : 'DANGER'}

DNS Status  : ${dnsStatus || 'N/A'}
SSL Valid   : ${sslValid === true ? 'YES' : sslValid === false ? 'NO' : 'N/A'}
Cert Issuer : ${certificateIssuer || 'N/A'}
Redirects   : ${redirects || 0}

Suspicious Keywords: ${suspiciousKeywords?.join(', ') || 'None'}

AI FORENSIC ANALYSIS:
${aiAnalysis || 'N/A'}

Generated by PhishGuard v2.0 | ${new Date().toUTCString()}
`.trim();

  navigator.clipboard.writeText(report)
    .then(() => showToast('✓ Report copied to clipboard'))
    .catch(() => {
      // Fallback
      const ta = document.createElement('textarea');
      ta.value = report;
      document.body.appendChild(ta);
      ta.select();
      document.execCommand('copy');
      document.body.removeChild(ta);
      showToast('✓ Report copied to clipboard');
    });
}

// ─── RESET SCAN ────────────────────────────────────────────
function resetScan() {
  lastResult = null;
  document.getElementById('url-input').value   = '';
  document.getElementById('email-input').value = '';
  document.getElementById('progress-bar').style.width = '0%';
  document.getElementById('progress-percent').textContent = '0%';
  STEP_SEQUENCE.forEach(s => {
    const el = document.getElementById(s);
    el.className = 'step';
    el.querySelector('.step-dot').textContent    = '○';
    el.querySelector('.step-status').textContent = 'PENDING';
  });
  showPanel('results-empty');
}

// ─── TOAST NOTIFICATION ────────────────────────────────────
function showToast(msg) {
  const existing = document.querySelector('.toast');
  if (existing) existing.remove();

  const toast = document.createElement('div');
  toast.className   = 'toast';
  toast.textContent = msg;
  document.body.appendChild(toast);
  setTimeout(() => toast.remove(), 2200);
}

// ─── UTILITIES ─────────────────────────────────────────────
function escapeHtml(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

function escapeRegex(str) {
  return str.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

// ─── KEYBOARD SHORTCUT ─────────────────────────────────────
document.addEventListener('keydown', e => {
  // Ctrl+Enter or Cmd+Enter to start scan
  if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
    startScan();
  }
  // Escape to reset
  if (e.key === 'Escape') {
    resetScan();
  }
});

// Enter key in URL input
document.getElementById('url-input')?.addEventListener('keydown', e => {
  if (e.key === 'Enter') startScan();
});

// ─── INIT ──────────────────────────────────────────────────
document.addEventListener('DOMContentLoaded', () => {
  showPanel('results-empty');
  console.log('[PhishGuard] Frontend initialized. API target:', API_BASE);
});
