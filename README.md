# PHISH-GUARD – AI-Powered URL & Email Security Auditor

A production-grade, full-stack security dashboard that performs live forensic analysis
of suspicious URLs and email content using DNS lookup, SSL validation, HTTP header
inspection, keyword detection, and AI-powered forensic explanation via **Google Gemini Pro**.

---

## 📁 Folder Structure

```
phish-guard/
├── frontend/
│   ├── index.html       ← Main dashboard UI
│   ├── style.css        ← Dark cyber security theme
│   └── app.js           ← Vanilla JS / fetch API client
│
├── backend/
│   ├── server.js                   ← Express app, routes, middleware
│   ├── package.json
│   ├── .env.example                ← Environment variable template
│   └── services/
│       ├── urlScanner.js           ← DNS, SSL, headers, risk scoring
│       ├── emailScanner.js         ← Keyword detection, URL extraction
│       └── aiAnalyzer.js           ← Gemini Pro AI forensic analysis
│
└── README.md
```

---

## 🚀 Installation & Setup

### Prerequisites
- **Node.js v18+** (required for native `fetch` and modern `dns.promises`)
- **npm v8+**
- **Google Gemini API Key** (free at https://aistudio.google.com/app/apikey)

### 1. Clone / Download
```bash
git clone https://github.com/yourrepo/phish-guard.git
cd phish-guard
```

### 2. Backend Setup
```bash
cd backend
npm install

# Configure environment
cp .env.example .env
# Edit .env and add your GEMINI_API_KEY
```

### 3. Start the Backend Server
```bash
# Development (with auto-restart)
npm run dev

# Production
npm start
```

Server starts on `http://localhost:3000`

### 4. Serve the Frontend

**Option A – VS Code Live Server (recommended for dev)**
- Install "Live Server" extension
- Right-click `frontend/index.html` → Open with Live Server
- Runs on `http://localhost:5500`

**Option B – Python HTTP server**
```bash
cd frontend
python3 -m http.server 5500
```

**Option C – nginx / Apache (production)**
- Copy `frontend/` files to your web root
- Ensure `API_BASE` in `app.js` points to your backend URL

---

## 🔧 Configuration

Edit `backend/.env`:
```env
PORT=3000
NODE_ENV=development
GEMINI_API_KEY=your_api_key_here
ALLOWED_ORIGINS=http://localhost:5500,https://yourdomain.com
```

Edit `frontend/app.js` line 8:
```js
const API_BASE = 'http://localhost:3000'; // → change to your backend URL
```

---

## 🌐 API Endpoints

### POST `/scan-url`
```json
Request:  { "url": "https://suspicious.com/login" }
Response: {
  "threatScore": 72,
  "dnsStatus": "RESOLVED",
  "sslValid": false,
  "certificateIssuer": "CERT_HAS_EXPIRED",
  "redirects": 3,
  "suspiciousKeywords": ["url-shortener", "brand-spoof:paypal"],
  "httpHeaders": { ... },
  "aiAnalysis": "Forensic analysis text...",
  "scanId": "SID-ABC123",
  "timestamp": "2024-01-01T00:00:00.000Z"
}
```

### POST `/scan-email`
```json
Request:  { "emailContent": "From: security@paypa1.com\n..." }
Response: {
  "threatScore": 88,
  "suspiciousKeywords": ["urgent", "account suspended", "verify now"],
  "extractedUrls": ["http://paypal-verify.xyz/login"],
  "aiAnalysis": "...",
  ...
}
```

### GET `/health`
```json
{ "status": "ok", "service": "phish-guard-backend", "version": "2.0.0" }
```

---

## 🏗️ Architecture

```
Browser (HTML/CSS/JS)
    │
    │ fetch() POST /scan-url or /scan-email
    ▼
Express Server (Node.js)
    │
    ├── Helmet (security headers)
    ├── CORS (origin whitelist)
    ├── Rate Limiter (100/15min general, 20/5min scans)
    ├── Input Validation + Sanitization (validator.js)
    │
    ├── /scan-url ──────────────────────────────────────────┐
    │       │                                               │
    │   urlScanner.js                                       │
    │   ├── dns.resolve4()          Node built-in           │
    │   ├── https.request()         SSL cert extraction     │
    │   ├── Redirect chain follow   HEAD requests           │
    │   ├── Risk scoring algorithm  Weighted factors        │
    │   └── Pattern matching        Regex-based            │
    │                                                       │
    └── /scan-email ─────────────────────────────────────────┤
            │                                               │
        emailScanner.js                                     │
        ├── Keyword detection      Weighted regex patterns  │
        ├── URL extraction         Regex + scanUrl()        │
        ├── Sender analysis        Domain/homoglyph checks  │
        └── Blended risk scoring                            │
                                                            │
    Both routes call:                                       │
        aiAnalyzer.js ◄──────────────────────────────────────┘
        └── Gemini Pro API (server-side only, key never exposed)
            └── Returns human-readable forensic analysis
```

---

## 🔐 Security Practices

| Practice | Implementation |
|---|---|
| API Key Protection | Loaded from `.env`, never sent to frontend |
| CORS | Whitelist-based origin validation |
| Rate Limiting | express-rate-limit on all scan endpoints |
| Input Validation | validator.js + length limits + protocol check |
| Injection Prevention | Input sanitization, parameterized URL parsing |
| Security Headers | helmet.js on all responses |
| Private IP Blocking | Block localhost/RFC1918 scans in production |
| JSON Size Limit | 50KB max to prevent DoS |
| Error Handling | Never leak stack traces to client in production |

---

## 🚀 Deployment Guide

### Deploy Backend to Railway / Render / Fly.io

1. Push to GitHub
2. Create new project on Railway/Render
3. Set environment variables:
   - `GEMINI_API_KEY=your_key`
   - `NODE_ENV=production`
   - `ALLOWED_ORIGINS=https://yourdomain.com`
4. Set build command: `npm install`
5. Set start command: `npm start`

### Deploy Frontend to Vercel / Netlify / GitHub Pages

1. Update `API_BASE` in `frontend/app.js` to your backend URL
2. Deploy the `frontend/` folder
3. No build step needed (pure HTML/CSS/JS)

### Deploy with Docker
```dockerfile
FROM node:20-alpine
WORKDIR /app
COPY backend/package*.json ./
RUN npm ci --only=production
COPY backend/ .
EXPOSE 3000
CMD ["node", "server.js"]
```

---

## ⌨️ Keyboard Shortcuts

| Shortcut | Action |
|---|---|
| `Ctrl+Enter` | Start scan |
| `Escape` | Reset / clear results |
| `Enter` (in URL field) | Start scan |

---

## 📝 License

MIT License. Use responsibly for security research and education.
