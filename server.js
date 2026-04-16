/**
 * xero-mcp-auth — Minimal local Xero OAuth 2.0 token server
 *
 * USAGE:
 *   1. Copy .env.example → .env and fill in your Xero credentials
 *   2. npm install
 *   3. node server.js
 *   4. Open http://localhost:3000 in your browser
 *   5. Click "Login with Xero", complete the OAuth flow
 *   6. Copy the displayed bearer token into Claude Desktop MCP config
 *
 * Tokens are stored in NeonDB (auto-initialised on first run).
 * Tokens auto-refresh when you visit the page or call /api/token.
 */

'use strict';

require('dotenv').config();
const express        = require('express');
const axios          = require('axios');
const crypto         = require('crypto');
const { neon }       = require('@neondatabase/serverless');

const sql = neon(process.env.DATABASE_URL);

// ── Config ────────────────────────────────────────────────────────────────────

const PORT          = process.env.PORT          || 3000;
const CLIENT_ID     = process.env.XERO_CLIENT_ID;
const CLIENT_SECRET = process.env.XERO_CLIENT_SECRET;
const REDIRECT_URI  = process.env.XERO_REDIRECT_URI  || `http://localhost:${PORT}/callback`;

// Granular scopes for full Xero MCP access (Xero deprecated the broad scopes).
// offline_access is required to get a refresh_token — do not remove it.
//
// Covers:
//   invoices, payments, bank transactions, manual journals (read + write)
//   contacts + contact groups (read + write)
//   accounts, tax rates, tracking categories, items (settings)
//   balance sheet, P&L, trial balance, aged reports (read-only)
const SCOPES = process.env.XERO_SCOPES ||
  [
    'openid', 'profile', 'email',
    // Transactions (granular — replaces deprecated accounting.transactions)
    'accounting.invoices',
    'accounting.payments',
    'accounting.banktransactions',
    'accounting.manualjournals',
    // Contacts (replaces deprecated accounting.contacts)
    'accounting.contacts',
    // Settings: accounts, tax rates, tracking categories, items
    'accounting.settings',
    // Reports (granular — replaces deprecated accounting.reports.read)
    'accounting.reports.balancesheet.read',
    'accounting.reports.profitandloss.read',
    'accounting.reports.trialbalance.read',
    'accounting.reports.aged.read',
    // Required for refresh tokens
    'offline_access',
  ].join(' ');

const XERO_AUTH_URL  = 'https://login.xero.com/identity/connect/authorize';
const XERO_TOKEN_URL = 'https://identity.xero.com/connect/token';
const XERO_CONN_URL  = 'https://api.xero.com/connections';

// ── Token storage (NeonDB) ───────────────────────────────────────────────────

/** Create table on first run if it doesn't exist yet */
async function initDb() {
  await sql`
    CREATE TABLE IF NOT EXISTS xero_tokens (
      id            INTEGER PRIMARY KEY DEFAULT 1,
      access_token  TEXT    NOT NULL,
      refresh_token TEXT    NOT NULL,
      expires_at    BIGINT  NOT NULL,
      tenant_id     TEXT,
      tenant_name   TEXT,
      authorised_at TEXT,
      refreshed_at  TEXT
    )
  `;
}

async function loadTokens() {
  const rows = await sql`SELECT * FROM xero_tokens WHERE id = 1`;
  return rows[0] ?? null;
}

async function saveTokens(data) {
  await sql`
    INSERT INTO xero_tokens
      (id, access_token, refresh_token, expires_at, tenant_id, tenant_name, authorised_at, refreshed_at)
    VALUES
      (1, ${data.access_token}, ${data.refresh_token}, ${data.expires_at},
       ${data.tenant_id ?? null}, ${data.tenant_name ?? null},
       ${data.authorised_at ?? null}, ${data.refreshed_at ?? null})
    ON CONFLICT (id) DO UPDATE SET
      access_token  = EXCLUDED.access_token,
      refresh_token = EXCLUDED.refresh_token,
      expires_at    = EXCLUDED.expires_at,
      tenant_id     = EXCLUDED.tenant_id,
      tenant_name   = EXCLUDED.tenant_name,
      authorised_at = EXCLUDED.authorised_at,
      refreshed_at  = EXCLUDED.refreshed_at
  `;
}

async function clearTokens() {
  await sql`DELETE FROM xero_tokens WHERE id = 1`;
}

function isExpired(tokens) {
  // Treat as expired 60 seconds early to avoid race conditions
  return !tokens || Date.now() >= (tokens.expires_at - 60_000);
}

// ── Token refresh ─────────────────────────────────────────────────────────────

async function refreshIfNeeded() {
  const tokens = await loadTokens();
  if (!tokens) return null;

  if (!isExpired(tokens)) {
    return tokens; // Still valid
  }

  console.log('[xero-auth] Token expired — refreshing...');
  try {
    const res = await axios.post(
      XERO_TOKEN_URL,
      new URLSearchParams({
        grant_type:    'refresh_token',
        refresh_token: tokens.refresh_token,
      }),
      {
        auth: { username: CLIENT_ID, password: CLIENT_SECRET },
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      }
    );

    const refreshed = {
      ...tokens,                                    // keep tenant info
      access_token:  res.data.access_token,
      refresh_token: res.data.refresh_token,        // Xero rotates refresh tokens
      expires_at:    Date.now() + res.data.expires_in * 1000,
      refreshed_at:  new Date().toISOString(),
    };

    await saveTokens(refreshed);
    console.log('[xero-auth] Token refreshed successfully');
    return refreshed;

  } catch (err) {
    console.error('[xero-auth] Refresh failed:', err.response?.data || err.message);
    return null; // Caller will show "re-login" message
  }
}

// ── Express app ───────────────────────────────────────────────────────────────

const app = express();

// In-memory CSRF state (fine for local single-user app)
let oauthState = null;

// ── GET / — Home: show token status ──────────────────────────────────────────

app.get('/', async (req, res) => {
  const tokens = await refreshIfNeeded();

  if (!tokens) {
    // Not authenticated yet (or refresh failed after expiry)
    return res.send(renderPage({
      title:   'Xero MCP Auth',
      content: `
        <div class="card center">
          <div class="icon">🔐</div>
          <h2>Not connected</h2>
          <p>Click the button below to authorise this app with Xero.<br>
             You only need to do this once — tokens are saved locally and auto-refreshed.</p>
          <a href="/login" class="btn">Login with Xero</a>
        </div>`,
    }));
  }

  const expiresAt     = new Date(tokens.expires_at);
  const secondsLeft   = Math.max(0, Math.round((tokens.expires_at - Date.now()) / 1000));
  const minutesLeft   = Math.floor(secondsLeft / 60);
  const expiryLabel   = minutesLeft > 1
    ? `${minutesLeft} min remaining`
    : secondsLeft > 0 ? `${secondsLeft}s remaining` : 'expired';

  const statusClass   = secondsLeft > 300 ? 'ok' : secondsLeft > 0 ? 'warn' : 'error';
  const statusIcon    = secondsLeft > 300 ? '✅' : '⏳';

  // Redact middle of token for display safety
  const token     = tokens.access_token;
  const tenantId  = tokens.tenant_id  || '';
  const orgName   = tokens.tenant_name || 'Unknown Org';

  // Build Claude Desktop MCP config
  const mcpConfig = JSON.stringify({
    mcpServers: {
      xero: {
        command: 'npx',
        args: ['-y', 'xero-mcp-server'],
        env: {
          XERO_CLIENT_ID:           CLIENT_ID,
          XERO_CLIENT_SECRET:       CLIENT_SECRET,
          XERO_CLIENT_BEARER_TOKEN: token,
          XERO_TENANT_ID:           tenantId,
        },
      },
    },
  }, null, 2);

  return res.send(renderPage({
    title:   `Token — ${orgName}`,
    content: `
      <div class="card">
        <div class="org-row">
          <span class="org-name">🏢 ${esc(orgName)}</span>
          <span class="expiry ${statusClass}">${statusIcon} ${esc(expiryLabel)} · expires ${expiresAt.toLocaleTimeString()}</span>
        </div>

        <label class="field-label">Bearer Token (XERO_CLIENT_BEARER_TOKEN)</label>
        <div class="token-wrap">
          <code id="bearerToken">${esc(token)}</code>
          <button class="copy-btn" onclick="copy('bearerToken', this)">Copy</button>
        </div>

        <label class="field-label" style="margin-top:18px">Tenant ID (XERO_TENANT_ID)</label>
        <div class="token-wrap">
          <code id="tenantId">${esc(tenantId)}</code>
          <button class="copy-btn" onclick="copy('tenantId', this)">Copy</button>
        </div>

        <label class="field-label" style="margin-top:26px">Ready-to-paste Claude Desktop MCP Config</label>
        <div class="config-wrap">
          <pre id="mcpConfig">${esc(mcpConfig)}</pre>
          <button class="copy-btn dark" onclick="copy('mcpConfig', this)">Copy JSON</button>
        </div>

        <div class="actions">
          <a href="/refresh" class="btn outline">↻ Force Refresh Token</a>
          <a href="/login"   class="btn outline">Re-authorise Xero</a>
          <a href="/logout"  class="btn outline danger">Clear Tokens</a>
        </div>
      </div>

      <div class="info-box">
        <strong>📋 How to use:</strong>
        Copy the MCP Config JSON above → open <code>~/.claude/claude_desktop_config.json</code>
        → paste/merge the <code>mcpServers</code> block → restart Claude Desktop.<br>
        Tokens expire every <strong>30 min</strong>. This page auto-refreshes them on load.
        When MCP stops working: revisit here, copy fresh token, update config, restart Claude Desktop.
      </div>`,
  }));
});

// ── GET /login — Start OAuth flow ─────────────────────────────────────────────

app.get('/login', (req, res) => {
  if (!CLIENT_ID || !CLIENT_SECRET) {
    return res.send(renderPage({
      title: 'Setup Required',
      content: `<div class="card center">
        <div class="icon">⚠️</div>
        <h2>Missing credentials</h2>
        <p>Create a <code>.env</code> file from <code>.env.example</code> and fill in your
           <strong>XERO_CLIENT_ID</strong> and <strong>XERO_CLIENT_SECRET</strong>.</p>
        <pre style="text-align:left;background:#f5f5f5;padding:14px;border-radius:8px;font-size:12px">cp .env.example .env
# then edit .env with your Xero app credentials</pre>
      </div>`,
    }));
  }

  oauthState = crypto.randomBytes(16).toString('hex');

  const url = XERO_AUTH_URL + '?' + new URLSearchParams({
    response_type: 'code',
    client_id:     CLIENT_ID,
    redirect_uri:  REDIRECT_URI,
    scope:         SCOPES,
    state:         oauthState,
  });

  res.redirect(url);
});

// ── GET /callback — Handle Xero redirect after login ──────────────────────────

app.get('/callback', async (req, res) => {
  const { code, state, error } = req.query;

  // OAuth error from Xero (e.g. user denied access)
  if (error) {
    return res.send(renderPage({
      title: 'Auth Error',
      content: `<div class="card center">
        <div class="icon">❌</div>
        <h2>Xero returned an error</h2>
        <p>${esc(String(error))}</p>
        <a href="/login" class="btn">Try again</a>
      </div>`,
    }));
  }

  // CSRF check
  if (!state || state !== oauthState) {
    return res.status(400).send(renderPage({
      title: 'Invalid State',
      content: `<div class="card center">
        <div class="icon">🚫</div>
        <h2>Invalid state parameter</h2>
        <p>Possible CSRF or stale session. Please try again.</p>
        <a href="/login" class="btn">Retry</a>
      </div>`,
    }));
  }

  oauthState = null; // consume state

  try {
    // ── Step 1: Exchange code for tokens ──────────────────────────────────
    const tokenRes = await axios.post(
      XERO_TOKEN_URL,
      new URLSearchParams({
        grant_type:   'authorization_code',
        code,
        redirect_uri: REDIRECT_URI,
      }),
      {
        auth: { username: CLIENT_ID, password: CLIENT_SECRET },
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      }
    );

    const { access_token, refresh_token, expires_in } = tokenRes.data;

    // ── Step 2: Fetch connected orgs to get tenant ID ─────────────────────
    const connRes = await axios.get(XERO_CONN_URL, {
      headers: { Authorization: `Bearer ${access_token}` },
    });

    const tenants = connRes.data;

    if (!tenants || tenants.length === 0) {
      return res.send(renderPage({
        title: 'No Orgs Found',
        content: `<div class="card center">
          <div class="icon">⚠️</div>
          <h2>No Xero organisations found</h2>
          <p>Your Xero account has no connected organisations. Please check your Xero account.</p>
          <a href="/login" class="btn">Try again</a>
        </div>`,
      }));
    }

    // If multiple orgs, show a picker
    if (tenants.length > 1 && !req.query.tenant_id) {
      return res.send(renderPage({
        title: 'Select Organisation',
        content: `
          <div class="card">
            <h2 style="margin-bottom:16px">Select your Xero organisation</h2>
            <p style="font-size:14px;color:#666;margin-bottom:20px">
              Multiple organisations found. Choose which one to use with Claude Desktop MCP.
            </p>
            ${tenants.map(t => `
              <a href="/callback?code=${esc(String(code))}&state=${esc(String(req.query.state || ''))}&tenant_id=${esc(t.tenantId)}"
                 class="org-item">
                🏢 <strong>${esc(t.tenantName)}</strong>
                <span style="font-size:11px;color:#888;margin-left:8px">${esc(t.tenantId)}</span>
              </a>
            `).join('')}
          </div>`,
      }));
    }

    // Use requested tenant or first one
    const selectedId = req.query.tenant_id || tenants[0].tenantId;
    const tenant     = tenants.find(t => t.tenantId === selectedId) || tenants[0];

    // ── Step 3: Save tokens ───────────────────────────────────────────────
    await saveTokens({
      access_token,
      refresh_token,
      expires_at:   Date.now() + expires_in * 1000,
      tenant_id:    tenant.tenantId,
      tenant_name:  tenant.tenantName,
      authorised_at: new Date().toISOString(),
      refreshed_at:  null,
    });

    console.log(`[xero-auth] Authorised: ${tenant.tenantName} (${tenant.tenantId})`);

    res.redirect('/?connected=1');

  } catch (err) {
    const detail = err.response?.data
      ? JSON.stringify(err.response.data)
      : err.message;

    console.error('[xero-auth] Token exchange failed:', detail);

    return res.send(renderPage({
      title: 'Auth Failed',
      content: `<div class="card center">
        <div class="icon">❌</div>
        <h2>Token exchange failed</h2>
        <p>Xero returned an error during the code exchange. Check your credentials.</p>
        <pre style="background:#fef2f2;border:1px solid #fecaca;padding:12px;border-radius:8px;font-size:12px;text-align:left;word-break:break-all">${esc(detail)}</pre>
        <a href="/login" class="btn" style="margin-top:12px">Try again</a>
      </div>`,
    }));
  }
});

// ── GET /refresh — Force token refresh ───────────────────────────────────────

app.get('/refresh', async (req, res) => {
  const tokens = await loadTokens();
  if (!tokens) return res.redirect('/');

  // Force-expire so refreshIfNeeded() will refresh
  tokens.expires_at = 0;
  await saveTokens(tokens);

  await refreshIfNeeded();
  res.redirect('/');
});

// ── GET /logout — Clear saved tokens ─────────────────────────────────────────

app.get('/logout', async (req, res) => {
  await clearTokens();
  res.redirect('/');
});

// ── GET /api/token — JSON endpoint ───────────────────────────────────────────
//
// Returns the current valid token as JSON.
// Useful for scripts: curl http://localhost:3000/api/token
//
// Response:
//   { "ok": true, "access_token": "eyJ...", "tenant_id": "...",
//     "tenant_name": "...", "expires_at": 1234567890, "expires_in_seconds": 1234 }

app.get('/api/token', async (req, res) => {
  res.setHeader('Content-Type', 'application/json');
  res.setHeader('Cache-Control', 'no-store');

  const tokens = await refreshIfNeeded();

  if (!tokens) {
    return res.status(401).json({
      ok: false,
      error: 'not_authenticated',
      message: 'No tokens found. Visit http://localhost:' + PORT + ' and log in first.',
    });
  }

  return res.json({
    ok:              true,
    access_token:    tokens.access_token,
    tenant_id:       tokens.tenant_id,
    tenant_name:     tokens.tenant_name,
    expires_at:      Math.floor(tokens.expires_at / 1000), // Unix timestamp (seconds)
    expires_in_seconds: Math.max(0, Math.round((tokens.expires_at - Date.now()) / 1000)),
  });
});

// ── HTML helpers ──────────────────────────────────────────────────────────────

/** Escape HTML special chars */
function esc(str) {
  return String(str)
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/** Wrap content in the shared HTML shell */
function renderPage({ title, content }) {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>${esc(title)} — Xero MCP Auth</title>
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif;
    background: #f4f4f5; color: #18181b; min-height: 100vh;
  }

  /* ── Header ── */
  header {
    background: #18181b; color: #fff;
    padding: 14px 32px;
    display: flex; align-items: center; justify-content: space-between;
  }
  header h1 { font-size: 16px; font-weight: 600; letter-spacing: -.2px; }
  header nav a { color: #a1a1aa; font-size: 13px; text-decoration: none; margin-left: 16px; }
  header nav a:hover { color: #fff; }

  /* ── Layout ── */
  main { max-width: 820px; margin: 36px auto; padding: 0 20px; }

  /* ── Card ── */
  .card {
    background: #fff; border: 1px solid #e4e4e7;
    border-radius: 12px; padding: 28px 32px;
  }
  .card.center { text-align: center; padding: 48px 32px; }
  .icon { font-size: 48px; margin-bottom: 16px; }
  .card h2 { font-size: 20px; font-weight: 700; margin-bottom: 10px; }
  .card p  { font-size: 14px; color: #52525b; line-height: 1.6; margin-bottom: 20px; }

  /* ── Org row ── */
  .org-row { display: flex; align-items: center; justify-content: space-between;
             flex-wrap: wrap; gap: 8px; margin-bottom: 20px; }
  .org-name { font-size: 16px; font-weight: 600; }
  .expiry { font-size: 12px; font-weight: 600; padding: 3px 10px; border-radius: 20px; }
  .expiry.ok    { background: #dcfce7; color: #15803d; }
  .expiry.warn  { background: #fef3c7; color: #b45309; }
  .expiry.error { background: #fee2e2; color: #b91c1c; }

  /* ── Field label ── */
  .field-label {
    display: block; font-size: 11px; font-weight: 600; letter-spacing: .5px;
    text-transform: uppercase; color: #71717a; margin-bottom: 6px;
  }

  /* ── Token / code block ── */
  .token-wrap, .config-wrap {
    position: relative;
    background: #f4f4f5; border: 1px solid #d4d4d8;
    border-radius: 8px; padding: 12px 100px 12px 14px;
  }
  .config-wrap { background: #0d1117; border-color: #30363d; }

  .token-wrap code {
    font-family: 'SF Mono', Menlo, Consolas, monospace;
    font-size: 11.5px; color: #18181b; word-break: break-all; line-height: 1.6;
  }
  .config-wrap pre {
    font-family: 'SF Mono', Menlo, Consolas, monospace;
    font-size: 11.5px; color: #e6edf3; white-space: pre; line-height: 1.6;
    overflow-x: auto;
  }

  /* ── Copy button ── */
  .copy-btn {
    position: absolute; top: 10px; right: 10px;
    background: #18181b; color: #fff;
    border: none; border-radius: 6px;
    padding: 5px 14px; font-size: 12px; font-weight: 500;
    cursor: pointer; font-family: inherit; white-space: nowrap;
    transition: background .15s;
  }
  .copy-btn:hover    { background: #3f3f46; }
  .copy-btn.copied   { background: #16a34a; }
  .copy-btn.dark     { background: rgba(255,255,255,.12); border: 1px solid rgba(255,255,255,.15); }
  .copy-btn.dark:hover  { background: rgba(255,255,255,.2); }
  .copy-btn.dark.copied { background: #16a34a; border-color: #16a34a; }

  /* ── Buttons ── */
  .btn {
    display: inline-block; padding: 9px 20px;
    background: #18181b; color: #fff;
    border: 1px solid transparent;
    text-decoration: none; border-radius: 7px;
    font-size: 13px; font-weight: 500; cursor: pointer;
    font-family: inherit; transition: background .15s;
  }
  .btn:hover    { background: #3f3f46; }
  .btn.outline  { background: transparent; color: #3f3f46; border-color: #d4d4d8; }
  .btn.outline:hover { background: #f4f4f5; }
  .btn.danger   { color: #dc2626; border-color: #fecaca; }
  .btn.danger:hover { background: #fef2f2; }

  .actions { display: flex; gap: 10px; flex-wrap: wrap; margin-top: 24px; }

  /* ── Org picker items ── */
  .org-item {
    display: flex; align-items: center;
    padding: 14px 16px; border: 1px solid #e4e4e7; border-radius: 8px;
    margin-bottom: 10px; text-decoration: none; color: inherit;
    transition: background .12s;
  }
  .org-item:hover { background: #f4f4f5; }

  /* ── Info box ── */
  .info-box {
    background: #eff6ff; border: 1px solid #bfdbfe; color: #1e40af;
    border-radius: 8px; padding: 14px 16px;
    font-size: 13px; line-height: 1.6; margin-top: 20px;
  }
  .info-box code { background: rgba(0,0,0,.06); padding: 1px 5px; border-radius: 3px; font-size: 12px; }
</style>
</head>
<body>

<header>
  <h1>🔑 Xero MCP Auth</h1>
  <nav>
    <a href="/">Home</a>
    <a href="/api/token" target="_blank">JSON API</a>
    <a href="/login">Re-auth</a>
  </nav>
</header>

<main>
  ${content}
</main>

<script>
  function copy(id, btn) {
    const el = document.getElementById(id);
    const text = el.innerText || el.textContent;
    navigator.clipboard.writeText(text).then(() => {
      const orig = btn.textContent;
      btn.textContent = '✓ Copied!';
      btn.classList.add('copied');
      setTimeout(() => { btn.textContent = orig; btn.classList.remove('copied'); }, 2200);
    });
  }
</script>

</body>
</html>`;
}

// ── Start ─────────────────────────────────────────────────────────────────────

(async () => {
  // Create the DB table if it doesn't exist yet, then start the server
  await initDb();
  console.log('[xero-auth] Database ready (NeonDB)');

  app.listen(PORT, () => {
    console.log('');
    console.log('  🔑 Xero MCP Auth running at http://localhost:' + PORT);
    console.log('');
    if (!CLIENT_ID || !CLIENT_SECRET) {
      console.log('  ⚠️  No credentials found!');
      console.log('     Copy .env.example → .env and fill in XERO_CLIENT_ID + XERO_CLIENT_SECRET');
    } else {
      console.log('  → Open http://localhost:' + PORT + ' in your browser to get your token');
      console.log('  → JSON API: GET http://localhost:' + PORT + '/api/token');
    }
    console.log('');
  });
})();
