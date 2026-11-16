// Include this file in the GitHub Pages dashboard.
// Set API_BASE to the custom HTTPS Worker hostname.
// The dashboard and API should be protected by Cloudflare Access.
// Do not put Cloudflare API tokens or Logpush ingest secrets in this file.
const BACKBLOCK_API_BASE = "https://api.mommiesprincess.party";

async function backblockApi(path, options = {}) {
  const response = await fetch(`${BACKBLOCK_API_BASE}${path}`, {
    ...options,
    credentials: "include",
    headers: {
      "content-type": "application/json",
      ...(options.headers || {})
    }
  });
  if (!response.ok) {
    const body = await response.json().catch(() => ({}));
    throw new Error(body.error || `BACKBLOCK API returned HTTP ${response.status}`);
  }
  return response.json();
}

async function loadBackblockHealth() {
  return backblockApi("/api/health");
}
async function loadBackblockEvents(limit = 100) {
  return backblockApi(`/api/events?limit=${encodeURIComponent(limit)}`);
}
async function loadBackblockAlerts() {
  return backblockApi("/api/alerts");
}
async function loadBackblockCases() {
  return backblockApi("/api/cases");
}
