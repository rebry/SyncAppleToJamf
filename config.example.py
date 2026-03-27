# ──────────────────────────────────────────────────────────────────────────────
# config.example.py — template for SyncAppleToJamf.py credentials
#
# Copy this file to config.py and fill in your real values.
# config.py is gitignored and should never be committed.
# ──────────────────────────────────────────────────────────────────────────────

# ── Apple credentials ─────────────────────────────────────────────────────────
# Find these in ABM: Settings → Your Organization → API → Manage Keys
# Find these in ASM: Settings → API → Manage Keys
#
# CLIENT_ID prefix determines which service is used:
#   BUSINESSAPI.  →  Apple Business Manager
#   SCHOOLAPI.    →  Apple School Manager
ASM_KEY_ID       = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
ASM_CLIENT_ID    = "BUSINESSAPI.xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
ASM_KEY_FILENAME = "AxMCert.pem"   # filename of the private key — must be in the same folder

# ── Jamf Pro credentials ──────────────────────────────────────────────────────
# Find these in Jamf Pro: Settings → System → API Roles and Clients → API Clients
JAMF_URL           = "https://yourorg.jamfcloud.com"
JAMF_CLIENT_ID     = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
JAMF_CLIENT_SECRET = "your-client-secret-here"

# ── Vendor mapping ────────────────────────────────────────────────────────────
# Apple returns an internal vendor code; map it to a human-readable name here.
# Add more entries if you have multiple resellers.
# Leave empty if you don't want vendor mapping: VENDOR_MAP = {}
VENDOR_MAP = {
    "XXXXXXXX": "Your Reseller Name",
}

# ── Tuning ────────────────────────────────────────────────────────────────────
# Delay between AppleCare coverage API calls.
# Increase if you see HTTP 429 (rate limited) errors from Apple.
ASM_RATE_LIMIT_DELAY_SECONDS = 0.3
