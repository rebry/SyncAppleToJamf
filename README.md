# SyncAppleToJamf

> Pulls purchasing and AppleCare data from Apple Business Manager or Apple School Manager and writes it into Jamf Pro — for every device that exists in both systems.

Run it once from any Mac. It matches devices by serial number and updates them in bulk — no need to touch each device individually.

---

## How it works

Each run will:

1. Connect to both Apple and Jamf Pro
2. Check that the required extension attributes exist in Jamf Pro — any that are missing are created automatically
3. Fetch all devices from both systems and match them by serial number
4. For each match, pull purchasing details and AppleCare coverage from Apple and write them to Jamf Pro

### What gets written

**Inventory → Purchasing**

- **Purchased / Leased** — purchase type from Apple
- **PO Date** — order date from Apple
- **PO Number** — order number from Apple
- **Vendor** — reseller name (mapped from Apple's internal vendor code via `VENDOR_MAP` in `config.py`)
- **Warranty Expiry** — AppleCare end date, or standard warranty as fallback
- **AppleCare ID** — agreement number (AppleCare+ only)

**Extension Attributes** — created automatically in Jamf Pro if missing

- **AppleCare Plan Type** — e.g. `AppleCare+` or `Limited Warranty`
- **AppleCare Status** — e.g. `ACTIVE` or `EXPIRED`
- **AppleCare Start Date** — e.g. `2024-01-15`
- **AppleCare End Date** — e.g. `2027-01-14`

> [!NOTE]
> Fields with no data in Apple are left unchanged in Jamf Pro. Existing values are never overwritten with blanks.

---

## Requirements

- macOS
- Python 3.9 or later — install via [python.org](https://www.python.org/downloads/) or `brew install python`
- openssl — pre-installed on macOS
- An Apple API private key — downloaded from ABM or ASM ([details below](#getting-your-apple-api-key))
- A Jamf Pro API client — created in Jamf Pro settings ([details below](#setting-up-jamf-pro))

---

## Setup

### 1. Configure credentials

Rename `config.example.py` to `config.py`:

```bash
mv config.example.py config.py
```

Then open `config.py` and fill in the values marked below. The rest are already pre-filled and ready to go.

**Fill in yourself:**
- `ASM_KEY_ID` — the Key ID from ABM or ASM
- `ASM_CLIENT_ID` — the Client ID from ABM or ASM (starts with `BUSINESSAPI.` or `SCHOOLAPI.`)
- `ASM_KEY_FILENAME` — the filename of your Apple private key (default: `AxMCert.pem`)
- `JAMF_URL` — your Jamf Pro URL, e.g. `https://yourorg.jamfcloud.com`
- `JAMF_CLIENT_ID` — the API Client ID from Jamf Pro
- `JAMF_CLIENT_SECRET` — the API Client Secret from Jamf Pro

**Already pre-filled:**
- `VENDOR_MAP` — maps Apple's internal vendor code to a human-readable reseller name
- `ASM_RATE_LIMIT_DELAY_SECONDS` — set to `0.3s` to stay within Apple's rate limits

### 2. Add your Apple private key

Place your `.pem` or `.p8` key file in the same folder as `SyncAppleToJamf.py` and set `ASM_KEY_FILENAME` in `config.py` to match the filename.

### 3. Run the sync

```bash
python3 SyncAppleToJamf.py
```

> [!NOTE]
> The script automatically creates any missing extension attributes in Jamf Pro before syncing — no separate setup step needed.

---

## Usage

Full sync — updates all matched devices (also creates any missing extension attributes automatically):
```bash
python3 SyncAppleToJamf.py
```

Setup only — verifies and creates extension attributes in Jamf Pro without running a full sync. No Apple credentials needed:
```bash
python3 SyncAppleToJamf.py --setup-only
```

---

## Getting your Apple API key

Go to [Apple Business Manager](https://business.apple.com) or [Apple School Manager](https://school.apple.com):

**Settings → Your Organisation → API → Manage Keys**

1. Click **Add** — Apple generates the key for you
2. Download the private key file — **you can only download it once**
3. Note the **Key ID** and **Client ID** on the same page
4. Place the key file in the same folder as `SyncAppleToJamf.py`
5. Fill in `ASM_KEY_ID`, `ASM_CLIENT_ID`, and `ASM_KEY_FILENAME` in `config.py`

The script detects ABM vs ASM automatically from the Client ID prefix:

- `BUSINESSAPI.` → Apple Business Manager
- `SCHOOLAPI.` → Apple School Manager

---

## Setting up Jamf Pro

Go to **Settings → System → API Roles and Clients**.

**Step 1 — Create an API Role** with these privileges:

*Computers*
- Read Computers
- Update Computers
- Read Computer Extension Attributes
- Create Computer Extension Attributes

*Mobile Devices*
- Read Mobile Devices
- Update Mobile Devices
- Read Mobile Device Extension Attributes
- Create Mobile Device Extension Attributes

**Step 2 — Create an API Client** assigned to that role.

**Step 3 — Paste the Client ID and Client Secret** into `config.py`.

---

## Troubleshooting

<details>
<summary><b>"config.py not found"</b></summary>

You don't have a `config.py` file. Copy the example to create one: `cp config.example.py config.py`, then fill in your credentials.

</details>

<details>
<summary><b>"0 devices matched"</b></summary>

The devices in Jamf Pro don't appear in your ABM/ASM account. This usually means they were enrolled through a different account. Try switching between ABM and ASM credentials.

Set `DEBUG = True` at the top of `SyncAppleToJamf.py` to print which serial numbers each system returns.

</details>

<details>
<summary><b>"invalid_client" from Apple</b></summary>

The private key file doesn't match the Key ID or Client ID in `config.py`. Re-download the key from ABM/ASM and update the `ASM_` values.

</details>

<details>
<summary><b>"HTTP 401" from Jamf</b></summary>

The Client ID or Client Secret is wrong, or the API Client has been disabled. Check **Settings → API Roles and Clients** in Jamf Pro.

</details>

<details>
<summary><b>"HTTP 403" from Jamf</b></summary>

The API Role is missing one or more required privileges. Compare it against the list in [Setting up Jamf Pro](#setting-up-jamf-pro).

</details>

<details>
<summary><b>Extension attributes are missing in Jamf Pro</b></summary>

The sync creates missing extension attributes automatically on each run. If you want to create them without running a full sync, use `python3 SyncAppleToJamf.py --setup-only`.

</details>

<details>
<summary><b>Need more detail on what's happening?</b></summary>

Set `DEBUG = True` at the top of `SyncAppleToJamf.py` to print full API responses and per-device output.

</details>
