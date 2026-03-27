#!/usr/bin/env python3
# Author:       Per Kristian Thorsen
# Organisation: Eplehuset
# Version:      1.0
# Created:      2026-03-26
# Last updated: 2026-03-27
# Description:  Syncs purchasing data from Apple Business Manager or Apple
#               School Manager into Jamf Pro for all matched computers and
#               mobile devices. Matches devices by serial number and writes
#               purchasing fields and AppleCare extension attributes.
# Requires:     Python 3.9+ (python.org or brew install python), openssl (pre-installed
#               on macOS), Apple private key file (.pem or .p8) placed in the same
#               folder as this script (filename set in config.py).
#
# See README.md for full documentation, setup instructions, and troubleshooting.
"""
Usage:
    python3 SyncAppleToJamf.py               # full sync (Apple → Jamf Pro)
    python3 SyncAppleToJamf.py --setup-only  # verify/create EAs in Jamf Pro only
"""

import argparse
import base64
import json
import os
import subprocess
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import uuid


# ──────────────────────────────────────────────────────────────────────────────
# CONFIGURATION
# All credentials and settings live in config.py (gitignored).
# Copy config.example.py to config.py and fill in your values.
# ──────────────────────────────────────────────────────────────────────────────

# Set to True to print raw API responses and extra detail for each device.
# Useful when something isn't updating as expected.
DEBUG = False

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, SCRIPT_DIR)

try:
    import config
except ImportError:
    print("ERROR: config.py not found.")
    print("       Copy config.example.py to config.py and fill in your credentials.")
    sys.exit(1)

ASM_KEY_ID                   = config.ASM_KEY_ID
ASM_CLIENT_ID                = config.ASM_CLIENT_ID
ASM_KEY_FILE                 = os.path.join(SCRIPT_DIR, config.ASM_KEY_FILENAME)
JAMF_URL                     = config.JAMF_URL
JAMF_CLIENT_ID               = config.JAMF_CLIENT_ID
JAMF_CLIENT_SECRET           = config.JAMF_CLIENT_SECRET
VENDOR_MAP                   = config.VENDOR_MAP
ASM_RATE_LIMIT_DELAY_SECONDS = config.ASM_RATE_LIMIT_DELAY_SECONDS


# ──────────────────────────────────────────────────────────────────────────────
# DERIVED SETTINGS
# Do not edit — these are set automatically based on the CLIENT_ID prefix.
# ──────────────────────────────────────────────────────────────────────────────

ASM_TOKEN_URL = "https://account.apple.com/auth/oauth2/token"

if ASM_CLIENT_ID.startswith("BUSINESSAPI."):
    ASM_SCOPE    = "business.api"
    ASM_BASE_URL = "https://api-business.apple.com"
    ASM_SERVICE  = "Apple Business Manager"
elif ASM_CLIENT_ID.startswith("SCHOOLAPI."):
    ASM_SCOPE    = "school.api"
    ASM_BASE_URL = "https://api-school.apple.com"
    ASM_SERVICE  = "Apple School Manager"
else:
    print(f"ERROR: Unrecognised CLIENT_ID prefix in '{ASM_CLIENT_ID}'")
    print("       Expected 'BUSINESSAPI.' or 'SCHOOLAPI.'")
    sys.exit(1)


# ──────────────────────────────────────────────────────────────────────────────
# EXTENSION ATTRIBUTE DEFINITIONS
#
# These four EAs are required in Jamf Pro for both Computers and Mobile Devices.
# The script checks for them at startup and creates any that are missing.
# IDs are looked up by name at runtime — no hardcoding needed.
# ──────────────────────────────────────────────────────────────────────────────

APPLECARE_EAS = [
    {
        "name":        "AppleCare Plan Type",
        "description": "AppleCare plan type, e.g. AppleCare+ or Limited Warranty",
        "dataType":    "STRING",
        "inputType":   "TEXT",
    },
    {
        "name":        "AppleCare Status",
        "description": "AppleCare coverage status, e.g. ACTIVE or EXPIRED",
        "dataType":    "STRING",
        "inputType":   "TEXT",
    },
    {
        "name":        "AppleCare Start Date",
        "description": "AppleCare coverage start date (YYYY-MM-DD)",
        "dataType":    "DATE",
        "inputType":   "TEXT",
    },
    {
        "name":        "AppleCare End Date",
        "description": "AppleCare coverage end date (YYYY-MM-DD)",
        "dataType":    "DATE",
        "inputType":   "TEXT",
    },
]


# ──────────────────────────────────────────────────────────────────────────────
# LOGGING
# ──────────────────────────────────────────────────────────────────────────────

def log(message):
    print(message)

def log_step(number, total, message):
    print(f"\n[Step {number}/{total}] {message}")

def log_success(message):
    print(f"  ✓ {message}")

def log_warning(message):
    print(f"  ! {message}")

def log_error(message):
    print(f"  ✗ {message}", file=sys.stderr)

def log_detail(label, value):
    print(f"      {label:<22} {value}")

def log_debug(message, data=None):
    """Prints extra detail when DEBUG = True."""
    if not DEBUG:
        return
    print(f"  [DEBUG] {message}")
    if data is not None:
        print(json.dumps(data, indent=4, default=str))


# ──────────────────────────────────────────────────────────────────────────────
# JWT HELPERS
#
# Apple uses JWT-based OAuth2. We build a short-lived JWT, sign it with our
# EC private key using openssl, then exchange it for a bearer access token.
#
# Technical note: openssl outputs DER-encoded ECDSA signatures, but ES256 JWT
# requires a raw 64-byte r||s format. der_to_raw_sig() handles the conversion.
# ──────────────────────────────────────────────────────────────────────────────

def base64url_encode(data: bytes) -> str:
    """Base64 URL encoding without padding — required by the JWT spec."""
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def der_to_raw_sig(der_signature: bytes) -> bytes:
    """
    Convert a DER-encoded ECDSA signature (from openssl) to the raw r||s
    format that ES256 JWT requires (exactly 64 bytes: 32 bytes r + 32 bytes s).

    DER layout: 0x30 <len> 0x02 <r-len> <r> 0x02 <s-len> <s>
    """
    assert der_signature[0] == 0x30, "Not a valid DER signature"
    index = 2   # skip the 0x30 sequence tag and total-length byte

    assert der_signature[index] == 0x02, "Expected INTEGER tag for r"
    r_length = der_signature[index + 1]
    r_bytes  = der_signature[index + 2 : index + 2 + r_length]
    index   += 2 + r_length

    assert der_signature[index] == 0x02, "Expected INTEGER tag for s"
    s_length = der_signature[index + 1]
    s_bytes  = der_signature[index + 2 : index + 2 + s_length]

    # DER can add a leading 0x00 byte when the high bit is set to avoid
    # sign ambiguity. Strip it, then pad each value to exactly 32 bytes.
    r_padded = r_bytes.lstrip(b"\x00").rjust(32, b"\x00")
    s_padded = s_bytes.lstrip(b"\x00").rjust(32, b"\x00")

    return r_padded + s_padded


def build_asm_jwt() -> str:
    """
    Build and sign a JWT client assertion for authenticating with Apple.
    Apple accepts JWTs valid for up to 180 days.
    """
    header = {"alg": "ES256", "kid": ASM_KEY_ID, "typ": "JWT"}
    now    = int(time.time())
    payload = {
        "iss": ASM_CLIENT_ID,
        "sub": ASM_CLIENT_ID,
        "aud": "https://account.apple.com/auth/oauth2/v2/token",
        "iat": now,
        "exp": now + (180 * 24 * 60 * 60),   # 180 days (Apple's maximum)
        "jti": str(uuid.uuid4()),              # unique ID — prevents replay attacks
    }

    header_b64  = base64url_encode(json.dumps(header,  separators=(",", ":")).encode())
    payload_b64 = base64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    signing_input = f"{header_b64}.{payload_b64}"

    result = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", ASM_KEY_FILE],
        input=signing_input.encode(),
        capture_output=True,
    )
    if result.returncode != 0:
        log_error(f"openssl signing failed: {result.stderr.decode()}")
        log_error(f"Check that the key file exists and is a valid EC private key: {ASM_KEY_FILE}")
        sys.exit(1)

    signature = base64url_encode(der_to_raw_sig(result.stdout))
    log_debug("Built JWT", {"header": header, "payload": payload})
    return f"{signing_input}.{signature}"


# ──────────────────────────────────────────────────────────────────────────────
# AUTHENTICATION
# ──────────────────────────────────────────────────────────────────────────────

def get_asm_access_token() -> str:
    """
    Exchange a signed JWT for an Apple bearer token.
    The returned token is valid for 1 hour.
    """
    params = urllib.parse.urlencode({
        "grant_type":            "client_credentials",
        "client_id":             ASM_CLIENT_ID,
        "client_assertion_type": "urn:ietf:params:oauth:client-assertion-type:jwt-bearer",
        "client_assertion":      build_asm_jwt(),
        "scope":                 ASM_SCOPE,
    }).encode()

    request = urllib.request.Request(ASM_TOKEN_URL, data=params, method="POST")
    request.add_header("Content-Type", "application/x-www-form-urlencoded")

    try:
        with urllib.request.urlopen(request) as response:
            token_data = json.loads(response.read())
            log_debug("Apple token response", token_data)
            return token_data["access_token"]
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        log_error(f"Apple token request failed (HTTP {e.code}): {body}")
        if "invalid_client" in body:
            log_error("Hint: the Key ID or Client ID does not match the private key file.")
            log_error(f"      Key file: {ASM_KEY_FILE}")
            log_error(f"      Key ID:   {ASM_KEY_ID}")
        sys.exit(1)


def get_jamf_access_token() -> str:
    """
    Fetch a Jamf Pro bearer token using client credentials.
    Jamf tokens expire after approximately 60 seconds, so this is called
    before each write operation to avoid mid-run 401 errors.
    """
    params = urllib.parse.urlencode({
        "client_id":     JAMF_CLIENT_ID,
        "client_secret": JAMF_CLIENT_SECRET,
        "grant_type":    "client_credentials",
    }).encode()

    request = urllib.request.Request(
        f"{JAMF_URL}/api/v1/oauth/token", data=params, method="POST"
    )
    request.add_header("Content-Type", "application/x-www-form-urlencoded")

    try:
        with urllib.request.urlopen(request) as response:
            return json.loads(response.read())["access_token"]
    except urllib.error.HTTPError as e:
        body = e.read().decode()
        log_error(f"Jamf token request failed (HTTP {e.code}): {body}")
        if e.code == 401:
            log_error("Hint: the Client ID or Secret is wrong, or the API client is disabled.")
        sys.exit(1)


# ──────────────────────────────────────────────────────────────────────────────
# HTTP HELPERS
# ──────────────────────────────────────────────────────────────────────────────

def http_get(url: str, token: str, retries: int = 3) -> dict:
    """
    GET a JSON endpoint with bearer token auth.
    - Retries up to `retries` times on HTTP 429 (rate limited), with backoff.
    - Returns an empty dict on HTTP 404 (device/resource not found).
    - Raises on any other HTTP error.
    """
    request = urllib.request.Request(url, headers={
        "Authorization": f"Bearer {token}",
        "Accept":        "application/json",
    })
    log_debug(f"GET {url}")

    for attempt in range(retries):
        try:
            with urllib.request.urlopen(request) as response:
                data = json.loads(response.read())
                log_debug(f"Response from {url}", data)
                return data

        except urllib.error.HTTPError as e:
            if e.code == 429:
                wait = 2 + (attempt * 2)   # 2s, 4s, 6s
                log_warning(f"Rate limited (HTTP 429) — waiting {wait}s before retry {attempt + 1}/{retries}...")
                time.sleep(wait)
            elif e.code == 404:
                log_debug(f"404 Not Found: {url}")
                return {}
            else:
                body = e.read().decode()
                log_error(f"GET {url} → HTTP {e.code}: {body}")
                raise

    raise RuntimeError(f"GET {url} failed after {retries} attempts (rate limited)")


def http_patch(url: str, token: str, body: dict) -> int:
    """
    PATCH a JSON endpoint. Returns the HTTP status code.
    Jamf Pro returns 204 (No Content) on a successful update.
    """
    log_debug(f"PATCH {url}", body)
    request = urllib.request.Request(url, data=json.dumps(body).encode(), method="PATCH")
    request.add_header("Authorization", f"Bearer {token}")
    request.add_header("Content-Type",  "application/json")
    request.add_header("Accept",        "application/json")

    try:
        with urllib.request.urlopen(request) as response:
            return response.status
    except urllib.error.HTTPError as e:
        body_text = e.read().decode()
        log_error(f"PATCH {url} → HTTP {e.code}: {body_text}")
        return e.code


# ──────────────────────────────────────────────────────────────────────────────
# EXTENSION ATTRIBUTE SETUP
#
# Runs at startup to ensure the four AppleCare EAs exist in Jamf Pro for
# both Computers and Mobile Devices. Creates any that are missing.
#
# Returns a name→id dict for computers so the payload builder can reference
# EAs by their live Jamf-assigned ID (which changes if an EA is recreated).
# ──────────────────────────────────────────────────────────────────────────────

def ensure_computer_eas(jamf_token: str) -> dict:
    """
    Verify the four AppleCare EAs exist for Computers. Create missing ones.
    Returns a dict of { EA name: definition ID (as string) }.
    """
    response = http_get(
        f"{JAMF_URL}/api/v1/computer-extension-attributes?page-size=200",
        jamf_token,
    )
    # Build a name→id map from what already exists
    existing = {ea["name"]: str(ea["id"]) for ea in response.get("results", [])}

    for ea_def in APPLECARE_EAS:
        name = ea_def["name"]
        if name in existing:
            log_success(f"Computer EA exists:  {name}  (ID {existing[name]})")
        else:
            log_warning(f"Computer EA missing: {name} — creating...")
            payload = json.dumps({
                "name":                 name,
                "description":          ea_def["description"],
                "dataType":             ea_def["dataType"],
                "inputType":            ea_def["inputType"],
                "inventoryDisplayType": "PURCHASING",
                "enabled":              True,
            }).encode()
            req = urllib.request.Request(
                f"{JAMF_URL}/api/v1/computer-extension-attributes",
                data=payload, method="POST",
            )
            req.add_header("Authorization", f"Bearer {jamf_token}")
            req.add_header("Content-Type",  "application/json")
            req.add_header("Accept",        "application/json")
            try:
                with urllib.request.urlopen(req) as resp:
                    created = json.loads(resp.read())
                    existing[name] = str(created["id"])
                    log_success(f"Created computer EA: {name}  (ID {created['id']})")
            except urllib.error.HTTPError as e:
                log_error(f"Failed to create computer EA '{name}': {e.read().decode()}")

    return existing


def ensure_mobile_device_eas(jamf_token: str):
    """
    Verify the four AppleCare EAs exist for Mobile Devices. Create missing ones.

    Note: The Jamf Pro modern API (v1) does not support creating mobile device
    EAs, so we use the classic API (XML) for creation only.
    """
    # Jamf classic API uses different values for data type and input type
    data_type_map  = {"STRING": "String", "INTEGER": "Integer", "DATE": "Date"}
    input_type_map = {"TEXT": "Text Field", "POPUP": "Pop-up Menu"}

    response = http_get(
        f"{JAMF_URL}/api/v1/mobile-device-extension-attributes?page-size=200",
        jamf_token,
    )
    existing_names = {ea["name"] for ea in response.get("results", [])}

    for ea_def in APPLECARE_EAS:
        name = ea_def["name"]
        if name in existing_names:
            log_success(f"Mobile device EA exists:  {name}")
        else:
            log_warning(f"Mobile device EA missing: {name} — creating...")
            xml_body = (
                '<?xml version="1.0" encoding="UTF-8"?>'
                "<mobile_device_extension_attribute>"
                f"<name>{name}</name>"
                f"<description>{ea_def['description']}</description>"
                f"<data_type>{data_type_map.get(ea_def['dataType'], 'String')}</data_type>"
                "<input_type>"
                f"<type>{input_type_map.get(ea_def['inputType'], 'Text Field')}</type>"
                "</input_type>"
                "<inventory_display>Purchasing</inventory_display>"
                "</mobile_device_extension_attribute>"
            )
            req = urllib.request.Request(
                f"{JAMF_URL}/JSSResource/mobiledeviceextensionattributes/id/0",
                data=xml_body.encode("utf-8"), method="POST",
            )
            req.add_header("Authorization", f"Bearer {jamf_token}")
            req.add_header("Content-Type",  "application/xml")
            try:
                urllib.request.urlopen(req)
                log_success(f"Created mobile device EA: {name}")
            except urllib.error.HTTPError as e:
                log_error(f"Failed to create mobile device EA '{name}': {e.read().decode()}")


# ──────────────────────────────────────────────────────────────────────────────
# DATA FETCHING
# ──────────────────────────────────────────────────────────────────────────────

def fetch_asm_devices(asm_token: str) -> dict:
    """
    Fetch all devices from Apple (handles pagination automatically).
    Returns { serial_number: device_attributes_dict }.
    """
    all_devices = []
    next_url    = f"{ASM_BASE_URL}/v1/orgDevices"

    while next_url:
        page = http_get(next_url, asm_token)
        all_devices.extend(page.get("data", []))
        next_url = page.get("links", {}).get("next")
        if next_url:
            log_debug(f"Fetching next page: {next_url}")

    return {
        device["attributes"]["serialNumber"]: device["attributes"]
        for device in all_devices
    }


def fetch_jamf_computers(jamf_token: str) -> dict:
    """
    Fetch all computers from Jamf Pro (handles pagination automatically).
    Returns { serial_number: { id, name } }.
    Computers with no serial number recorded are skipped.
    """
    all_computers = {}
    page          = 0

    while True:
        url  = (f"{JAMF_URL}/api/v1/computers-inventory"
                f"?section=GENERAL&section=HARDWARE&page-size=100&page={page}")
        data = http_get(url, jamf_token)

        results = data.get("results", [])
        if not results:
            break

        for computer in results:
            serial = (computer.get("hardware") or {}).get("serialNumber")
            if serial:
                all_computers[serial] = {
                    "id":   computer["id"],
                    "name": (computer.get("general") or {}).get("name", "Unknown"),
                }
            else:
                log_debug(f"Skipping computer with no serial: id={computer.get('id')}")

        if len(all_computers) >= data.get("totalCount", 0):
            break
        page += 1

    return all_computers


def fetch_jamf_mobile_devices(jamf_token: str) -> dict:
    """
    Fetch all mobile devices from Jamf Pro (handles pagination automatically).
    Returns { serial_number: { id, name } }.
    Mobile devices with no serial number recorded are skipped.
    """
    all_devices = {}
    page        = 0

    while True:
        url  = (f"{JAMF_URL}/api/v2/mobile-devices"
                f"?section=GENERAL&page-size=100&page={page}")
        data = http_get(url, jamf_token)

        results = data.get("results", [])
        if not results:
            break

        for device in results:
            serial = device.get("serialNumber")
            if serial:
                all_devices[serial] = {
                    "id":   device["id"],
                    "name": device.get("name", "Unknown"),
                }
            else:
                log_debug(f"Skipping mobile device with no serial: id={device.get('id')}")

        if len(all_devices) >= data.get("totalCount", 0):
            break
        page += 1

    return all_devices


def fetch_applecare_coverage(serial: str, asm_token: str) -> dict:
    """
    Fetch AppleCare coverage plans for a device from Apple.

    Selection priority:
      1. Active, non-expired AppleCare+ plan  → populates all fields
      2. Active, non-expired standard warranty → used as a fallback
      3. No active coverage                    → all fields return None

    Returns a dict with the following keys:
      warrantyDate    — end date for the Jamf warrantyDate field
      appleCareId     — agreement number (AppleCare+ only)
      planType        — plan description (EA: AppleCare Plan Type)
      coverageStatus  — e.g. "ACTIVE" (EA: AppleCare Status)
      startDate       — coverage start date (EA: AppleCare Start Date)
      endDate         — coverage end date (EA: AppleCare End Date)
    """
    today    = time.time()
    response = http_get(f"{ASM_BASE_URL}/v1/orgDevices/{serial}/appleCareCoverage", asm_token)
    plans    = response.get("data", [])

    log_debug(f"AppleCare coverage for {serial}", response)

    result = {
        "warrantyDate":   None,
        "appleCareId":    None,
        "planType":       None,
        "coverageStatus": None,
        "startDate":      None,
        "endDate":        None,
    }

    for plan in plans:
        attrs = plan["attributes"]

        is_applecare_plus = "AppleCare" in attrs.get("description", "")
        is_active         = attrs.get("status") == "ACTIVE" and not attrs.get("isCanceled", False)
        end_date_str      = attrs.get("endDateTime")
        is_not_expired    = (
            end_date_str is None
            or time.mktime(time.strptime(end_date_str[:10], "%Y-%m-%d")) > today
        )

        if not (is_active and is_not_expired):
            log_debug(f"  Skipping plan '{attrs.get('description')}': active={is_active}, expired={not is_not_expired}")
            continue

        start_date = attrs["startDateTime"][:10] if attrs.get("startDateTime") else None
        end_date   = end_date_str[:10] if end_date_str else None

        if is_applecare_plus:
            # AppleCare+ takes full priority — stop after finding the first active plan
            result["warrantyDate"]   = end_date
            result["planType"]       = attrs.get("description")
            result["coverageStatus"] = attrs.get("status")
            result["startDate"]      = start_date
            result["endDate"]        = end_date
            agreement = attrs.get("agreementNumber")
            if agreement and agreement != "null":
                result["appleCareId"] = agreement
            log_debug(f"  Found active AppleCare+: {result}")
            break
        elif result["warrantyDate"] is None:
            # Standard warranty fallback — keep looking in case there is also an AppleCare+ plan
            result["warrantyDate"]   = end_date
            result["planType"]       = attrs.get("description")
            result["coverageStatus"] = attrs.get("status")
            result["startDate"]      = start_date
            result["endDate"]        = end_date
            log_debug(f"  Found standard warranty (keeping as fallback): {result}")

    return result


# ──────────────────────────────────────────────────────────────────────────────
# PURCHASING PAYLOAD BUILDER
#
# Maps Apple device data to Jamf Pro's purchasing fields.
# Fields with no value are excluded so we don't overwrite existing Jamf data
# with blanks if Apple doesn't have that information.
#
# Apple field               → Jamf Pro field (computers + mobile devices)
# ───────────────────────────────────────────────────────────────────────
# orderDateTime             → poDate
# orderNumber               → poNumber
# purchaseSourceId          → vendor  (mapped via VENDOR_MAP)
# coverage endDateTime      → warrantyDate / warrantyExpiresDate
# coverage agreementNumber  → appleCareId
# coverage description      → EA: AppleCare Plan Type
# coverage status           → EA: AppleCare Status
# coverage startDateTime    → EA: AppleCare Start Date
# coverage endDateTime      → EA: AppleCare End Date
# ──────────────────────────────────────────────────────────────────────────────

def build_jamf_purchasing_payload(asm_attributes: dict, applecare: dict, ea_id_map: dict) -> dict:
    """
    Build the JSON body for PATCH /api/v3/computers-inventory-detail/{id}.

    The Jamf Pro v3 API expects extensionAttributes at the top level of the
    request body, as a sibling of purchasing — not nested inside it.

    ea_id_map — name→id dict returned by ensure_computer_eas(), used so
                extension attributes are referenced by their live Jamf ID
                rather than hardcoded values.
    """
    order_date = (asm_attributes.get("orderDateTime") or "")[:10] or None
    po_number  = asm_attributes.get("orderNumber") or None
    vendor_raw = asm_attributes.get("purchaseSourceId") or None
    vendor     = VENDOR_MAP.get(vendor_raw, vendor_raw)   # map code → name if known

    purchasing_fields = {
        "poDate":       order_date,
        "poNumber":     po_number,
        "vendor":       vendor,
        "warrantyDate": applecare.get("warrantyDate"),
        "appleCareId":  applecare.get("appleCareId"),
    }

    # Extension attributes — look up the live definition ID for each EA by name
    ea_values = {
        ea_id_map.get("AppleCare Plan Type"):  applecare.get("planType"),
        ea_id_map.get("AppleCare Status"):     applecare.get("coverageStatus"),
        ea_id_map.get("AppleCare Start Date"): applecare.get("startDate"),
        ea_id_map.get("AppleCare End Date"):   applecare.get("endDate"),
    }
    extension_attributes = [
        {"definitionId": def_id, "values": [value]}
        for def_id, value in ea_values.items()
        if def_id is not None and value is not None
    ]

    # extensionAttributes must be top-level in the request body, not inside purchasing
    payload = {"purchasing": {k: v for k, v in purchasing_fields.items() if v is not None}}
    if extension_attributes:
        payload["extensionAttributes"] = extension_attributes

    return payload


def build_mobile_device_payload(asm_attributes: dict, applecare: dict) -> dict:
    """
    Build the JSON body for PATCH /api/v2/mobile-devices/{id}.

    Purchasing fields sit under ios.purchasing.
    Extension attributes use the updatedExtensionAttributes key, referenced
    by name — no EA ID lookup needed for mobile devices.

    Dates must be in ISO 8601 format with time component (YYYY-MM-DDT00:00:00Z).
    """
    order_date = (asm_attributes.get("orderDateTime") or "")[:10] or None
    po_number  = asm_attributes.get("orderNumber") or None
    vendor_raw = asm_attributes.get("purchaseSourceId") or None
    vendor     = VENDOR_MAP.get(vendor_raw, vendor_raw) if vendor_raw else None

    warranty_date  = applecare.get("warrantyDate")
    apple_care_id  = applecare.get("appleCareId")

    purchasing = {}
    if po_number:
        purchasing["poNumber"] = po_number
    if vendor:
        purchasing["vendor"] = vendor
    if order_date:
        purchasing["poDate"] = f"{order_date}T00:00:00Z"
    if warranty_date:
        purchasing["warrantyExpiresDate"] = f"{warranty_date}T00:00:00Z"
    if apple_care_id:
        purchasing["appleCareId"] = apple_care_id

    # Extension attributes — only include those with a value
    ea_entries = {
        "AppleCare Plan Type":  applecare.get("planType"),
        "AppleCare Status":     applecare.get("coverageStatus"),
        "AppleCare Start Date": applecare.get("startDate"),
        "AppleCare End Date":   applecare.get("endDate"),
    }
    updated_eas = [
        {"name": name, "type": "STRING", "value": [value]}
        for name, value in ea_entries.items()
        if value is not None
    ]

    payload = {"ios": {"purchasing": purchasing}}
    if updated_eas:
        payload["updatedExtensionAttributes"] = updated_eas

    return payload


# ──────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────

def run_setup_only():
    """
    Standalone EA setup mode (--setup-only).
    Checks that the four AppleCare extension attributes exist in Jamf Pro
    for both Computers and Mobile Devices, and creates any that are missing.
    Does not need Apple credentials.
    """
    log("=" * 65)
    log("  Jamf Pro — AppleCare Extension Attribute Setup")
    log("=" * 65)
    log(f"  Jamf URL: {JAMF_URL}")
    if DEBUG:
        log("  DEBUG mode is ON — verbose output enabled")

    log_step(1, 2, "Authenticating with Jamf Pro...")
    jamf_token = get_jamf_access_token()
    log_success("Jamf Pro token obtained")

    log_step(2, 2, "Verifying AppleCare extension attributes...")
    log("\n  Computers:")
    jamf_token = get_jamf_access_token()
    ensure_computer_eas(jamf_token)

    log("\n  Mobile Devices:")
    jamf_token = get_jamf_access_token()
    ensure_mobile_device_eas(jamf_token)

    log("\n" + "=" * 65)
    log("  Extension attribute setup complete.")
    log("=" * 65)


def main():
    parser = argparse.ArgumentParser(
        description="Sync purchasing data from Apple Business/School Manager into Jamf Pro.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument(
        "--setup-only",
        action="store_true",
        help="Only verify/create the required extension attributes in Jamf Pro. "
             "Does not run a full sync and does not need Apple credentials.",
    )
    args = parser.parse_args()

    if args.setup_only:
        run_setup_only()
        return

    log("=" * 65)
    log(f"  {ASM_SERVICE} → Jamf Pro  |  Purchasing Sync")
    log("=" * 65)
    log(f"  Service:   {ASM_SERVICE}")
    log(f"  Client ID: {ASM_CLIENT_ID}")
    log(f"  Key file:  {ASM_KEY_FILE}")
    log(f"  Jamf URL:  {JAMF_URL}")
    if DEBUG:
        log("  DEBUG mode is ON — verbose output enabled")

    # ── Step 1: Authenticate ─────────────────────────────────────────────────
    log_step(1, 6, "Authenticating...")
    asm_token  = get_asm_access_token()
    log_success(f"{ASM_SERVICE} token obtained")
    jamf_token = get_jamf_access_token()
    log_success("Jamf Pro token obtained")

    # ── Step 2: Verify extension attributes — create any that are missing ───────
    log_step(2, 6, "Verifying AppleCare extension attributes in Jamf Pro...")
    log("\n  Computers:")
    jamf_token = get_jamf_access_token()
    ea_id_map  = ensure_computer_eas(jamf_token)

    log("\n  Mobile Devices:")
    jamf_token = get_jamf_access_token()
    ensure_mobile_device_eas(jamf_token)

    # ── Step 3: Fetch all devices from Apple ─────────────────────────────────
    log_step(3, 6, f"Fetching all devices from {ASM_SERVICE}...")
    asm_devices = fetch_asm_devices(asm_token)
    log_success(f"{len(asm_devices)} devices found in {ASM_SERVICE}")

    # ── Step 4: Fetch all devices from Jamf ──────────────────────────────────
    log_step(4, 6, "Fetching all devices from Jamf Pro...")
    jamf_token          = get_jamf_access_token()
    jamf_computers      = fetch_jamf_computers(jamf_token)
    log_success(f"{len(jamf_computers)} computers found in Jamf Pro")
    jamf_token          = get_jamf_access_token()
    jamf_mobile_devices = fetch_jamf_mobile_devices(jamf_token)
    log_success(f"{len(jamf_mobile_devices)} mobile devices found in Jamf Pro")

    # Work out which serials appear in both systems — computers
    comp_matched  = {s for s in asm_devices if s in jamf_computers}
    comp_asm_only = {s for s in asm_devices if s not in jamf_computers}
    comp_jamf_only = {s for s in jamf_computers if s not in asm_devices}

    # Work out which serials appear in both systems — mobile devices
    mob_matched   = {s for s in asm_devices if s in jamf_mobile_devices}
    mob_asm_only  = {s for s in asm_devices if s not in jamf_mobile_devices}
    mob_jamf_only = {s for s in jamf_mobile_devices if s not in asm_devices}

    log(f"\n  Computers   — matched: {len(comp_matched)}  "
        f"Apple only: {len(comp_asm_only)}  Jamf only: {len(comp_jamf_only)}")
    log(f"  Mobile devs — matched: {len(mob_matched)}  "
        f"Apple only: {len(mob_asm_only)}  Jamf only: {len(mob_jamf_only)}")

    if len(comp_matched) == 0 and len(mob_matched) == 0:
        log_warning("No matching devices found in either category.")
        log_warning("This usually means the devices in Jamf were not purchased")
        log_warning("through this Apple Business/School Manager account.")

    if DEBUG:
        if comp_jamf_only:
            log("\n  Computers in Jamf but not in Apple:")
            for s in sorted(comp_jamf_only):
                log(f"    {s}  ({jamf_computers[s]['name']})")
        if mob_jamf_only:
            log("\n  Mobile devices in Jamf but not in Apple:")
            for s in sorted(mob_jamf_only):
                log(f"    {s}  ({jamf_mobile_devices[s]['name']})")

    # ── Step 5: Update matched computers ─────────────────────────────────────
    log_step(5, 6, f"Updating {len(comp_matched)} computer(s) in Jamf Pro...\n")

    comp_updated = []
    comp_failed  = []

    ea_id_to_name = {v: k for k, v in ea_id_map.items()}   # inverted for readable logging

    for serial in sorted(comp_matched):
        asm_data  = asm_devices[serial]
        jamf_info = jamf_computers[serial]
        jamf_id   = jamf_info["id"]
        jamf_name = jamf_info["name"]

        log(f"  ── {serial}  |  {jamf_name}  (Jamf ID: {jamf_id})")

        time.sleep(ASM_RATE_LIMIT_DELAY_SECONDS)
        applecare = fetch_applecare_coverage(serial, asm_token)
        payload   = build_jamf_purchasing_payload(asm_data, applecare, ea_id_map)

        for field, value in payload.get("purchasing", {}).items():
            log_detail(field, value)
        for ea in payload.get("extensionAttributes", []):
            ea_label = ea_id_to_name.get(ea["definitionId"], f"EA [{ea['definitionId']}]")
            log_detail(f"EA: {ea_label}", ea["values"][0])

        jamf_token = get_jamf_access_token()   # refresh before write
        status = http_patch(
            url   = f"{JAMF_URL}/api/v3/computers-inventory-detail/{jamf_id}",
            token = jamf_token,
            body  = payload,
        )

        if status == 204:   # Jamf v3 returns 204 No Content on success
            log_success("Updated successfully\n")
            comp_updated.append(serial)
        else:
            log_error(f"Update failed (HTTP {status})\n")
            comp_failed.append(serial)

    # ── Step 6: Update matched mobile devices ────────────────────────────────
    log_step(6, 6, f"Updating {len(mob_matched)} mobile device(s) in Jamf Pro...\n")

    mob_updated = []
    mob_failed  = []

    for serial in sorted(mob_matched):
        asm_data  = asm_devices[serial]
        jamf_info = jamf_mobile_devices[serial]
        jamf_id   = jamf_info["id"]
        jamf_name = jamf_info["name"]

        log(f"  ── {serial}  |  {jamf_name}  (Jamf ID: {jamf_id})")

        time.sleep(ASM_RATE_LIMIT_DELAY_SECONDS)
        applecare = fetch_applecare_coverage(serial, asm_token)
        payload   = build_mobile_device_payload(asm_data, applecare)

        # Log the fields that will be written
        purch = payload.get("ios", {}).get("purchasing", {})
        for field, value in purch.items():
            log_detail(field, value)
        for ea in payload.get("updatedExtensionAttributes", []):
            log_detail(f"EA: {ea['name']}", ea["value"][0])

        jamf_token = get_jamf_access_token()   # refresh before write
        status = http_patch(
            url   = f"{JAMF_URL}/api/v2/mobile-devices/{jamf_id}",
            token = jamf_token,
            body  = payload,
        )

        if status == 200:   # Jamf v2 returns 200 OK on success
            log_success("Updated successfully\n")
            mob_updated.append(serial)
        else:
            log_error(f"Update failed (HTTP {status})\n")
            mob_failed.append(serial)

    # ── Summary ───────────────────────────────────────────────────────────────
    total_updated = len(comp_updated) + len(mob_updated)
    total_failed  = len(comp_failed)  + len(mob_failed)
    log("=" * 65)
    log(f"  Computers   — updated: {len(comp_updated)}  failed: {len(comp_failed)}")
    log(f"  Mobile devs — updated: {len(mob_updated)}  failed: {len(mob_failed)}")
    log(f"  Total updated: {total_updated}  |  Total failed: {total_failed}")
    if comp_failed:
        log(f"\n  Failed computers:")
        for serial in comp_failed:
            log(f"    {serial}  ({jamf_computers[serial]['name']})")
    if mob_failed:
        log(f"\n  Failed mobile devices:")
        for serial in mob_failed:
            log(f"    {serial}  ({jamf_mobile_devices[serial]['name']})")
    log("=" * 65)


if __name__ == "__main__":
    main()
