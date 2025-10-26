# ROPC Single‑Factor Login from New Country or App (MFA Bypass Risk)

## Detection KQL Query

```kusto
// === Parameters ===
let lookback = 14d;          // Baseline window
let detectionWindow = 1h;    // Recent window to check for deviations

// === Common filter & normalization ===
let baseFilter = materialize(
    SigninLogs
    | where AuthenticationRequirement == "singleFactorAuthentication"
    | where AuthenticationProtocol =~ "ropc"
    | where ResultSignature == "SUCCESS" or ResultType == 0
    | extend Loc = todynamic(LocationDetails)
    | extend Country = coalesce(tostring(Loc["countryOrRegion"]), tostring(Location), "Unknown")
    | extend App = iif(isempty(AppDisplayName), "Unknown App", AppDisplayName)
    | project TimeGenerated, UserPrincipalName, App, Country, AADTenantId, CorrelationId, IPAddress, UserAgent
);

// === Baseline over last 14d (exclude the last 1h to avoid contaminating baseline) ===
let baselineTriples =
    baseFilter
    | where TimeGenerated >= ago(lookback) and TimeGenerated < ago(detectionWindow)
    | summarize
        BaselineFirst = min(TimeGenerated),
        BaselineLast  = max(TimeGenerated),
        BaselineCount = count()
      by UserPrincipalName, App, Country;

let baselineByUserApp =
    baseFilter
    | where TimeGenerated >= ago(lookback) and TimeGenerated < ago(detectionWindow)
    | summarize
        BaselineCountries = make_set(Country, 100),
        BaselineEvents    = count(),
        BaselineFirstAny  = min(TimeGenerated),
        BaselineLastAny   = max(TimeGenerated)
      by UserPrincipalName, App;

// === Recent events (last 1h) ===
let recent =
    baseFilter
    | where TimeGenerated >= ago(detectionWindow);

// === Deviations = recent (user, app, country) NOT seen in baseline ===
recent
| join kind=leftanti (
    baselineTriples
) on UserPrincipalName, App, Country
// Enrich with what WAS normal for that user+app (countries set, counts, last seen)
| join kind=leftouter (
    baselineByUserApp
) on UserPrincipalName, App
| extend
    DeviationReason = iff(isnull(BaselineCountries),
                          "NoBaselineForUserApp (first ever in 14d)",
                          strcat("NewCountryForUserApp: ", Country)),
    BaselineSpanDays = iif(isnull(BaselineFirstAny) or isnull(BaselineLastAny),
                           real(null),
                           1.0 * datetime_diff('day', BaselineLastAny, BaselineFirstAny) + 1)
// Optional: group multiple hits for same user/app/country within the hour
| summarize
    FirstSeenHit = min(TimeGenerated),
    LastSeenHit  = max(TimeGenerated),
    HitCount     = count(),
    AnyIP        = make_set(IPAddress, 20),
    AnyUA        = make_set(UserAgent, 20),
    BaselineCountries = any(BaselineCountries),
    BaselineEvents    = any(BaselineEvents),
    BaselineFirstAny  = any(BaselineFirstAny),
    BaselineLastAny   = any(BaselineLastAny),
    BaselineSpanDays  = any(BaselineSpanDays),
    DeviationReason   = any(DeviationReason)
  by AADTenantId, UserPrincipalName, App, Country
| order by LastSeenHit desc

```


---


## Description

This detection identifies **single-factor ROPC (Resource Owner Password Credentials)** logins from **new countries** not seen in the last 14 days for a given **user+app** combination. ROPC authentication does not support MFA, making it a frequent vector for attackers to bypass MFA misconfigurations and gain initial access or escalate privileges in Azure AD.

---

### Query Illustration

* Pulls sign-in logs where ROPC + single-factor + successful login occurred.
* Establishes a 14-day baseline (excluding the last hour) of seen countries per user/app.
* Compares new 1-hour activity to that baseline.
* Flags user+app+country combinations not seen before.
* Enriches result with user’s historical context and deviation reason.

---

## Possible Attack Scenario

* Adversary gains credentials (phishing, password reuse, etc.).
* Uses `ropci` or custom tools to test **ROPC login** flow.
* Authenticates using a **built-in Microsoft app** (e.g., Office, Teams).
* Bypasses MFA due to **incomplete Conditional Access policies** or misconfigurations.
* Appears to login successfully from a new location (often via VPN or proxy).
* Uses the access token to query Graph API, read mail, download files, etc.

---

## Suggested Investigation Steps

1. Review the application ID and country flagged as anomalous.
2. Identify whether ROPC authentication is expected for that user.
3. Check for token issuance — what permissions were granted?
4. Investigate whether MFA is actually enforced via Conditional Access.
5. Review historical sign-ins and activity linked to the same IP, device, or token.
6. Pivot into `AuditLogs` and `AppAccessAuditLogs` to identify post-auth behavior.

---

## Suggested Response Actions

* **Revoke refresh tokens** for the affected user(s)
* **Reset credentials** for impacted users.
* **Explicitly enforce MFA** via Conditional Access — especially for legacy/auth flows.
* **Review and disable ROPC support** for all registered apps where possible.
* Implement **IP-based restrictions**, **app-based conditional access**, and **token lifetime policies**.

---

## Possible False Positives

* Legitimate international travel or VPN use.
* Admins using test apps or developer endpoints.
* Initial usage of new apps (first login scenario).

---

## Detection Blind Spots

* Users authenticating without location info (due to IP obfuscation or gaps in telemetry).
* Environments where ROPC is legitimately used by service accounts.
* ROPC bypass activity where the attacker uses existing refresh tokens (not captured here).
* Tenants relying only on **Security Defaults**, which don’t block all ROPC flows.

---

## MITRE Technique

* [T1078.004 — Valid Accounts: Cloud Accounts](https://attack.mitre.org/techniques/T1078/004/)
* [T1556.006 — Modify Authentication Process: Exploitation for MFA Bypass](https://attack.mitre.org/techniques/T1556/006/)
* [T1110.001 — Brute Force: Password Guessing](https://attack.mitre.org/techniques/T1110/001/)

---

## References

* [Microsoft: ROPC OAuth Flow](https://learn.microsoft.com/en-us/azure/active-directory/develop/v2-oauth-ropc)
* [ropci GitHub — MFA Bypass Testing Tool](https://github.com/wunderwuzzi23/ropci)
* [MFA Bypass & Dormant Cloud Account Abuse (ZDNet)](https://www.zdnet.com/article/hackers-are-using-this-sneaky-trick-to-exploit-dormant-microsoft-cloud-accounts-and-bypass-multi-factor-authentication/)
* [OAuth 2.0 Security Best Practices (RFC)](https://datatracker.ietf.org/doc/html/draft-ietf-oauth-security-topics#page-9)

