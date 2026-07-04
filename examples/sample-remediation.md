# vulnpipe remediation plan

**10 recommended actions** resolving **15 findings**.

| # | Priority | Fixes | Worst | Action | Recommendation |
| ---: | ---: | ---: | --- | --- | --- |
| 1 | 173 | 3 | 🟣 Critical ⚠️ | Patch Apache httpd 2.4.49 on 10.0.0.5 | Apply vendor updates for Apache httpd 2.4.49 on 10.0.0.5. |
| 2 | 89 | 3 | 🔴 High | Patch OpenSSH 7.4 on 10.0.0.5 | Apply vendor updates for OpenSSH 7.4 on 10.0.0.5. |
| 3 | 56 | 1 | 🔴 High | Remediate: Cross Site Scripting (Reflected) | Validate input and contextually encode user-supplied data on output. |
| 4 | 56 | 1 | 🔴 High | Remediate: SQL Injection | Use parameterized queries / prepared statements. |
| 5 | 54 | 2 | 🔴 High | Patch nginx 1.18.0 on 10.0.0.6 | Apply vendor updates for nginx 1.18.0 on 10.0.0.6. |
| 6 | 35 | 1 | 🟠 Medium | Remediate: Vulnerable JS Library | Upgrade to the latest version of jquery. |
| 7 | 14 | 1 | 🟡 Low | Remediate: Application Error Disclosure | Configure the application to return generic error pages. |
| 8 | 14 | 1 | 🟡 Low | Remediate: Cookie without SameSite Attribute | Set the SameSite attribute on sensitive cookies. |
| 9 | 0 | 1 | 🔵 Info | Remediate: Timestamp Disclosure - Unix | Manually confirm that the timestamp data is not sensitive. |
| 10 | 0 | 1 | 🔵 Info | Patch MySQL 8.0.27 on 10.0.0.6 | Apply vendor updates for MySQL 8.0.27 on 10.0.0.6. |
