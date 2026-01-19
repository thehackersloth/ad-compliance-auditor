# Quick Start Guide for MSPs

## Download & Run (30 seconds)

```powershell
# 1. Download/clone from GitHub
git clone https://github.com/thehackersloth/ad-compliance-auditor.git
cd ad-compliance-auditor

# 2. Run with interactive menu (EASIEST - Recommended)
.\AD-Audit-Script.ps1

# OR run automated audit & fix for client
.\AD-Audit-Script.ps1 -ClientName "Client Name" -Framework HIPAA -AutoFix -AutoApplyStandardSettings

# 3. Review reports in .\Reports\ folder
```

## That's It! ✅

The script will:
1. ✅ Audit Active Directory against compliance framework
2. ✅ Automatically fix ~90% of issues
3. ✅ Create and enforce security GPO
4. ✅ Generate reports (HTML, CSV, JSON)
5. ✅ Rescan to verify fixes

## Common Commands

### Standard Client Onboarding
```powershell
.\AD-Audit-Script.ps1 -ClientName "New Client" -Framework HIPAA -AutoFix -AutoApplyStandardSettings
```

### Monthly Compliance Check
```powershell
.\AD-Audit-Script.ps1 -ClientName "Existing Client" -Framework ALL -AuditOnly
```

### Quick Fix (Silent Mode)
```powershell
.\AD-Audit-Script.ps1 -ClientName "Client" -Framework CMMC -AutoFix -AutoApplyStandardSettings -Silent
```

## What Gets Fixed (90%)

- ✅ Password policies (length, complexity, expiration)
- ✅ Account lockout settings
- ✅ LM hash storage (disabled)
- ✅ Reversible encryption (disabled)
- ✅ SMBv1 (disabled)
- ✅ SMB signing/encryption (enabled)
- ✅ Kerberos encryption (AES only)
- ✅ Security GPOs (created and enforced)

## Advanced Auto-Fixes (90%+ Automation) ✅

- ✅ **Service Account Configurations**: Automatically sets password never expires
- ✅ **Domain Trust Relationships**: Automatically enables SID filtering for external trusts
- ✅ **Certificate/PKI Issues**: Automatically detects expiring certificates (warns, renewal manual)
- ✅ **Cloud Service Settings**: Automatically enables Microsoft 365 Security Defaults (if configured)
- ⚠️ **Separation of Duties**: Automatically flags violations (removal requires manual review for safety)

## What Still Requires Manual Review (<10%)

- ⚠️ Certificate renewal/replacement (detected automatically)
- ⚠️ Separation of duties group membership adjustments (flagged automatically, requires manual review)
- ⚠️ Forest trust selective authentication (external trust SID filtering auto-enabled)
- ⚠️ MSA conversion for service accounts (password never expires auto-set as interim fix)

## Reports Location

All reports saved to: `.\Reports\`

- HTML: Full audit report
- CSV: For ticketing systems
- JSON: For automation/APIs

## Need Help?

See README.md for detailed documentation.

For issues, feature requests, or contributions, visit: https://github.com/thehackersloth/ad-compliance-auditor
