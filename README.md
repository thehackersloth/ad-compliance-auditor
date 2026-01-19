# Active Directory Compliance Auditor

**For MSPs: Automated Active Directory Compliance Auditing & Remediation**

This script automatically audits and fixes 90% of common compliance issues across multiple frameworks: HIPAA, CMMC, NIST/CIS, GLBA, SOX, PCI-DSS, GDPR, and FISMA.

## Quick Start (MSP Workflow)

### 1. Download from GitHub
```powershell
# Clone the repository
git clone https://github.com/yourorg/ad-compliance-auditor.git
cd ad-compliance-auditor

# Or download ZIP and extract
```

### 2. Run Per Client (Recommended Workflow)

#### Option A: Automated Run & Fix (90% Automation)
```powershell
# Run with auto-fix for specific framework
.\AD-Audit-Script.ps1 -ClientName "Acme Corporation" -Framework HIPAA -AutoFix -AutoApplyStandardSettings

# All compliance frameworks
.\AD-Audit-Script.ps1 -ClientName "Acme Corporation" -Framework ALL -AutoFix -AutoApplyStandardSettings
```

#### Option B: Interactive Menu (Step-by-Step)
```powershell
# 1. Set client name first
.\AD-Audit-Script.ps1 -ClientName "Acme Corporation"

# 2. Follow menu prompts
#    - Select compliance framework
#    - Review findings
#    - Choose: Apply standard settings + GPO
```

#### Option C: Quick Audit Only (No Fixes)
```powershell
.\AD-Audit-Script.ps1 -ClientName "Acme Corporation" -Framework HIPAA -AuditOnly
```

### 3. Review Reports
All reports are saved to `.\Reports\` with client name prefix:
- `Acme_Corporation_HIPAA_Audit_20240115_143022.html`
- `Acme_Corporation_HIPAA_Audit_20240115_143022.csv`
- `Acme_Corporation_HIPAA_Audit_20240115_143022.json`

## Command Line Parameters

### Required
- `-ClientName` - Client name for this session (e.g., "Acme Corporation")

### Optional
- `-Framework` - Compliance framework: `HIPAA`, `CMMC`, `NIST`, `GLBA`, `SOX`, `PCI`, `GDPR`, `FISMA`, or `ALL`
- `-AutoFix` - Automatically fix issues without prompts (requires `-AutoApplyStandardSettings`)
- `-AutoApplyStandardSettings` - Apply standard compliance settings for selected framework
- `-AuditOnly` - Only audit, don't fix anything
- `-OutputPath` - Custom output path (default: `.\Reports`)
- `-ConfigPath` - Custom config path (default: `.\AD-Audit-Config.json`)
- `-Silent` - Run silently (only show errors)

## MSP Workflow Examples

### Standard Client Onboarding (HIPAA)
```powershell
.\AD-Audit-Script.ps1 `
    -ClientName "New Healthcare Client" `
    -Framework HIPAA `
    -AutoFix `
    -AutoApplyStandardSettings `
    -OutputPath ".\Clients\New_Healthcare_Client"
```

### Monthly Compliance Check (All Frameworks)
```powershell
# Audit all frameworks
.\AD-Audit-Script.ps1 -ClientName "Existing Client" -Framework ALL -AuditOnly

# Review reports, then apply fixes if needed
.\AD-Audit-Script.ps1 -ClientName "Existing Client" -Framework ALL -AutoFix -AutoApplyStandardSettings
```

### Quick Fix (CMMC for DoD Client)
```powershell
.\AD-Audit-Script.ps1 `
    -ClientName "DoD Contractor" `
    -Framework CMMC `
    -AutoFix `
    -AutoApplyStandardSettings `
    -Silent
```

## What Gets Fixed Automatically (90%+ Coverage)

### ✅ Password Policies
- Minimum password length (14 characters)
- Password complexity requirements
- Password expiration (90 days standard, 60 for CMMC/FISMA)
- Password history (24 passwords)
- Account lockout policies

### ✅ Account Security
- Disable LM hash storage
- Disable reversible encryption
- Remove password never expires from user accounts
- Account lockout thresholds and durations

### ✅ SMB Protocol Security
- Disable SMBv1 completely
- Require SMB signing
- Enable SMB encryption

### ✅ Kerberos Security
- Disable weak RC4 encryption
- Enforce AES128/AES256 encryption
- Configure ticket lifetimes

### ✅ Group Policy
- Create/enforce compliance GPO
- Apply security settings via GPO
- Link to domain or OU

### ✅ Advanced Auto-Fixes (Now Automated - 90%+ Coverage)
- **Service Account Configurations**: ✅ Automatically sets password never expires for service accounts
- **Domain Trust Relationships**: ✅ Automatically enables SID filtering for external trusts  
- **Certificate/PKI Issues**: ✅ Automatically detects and warns about expiring certificates (renewal still manual)
- **Cloud Service Settings**: ✅ Automatically enables Microsoft 365 Security Defaults (if configured)
- **Separation of Duties**: ⚠️ Flags violations automatically (removal requires manual review for safety)

### ⚠️ Still Requires Manual Review (<10%)
- **Certificate Renewal**: Automatically detected, but renewal/replacement requires manual steps
- **Separation of Duties Group Removals**: Automatically flagged, but requires manual review to avoid breaking access
- **Forest Trust Selective Authentication**: External trust SID filtering is auto-enabled, but forest trust selective auth requires manual configuration
- **Managed Service Account (MSA) Conversion**: Password never expires is auto-set as interim fix, but MSA conversion requires manual steps
- **Risky Sign-ins**: Detected automatically, but remediation requires manual review in Azure Portal

## Report Types

### HTML Report
- Full audit findings with severity color coding
- Executive summary
- Detailed recommendations
- Fix status tracking

### CSV Export
- Import into ticketing systems (ConnectWise, Autotask)
- Excel analysis
- Historical tracking

### JSON Export
- API integration
- Automation workflows
- Custom reporting

## Audit History

View audit history and compare progress:
```powershell
# Run script interactively
.\AD-Audit-Script.ps1 -ClientName "Client Name"

# Select: 11. View Audit History / Compare Reports
```

## Configuration

### Initial Setup (Optional)
Run script interactively and select: `9. Configuration Menu`

#### Enable Optional Checks:
- Enhanced Password Checks
- SMB Protocol Checks
- RBAC Permissions
- Certificate & PKI
- Multi-Domain Support

#### Cloud Service Integration:
- Microsoft 365 / Entra ID (requires Azure App Registration)
- Google Workspace (requires Service Account)

See configuration menu for detailed setup instructions.

## Requirements

### Windows Server
- Windows Server 2012 R2 or later
- RSAT-AD-PowerShell feature installed
- RSAT-GP feature installed
- Domain Administrator privileges

### PowerShell
- PowerShell 5.1 or later
- ActiveDirectory module
- GroupPolicy module

### Installation
```powershell
# Install required Windows features
Install-WindowsFeature RSAT-AD-PowerShell, RSAT-GP

# Verify modules are available
Get-Module -ListAvailable ActiveDirectory, GroupPolicy
```

## Safety Features

### Automatic Backups
- GPO backups before changes (if enabled in config)
- Domain configuration backups
- Backup location: `.\Backups\`

### Confirmation Prompts
- Requires explicit "YES" for auto-fix operations
- Shows preview of issues before fixing
- Reports what was fixed and what failed

### Rollback
- GPO backups can be restored
- Domain config backups available
- All changes logged in reports

## Troubleshooting

### "Cannot connect to Active Directory"
- Ensure running on domain controller or member server with RSAT
- Verify domain admin credentials
- Check network connectivity to domain controllers

### "Cannot access Group Policy"
- Install RSAT-GP feature
- Run as Domain Administrator
- Verify Group Policy Management Console works

### Fixes Not Applying
- Check GPO refresh: `gpupdate /force` on target systems
- Verify GPO is linked and enforced
- Review GPO backup/restore in config

## Support

For MSP support:
- GitHub Issues: [Link to your repo issues]
- Documentation: [Link to docs]
- Email: [Your MSP support email]

## License

[Your License Here]

## Version History

### v2.0 - MSP Automation
- Command-line automation
- 90% auto-fix coverage
- Client-based reporting
- Audit history tracking
- CSV/JSON export

### v1.0 - Initial Release
- Multi-framework compliance auditing
- Interactive menu system
- HTML reporting
- Basic fix capabilities
