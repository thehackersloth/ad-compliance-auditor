# Active Directory Compliance Auditor

**For MSPs: Automated Active Directory Compliance Auditing & Remediation**

This script automatically audits and fixes 90% of common compliance issues across multiple frameworks: HIPAA, CMMC, NIST/CIS, GLBA, SOX, PCI-DSS, GDPR, and FISMA.

## Quick Start (MSP Workflow)

### 1. Download from GitHub
```powershell
# Clone the repository
git clone https://github.com/thehackersloth/ad-compliance-auditor.git
cd ad-compliance-auditor

# Or download ZIP and extract
```

### 2. Run Per Client (Interactive Menu - Recommended)

**Easiest way - just run the script:**
```powershell
.\AD-Audit-Script.ps1
```

The interactive menu will guide you through:
- Setting client name
- Selecting compliance framework
- Reviewing findings
- Applying fixes automatically
- Generating reports

### 2b. Automated Workflow (Advanced)

Automated command-line mode (for scripting/automation):
```powershell
# Run with auto-fix for specific framework
.\AD-Audit-Script.ps1 -ClientName "Acme Corporation" -Framework HIPAA -AutoFix -AutoApplyStandardSettings

# All compliance frameworks
.\AD-Audit-Script.ps1 -ClientName "Acme Corporation" -Framework ALL -AutoFix -AutoApplyStandardSettings
```

### 2c. Quick Audit Only (No Fixes)
```powershell
.\AD-Audit-Script.ps1 -ClientName "Acme Corporation" -Framework HIPAA -AuditOnly
```

### 3. Review Reports
All reports are saved to `.\Reports\` with client name prefix:
- `Acme_Corporation_HIPAA_Audit_20240115_143022.html`
- `Acme_Corporation_HIPAA_Audit_20240115_143022.csv`
- `Acme_Corporation_HIPAA_Audit_20240115_143022.json`

## Interactive Menu Guide

When you run the script without parameters, you'll see an interactive menu:

```
═══════════════════════════════════════════════════════════════
      Active Directory Compliance Auditor                    
      Automated Audit & Remediation (90%+ Automation)        
═══════════════════════════════════════════════════════════════

  COMPLIANCE FRAMEWORK AUDITS
   1.  HIPAA Compliance Audit (Healthcare)
   2.  CMMC Compliance Audit (DoD Contractors)
   3.  NIST/CIS Baseline Audit (General Security)
   4.  GLBA Audit (Financial Institutions)
   5.  SOX Audit (Public Companies)
   6.  PCI-DSS Audit (Payment Card Industry)
   7.  GDPR Audit (Data Privacy)
   8.  FISMA Audit (Federal Systems)

  TOOLS & OPTIONS
   9.  Configuration Menu (Enable/Disable Checks)
   10. Set Client Name
   11. View Audit History & Compare Reports
   12. Export Reports (CSV/JSON)
   13. Exit
```

### Menu Workflow:
1. **Option 10**: Set client name first (recommended)
2. **Option 1-8**: Select compliance framework to audit
3. After audit: Choose to apply fixes automatically
4. **Option 11**: Review audit history and compare results
5. **Option 12**: Export reports for ticketing systems

## Command Line Parameters (For Automation)

### Optional Parameters
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

#### Step 1: Set PowerShell Execution Policy
```powershell
# Check current execution policy
Get-ExecutionPolicy

# Set execution policy to allow script execution (run as Administrator)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser

# OR for all users (requires Administrator)
Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope LocalMachine

# If you get an error, you may need to run:
Set-ExecutionPolicy -ExecutionPolicy Bypass -Scope Process -Force
```

**Note:** `RemoteSigned` allows local scripts to run and requires downloaded scripts to be signed. `Bypass` allows all scripts but is less secure.

#### Step 2: Install Required Windows Features
```powershell
# Run PowerShell as Administrator
# Install required Windows features
Install-WindowsFeature RSAT-AD-PowerShell, RSAT-GP

# Verify modules are available
Get-Module -ListAvailable ActiveDirectory, GroupPolicy
```

#### Step 3: Verify Prerequisites
```powershell
# Check if you're running as Administrator
$currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
$isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
Write-Host "Running as Administrator: $isAdmin"

# Test domain connectivity
Get-ADDomain

# Test Group Policy access
Get-GPO -All | Select-Object -First 1
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
