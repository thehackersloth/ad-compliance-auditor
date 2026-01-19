# Change Log

All notable changes to the Active Directory Compliance Audit Script will be documented in this file.

## [1.3.0] - 2024-12-19

### Added
- **Organizational Unit (OU) Scanning and Selection:**
  - `Get-OrganizationalUnits` function to scan and list all OUs in the domain
  - Displays OU list with ID numbers, names, and Distinguished Names
  - Formatted table view for easy OU selection
  - `Select-TargetOU` function for interactive OU selection
  - Option to select domain root (0) or any OU from the list
  - Support for manual Distinguished Name entry with validation
- **Updated GPO Naming Convention:**
  - Changed from `Compliance-{Framework}-{Date}` to `defaultSecurityPolicy-{CurrentDate}`
  - Consistent naming across all compliance frameworks
  - Format: `defaultSecurityPolicy-yyyyMMdd` (e.g., `defaultSecurityPolicy-20241219`)

### Enhanced
- Post-audit GPO workflow now scans OUs automatically
- Interactive OU selection replaces manual DN entry requirement
- Improved user experience with numbered OU selection
- Validation of manually entered Distinguished Names
- Clear display of selected OU before GPO linking

### Technical Details
- OU scanning uses `Get-ADOrganizationalUnit` cmdlet
- OUs are sorted by Distinguished Name for consistent ordering
- Domain root option (0) is always available for GPO linking
- Invalid selections default to domain root with user notification

## [1.2.0] - 2024-12-19

### Added
- **Group Policy Object (GPO) Management Functionality:**
  - Create and configure compliance GPOs for each framework
  - Automatically configure GPO settings including:
    - Password policies (minimum length, complexity, history, age)
    - Account lockout policies
    - Audit policies (account logon, account management, directory service access, etc.)
    - Kerberos encryption settings (AES128 and AES256)
    - Security options and configurations
  - Link GPOs to domain root or specific Organizational Units (OUs)
  - Enforce GPO links to prevent override
  - Update existing GPOs if they already exist
  - Framework-specific GPO configurations
- **Enhanced Post-Audit Options:**
  - Apply fixes only
  - Create and enforce GPO only
  - Apply fixes AND create/enforce GPO (combined workflow)
  - Integrated GPO creation into fix workflow
- New helper functions:
  - `New-ComplianceGPO` - Creates or updates compliance GPOs
  - `Set-GPOPasswordPolicy` - Configures password policy settings in GPO
  - `Set-GPOAccountLockoutPolicy` - Configures account lockout settings
  - `Set-GPOAuditPolicy` - Configures comprehensive audit logging
  - `Set-GPOKerberosEncryption` - Configures Kerberos encryption types
  - `Set-GPOSecurityOptions` - Configures security options
  - `New-FrameworkGPO` - Creates framework-specific GPO configurations
  - `Set-GPOLink` - Links GPOs to domain or OUs with enforcement option
  - `Invoke-ApplyComplianceGPO` - Complete GPO application workflow
  - `Invoke-PostAuditOptions` - Unified post-audit workflow handler

### Enhanced
- All compliance frameworks now support GPO creation and enforcement
- GPO settings automatically configured based on compliance requirements
- GPOs can be linked to domain root or specific OUs
- Enforcement option prevents GPO override by child OUs
- Improved workflow with integrated fix and GPO management

### Technical Details
- Requires GroupPolicy PowerShell module (RSAT-GP feature)
- GPO changes take effect on next Group Policy refresh cycle
- Script tracks all created GPOs for reporting
- GPOs are named with format: "Compliance-{Framework}-{Date}"

## [1.1.0] - 2024-12-19

### Added
- Five new compliance framework audit options:
  - GLBA (Gramm-Leach-Bliley Act) - Financial institution compliance
  - SOX (Sarbanes-Oxley) - Financial reporting compliance
  - PCI-DSS - Payment card industry compliance
  - GDPR - European data protection compliance
  - FISMA - Federal information security compliance
- New audit checks:
  - Separation of duties validation (checks for users in multiple privileged groups)
  - Audit logging configuration verification
  - Data access control validation (GDPR - excessive group memberships)
  - Password reuse detection (accounts with passwords unchanged for 180+ days)
- Expanded menu system with 8 compliance framework options plus exit

### Enhanced
- All new frameworks include appropriate audit checks tailored to their specific requirements
- Each framework maintains full fix, rescan, and reporting functionality

## [1.0.0] - 2024-12-19

### Added
- Initial release of AD-Audit-Script.ps1
- Menu system with three compliance framework options:
  - HIPAA Compliance Audit
  - CMMC Compliance Audit
  - NIST/CIS Baseline Audit
- Comprehensive audit checks:
  - Password policy validation (length, complexity, history, age)
  - Account lockout policy checks
  - Inactive account detection
  - Password never expires account detection
  - MFA requirement verification for privileged accounts
  - Service account auditing
  - Empty group detection
  - Disabled account cleanup
  - Kerberos encryption verification
- HTML report generation with:
  - Executive summary with severity breakdown
  - Detailed findings table
  - Color-coded severity indicators
  - Responsive design
- Automated fix functionality:
  - Fix script execution for identified issues
  - Confirmation prompts before applying fixes
  - Error handling for failed fixes
- Rescan and comparison:
  - Automatic rescan after fixes are applied
  - Fix report generation showing what was fixed
  - Post-fix audit report generation
  - Comparison capability between before and after reports

### Technical Details
- Requires ActiveDirectory PowerShell module
- Requires GroupPolicy PowerShell module (added in v1.2.0)
- Requires Domain Administrator or equivalent privileges
- Output reports saved to .\Reports directory by default
- All audit findings include category, severity, description, recommendation, and fix script

### Known Limitations
- MFA checks are placeholder implementations (requires customization based on MFA solution)
- Some checks may require manual review and cannot be automatically fixed
- Service account fixes require manual verification
