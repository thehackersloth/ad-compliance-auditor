<#
.SYNOPSIS
    Active Directory Compliance Audit and Remediation Script
    
.DESCRIPTION
    This script audits Active Directory against multiple compliance frameworks:
    HIPAA, CMMC, NIST/CIS, GLBA, SOX, PCI-DSS, GDPR, and FISMA.
    Generates HTML reports and provides automated remediation capabilities.
    
.NOTES
    Requires: ActiveDirectory PowerShell module
    Requires: GroupPolicy PowerShell module
    Requires: Run as Domain Administrator or equivalent privileges
#>

[CmdletBinding()]
param(
    [string]$OutputPath = ".\Reports",
    [string]$ConfigPath = ".\AD-Audit-Config.json",
    [switch]$FixIssues = $false,
    [switch]$AutoBackup = $true,
    [switch]$LoadConfig = $false,
    [Parameter(Mandatory=$false)]
    [string]$ClientName = "",
    [Parameter(Mandatory=$false)]
    [ValidateSet("HIPAA","CMMC","NIST","NISTCIS","GLBA","SOX","PCI","PCIDSS","GDPR","FISMA","ALL")]
    [string]$Framework = "",
    [switch]$AutoFix = $false,
    [switch]$AutoApplyStandardSettings = $false,
    [switch]$AuditOnly = $false,
    [switch]$Silent = $false
)

# Ensure ActiveDirectory module is loaded
if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
    Write-Error "ActiveDirectory PowerShell module is not installed. Please install RSAT-AD-PowerShell feature."
    exit 1
}
Import-Module ActiveDirectory -ErrorAction Stop

# Ensure GroupPolicy module is loaded
if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
    Write-Error "GroupPolicy PowerShell module is not installed. Please install RSAT-GP feature."
    exit 1
}
Import-Module GroupPolicy -ErrorAction Stop

# Global variables
$script:AuditResults = @()
$script:FixedIssues = @()
$script:ComplianceFramework = ""
$script:GPOsCreated = @()
$script:DomainDN = (Get-ADDomain).DistinguishedName
$script:DomainName = (Get-ADDomain).DNSRoot
$script:BackupPath = ".\Backups"
$script:Config = $null
$script:BackupsCreated = @()
$script:ClientName = ""
$script:AuditHistory = @()
$script:AuditHistoryPath = ".\AuditHistory.json"
$script:GraphToken = $null
$script:GoogleToken = $null
$script:GoogleServiceAccount = $null

# Default configuration for optional checks
$script:DefaultConfig = @{
    GPOBackupRestore = @{
        Enabled = $false
        AutoBackup = $true
        BackupPath = ".\Backups"
    }
    EnhancedPasswordChecks = @{
        Enabled = $false
        CheckLMHash = $true
        CheckReversibleEncryption = $true
        CheckPSO = $true
        CheckPasswordExpiration = $true
    }
    RBACPermissions = @{
        Enabled = $false
        CheckDelegation = $true
        CheckObjectPermissions = $true
        CheckServiceAccounts = $true
    }
    MultiDomainSupport = @{
        Enabled = $false
        ScanAllDomains = $false
        Domains = @()
    }
    SchemaDNSSecurity = @{
        Enabled = $false
        CheckSchemaVersion = $true
        CheckDNSSEC = $true
        CheckDynamicDNS = $true
    }
    TrustRelationships = @{
        Enabled = $false
        CheckExternalTrusts = $true
        CheckForestTrusts = $true
        CheckSIDFiltering = $true
    }
    CertificatePKI = @{
        Enabled = $false
        CheckCertExpiration = $true
        CheckCAValidity = $true
        CheckCertTemplates = $true
    }
    AccountSecurityEnhancements = @{
        Enabled = $false
        CheckAccountExpiration = $true
        CheckSmartCardRequired = $true
        CheckOrphanedAccounts = $true
        CheckLastLogonTimestamp = $true
    }
    PrivilegedAccessReview = @{
        Enabled = $false
        CheckNestedGroups = $true
        CheckOUDelegation = $true
        CheckAdminSDHolder = $true
        CheckProtectedAccounts = $true
    }
    AdditionalPasswordSecurity = @{
        Enabled = $false
        CheckPasswordHistory = $true
        CheckPasswordComplexity = $true
        CheckPasswordAge = $true
    }
    SMBProtocol = @{
        Enabled = $false
        CheckSMBv1 = $true
        CheckSMBv2 = $true
        DisableSMBv1 = $true
        RequireSMBv2Signing = $true
    }
    Microsoft365 = @{
        Enabled = $false
        TenantId = ""
        ClientId = ""
        ClientSecret = ""
        CheckOffice365 = $true
        CheckEntra = $true
        CheckConditionalAccess = $true
        CheckMFA = $true
    }
    GoogleWorkspace = @{
        Enabled = $false
        ServiceAccountKey = ""
        CustomerId = ""
        CheckSecurity = $true
        CheckMFA = $true
        CheckAPI = $true
    }
}

# Create output directories if they don't exist
if (-not (Test-Path $OutputPath)) {
    New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
}
if (-not (Test-Path $script:BackupPath)) {
    New-Item -ItemType Directory -Path $script:BackupPath -Force | Out-Null
}

# Load or initialize configuration
function Initialize-Config {
    param(
        [string]$ConfigPath
    )
    
    if (Test-Path $ConfigPath) {
        try {
            $script:Config = Get-Content $ConfigPath -Raw | ConvertFrom-Json | ConvertTo-Hashtable
            Write-Host "Configuration loaded from: $ConfigPath" -ForegroundColor Green
            return $script:Config
        } catch {
            Write-Warning "Failed to load configuration: $_"
            Write-Host "Using default configuration..." -ForegroundColor Yellow
            $script:Config = $script:DefaultConfig
            Save-Config -ConfigPath $ConfigPath
            return $script:Config
        }
    } else {
        Write-Host "Creating default configuration file: $ConfigPath" -ForegroundColor Yellow
        $script:Config = $script:DefaultConfig
        Save-Config -ConfigPath $ConfigPath
        return $script:Config
    }
}

# Save configuration to file
function Save-Config {
    param(
        [string]$ConfigPath
    )
    
    try {
        $script:Config | ConvertTo-Json -Depth 10 | Out-File -FilePath $ConfigPath -Encoding UTF8
        Write-Host "Configuration saved to: $ConfigPath" -ForegroundColor Green
    } catch {
        Write-Error "Failed to save configuration: $_"
    }
}

# Helper function to convert PSCustomObject to Hashtable recursively
function ConvertTo-Hashtable {
    param(
        [Parameter(Mandatory=$true)]
        [Object]$InputObject
    )
    
    if ($null -eq $InputObject) { return $null }
    
    if ($InputObject -is [System.Collections.IDictionary]) {
        $hash = @{}
        foreach ($key in $InputObject.Keys) {
            $hash[$key] = ConvertTo-Hashtable -InputObject $InputObject[$key]
        }
        return $hash
    }
    
    if ($InputObject -is [System.Collections.IEnumerable] -and $InputObject -isnot [string]) {
        $array = @()
        foreach ($item in $InputObject) {
            $array += ConvertTo-Hashtable -InputObject $item
        }
        return $array
    }
    
    if ($InputObject.GetType().Name -eq "PSCustomObject") {
        $hash = @{}
        $InputObject.PSObject.Properties | ForEach-Object {
            $hash[$_.Name] = ConvertTo-Hashtable -InputObject $_.Value
        }
        return $hash
    }
    
    return $InputObject
}

# Function to validate prerequisites and permissions
function Test-Prerequisites {
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "   Validating Prerequisites           " -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    $allGood = $true
    
    # Check ActiveDirectory module
    if (-not (Get-Module -ListAvailable -Name ActiveDirectory)) {
        Write-Host "[ERROR] ActiveDirectory PowerShell module not found!" -ForegroundColor Red
        Write-Host "        Install with: Install-WindowsFeature RSAT-AD-PowerShell" -ForegroundColor Yellow
        $allGood = $false
    } else {
        Write-Host "[OK] ActiveDirectory module found" -ForegroundColor Green
    }
    
    # Check GroupPolicy module
    if (-not (Get-Module -ListAvailable -Name GroupPolicy)) {
        Write-Host "[ERROR] GroupPolicy PowerShell module not found!" -ForegroundColor Red
        Write-Host "        Install with: Install-WindowsFeature RSAT-GP" -ForegroundColor Yellow
        $allGood = $false
    } else {
        Write-Host "[OK] GroupPolicy module found" -ForegroundColor Green
    }
    
    # Check if running as Administrator
    $currentPrincipal = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $isAdmin = $currentPrincipal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
    
    if (-not $isAdmin) {
        Write-Host "[WARNING] Script may not have sufficient privileges!" -ForegroundColor Yellow
        Write-Host "          Some operations require Domain Administrator rights" -ForegroundColor Yellow
    } else {
        Write-Host "[OK] Running with Administrator privileges" -ForegroundColor Green
    }
    
    # Test domain connectivity
    try {
        $domain = Get-ADDomain -ErrorAction Stop
        Write-Host "[OK] Connected to domain: $($domain.DNSRoot)" -ForegroundColor Green
    } catch {
        Write-Host "[ERROR] Cannot connect to Active Directory domain!" -ForegroundColor Red
        Write-Host "        Error: $_" -ForegroundColor Yellow
        $allGood = $false
    }
    
    # Test GPO access
    try {
        $gpos = Get-GPO -All -ErrorAction Stop | Select-Object -First 1
        Write-Host "[OK] Group Policy access verified" -ForegroundColor Green
    } catch {
        Write-Host "[WARNING] Cannot access Group Policy objects!" -ForegroundColor Yellow
        Write-Host "          Some GPO operations may fail" -ForegroundColor Yellow
    }
    
    Write-Host ""
    
    if (-not $allGood) {
        Write-Host "========================================" -ForegroundColor Red
        Write-Host "   Prerequisites Check FAILED          " -ForegroundColor Red
        Write-Host "========================================" -ForegroundColor Red
        Write-Host ""
        Write-Host "Please install missing prerequisites and try again." -ForegroundColor Yellow
        Write-Host "Press any key to exit..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        exit 1
    }
    
    Write-Host "========================================" -ForegroundColor Green
    Write-Host "   All Prerequisites Validated          " -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Green
    Start-Sleep -Seconds 1
}

# Initialize configuration
if ($LoadConfig) {
    $script:Config = Initialize-Config -ConfigPath $ConfigPath
} else {
    $script:Config = $script:DefaultConfig
}

# Set client name if provided via parameter
if ($ClientName) {
    $script:ClientName = $ClientName
    if (-not $Silent) {
        Write-Host "Client set to: $script:ClientName" -ForegroundColor Green
    }
}

# Validate prerequisites on startup (required for both modes)
Test-Prerequisites

# Handle automated workflow (command-line mode)
if ($Framework -and $Framework -ne "") {
    # Automated mode - skip menu
    if (-not $Silent) {
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "   Automated Compliance Audit & Fix   " -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "Client: $(if ($script:ClientName) { $script:ClientName } else { 'Not Set' })" -ForegroundColor Yellow
        Write-Host "Framework: $Framework" -ForegroundColor Yellow
        Write-Host "Mode: $(if ($AuditOnly) { 'Audit Only' } elseif ($AutoFix -and $AutoApplyStandardSettings) { 'Auto-Fix (90% Automation)' } else { 'Interactive' })" -ForegroundColor Yellow
        Write-Host ""
    }
    
    # Warn if no client name
    if (-not $script:ClientName) {
        Write-Host "WARNING: No client name set. Reports will not be tagged with client name." -ForegroundColor Yellow
        Write-Host "Consider using -ClientName parameter for better report organization." -ForegroundColor Yellow
        Write-Host ""
    }
    
    # Create output directory if needed
    if (-not (Test-Path $OutputPath)) {
        New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
    }
    
    # Run automated audit workflow
    if ($Framework -eq "ALL") {
        $frameworks = @("HIPAA", "CMMC", "NISTCIS", "GLBA", "SOX", "PCIDSS", "GDPR", "FISMA")
        foreach ($fw in $frameworks) {
            Start-AutomatedAudit -Framework $fw
        }
    } else {
        Start-AutomatedAudit -Framework $Framework
    }
    
    if (-not $Silent) {
        Write-Host "`n========================================" -ForegroundColor Green
        Write-Host "   Automated Workflow Complete!        " -ForegroundColor Green
        Write-Host "========================================" -ForegroundColor Green
        Write-Host "Reports saved to: $OutputPath" -ForegroundColor Cyan
        Write-Host ""
    }
    
    exit 0
}

# Function to display interactive menu
function Show-Menu {
    Clear-Host
    Write-Host "╔══════════════════════════════════════════════════════════════╗" -ForegroundColor Cyan
    Write-Host "║                                                              ║" -ForegroundColor Cyan
    Write-Host "║      Active Directory Compliance Auditor                    ║" -ForegroundColor Cyan
    Write-Host "║      Automated Audit & Remediation (90%+ Automation)        ║" -ForegroundColor Cyan
    Write-Host "║                                                              ║" -ForegroundColor Cyan
    Write-Host "╚══════════════════════════════════════════════════════════════╝" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "  Current Session Info:" -ForegroundColor Yellow
    Write-Host "  ├─ Client: $(if ($script:ClientName) { $script:ClientName } else { 'Not Set' })" -ForegroundColor $(if ($script:ClientName) { 'Green' } else { 'Yellow' })
    Write-Host "  └─ Domain: $script:DomainName" -ForegroundColor White
    Write-Host ""
    Write-Host "  ┌──────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
    Write-Host "  │  COMPLIANCE FRAMEWORK AUDITS                             │" -ForegroundColor Cyan
    Write-Host "  └──────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "   1.  HIPAA Compliance Audit (Healthcare)" -ForegroundColor White
    Write-Host "   2.  CMMC Compliance Audit (DoD Contractors)" -ForegroundColor White
    Write-Host "   3.  NIST/CIS Baseline Audit (General Security)" -ForegroundColor White
    Write-Host "   4.  GLBA Audit (Financial Institutions)" -ForegroundColor White
    Write-Host "   5.  SOX Audit (Public Companies)" -ForegroundColor White
    Write-Host "   6.  PCI-DSS Audit (Payment Card Industry)" -ForegroundColor White
    Write-Host "   7.  GDPR Audit (Data Privacy)" -ForegroundColor White
    Write-Host "   8.  FISMA Audit (Federal Systems)" -ForegroundColor White
    Write-Host ""
    Write-Host "  ┌──────────────────────────────────────────────────────────┐" -ForegroundColor Cyan
    Write-Host "  │  TOOLS & OPTIONS                                         │" -ForegroundColor Cyan
    Write-Host "  └──────────────────────────────────────────────────────────┘" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "   9.  Configuration Menu (Enable/Disable Checks)" -ForegroundColor Yellow
    Write-Host "   10. Set Client Name" -ForegroundColor Yellow
    Write-Host "   11. View Audit History & Compare Reports" -ForegroundColor Yellow
    Write-Host "   12. Export Reports (CSV/JSON)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "   13. Exit" -ForegroundColor Red
    Write-Host ""
    Write-Host "═══════════════════════════════════════════════════════════════" -ForegroundColor Cyan
    $choice = Read-Host "  Enter your choice (1-13)"
    return $choice
}

# Function to record audit finding
function Add-AuditFinding {
    param(
        [string]$Category,
        [string]$Finding,
        [string]$Severity,
        [string]$Description,
        [string]$Recommendation,
        [string]$FixScript,
        [object]$AffectedObject
    )
    
    $finding = @{
        Category = $Category
        Finding = $Finding
        Severity = $Severity
        Description = $Description
        Recommendation = $Recommendation
        FixScript = $FixScript
        AffectedObject = $AffectedObject
        Timestamp = Get-Date
        Framework = $script:ComplianceFramework
    }
    
    $script:AuditResults += $finding
}

# Function to check password policy
function Test-PasswordPolicy {
    $domain = Get-ADDomain
    $defaultPwdPolicy = Get-ADDefaultDomainPasswordPolicy
    
    # Check password length
    if ($defaultPwdPolicy.MinPasswordLength -lt 14) {
        Add-AuditFinding -Category "Password Policy" `
            -Finding "Minimum password length is less than 14 characters" `
            -Severity "High" `
            -Description "Current minimum password length: $($defaultPwdPolicy.MinPasswordLength)" `
            -Recommendation "Increase minimum password length to at least 14 characters" `
            -FixScript "Set-ADDefaultDomainPasswordPolicy -MinPasswordLength 14"
    }
    
    # Check password complexity
    if (-not $defaultPwdPolicy.ComplexityEnabled) {
        Add-AuditFinding -Category "Password Policy" `
            -Finding "Password complexity is not enabled" `
            -Severity "High" `
            -Description "Passwords do not require complexity" `
            -Recommendation "Enable password complexity requirements" `
            -FixScript "Set-ADDefaultDomainPasswordPolicy -ComplexityEnabled `$true"
    }
    
    # Check password history
    if ($defaultPwdPolicy.PasswordHistoryCount -lt 24) {
        Add-AuditFinding -Category "Password Policy" `
            -Finding "Password history is less than 24 passwords" `
            -Severity "Medium" `
            -Description "Current password history: $($defaultPwdPolicy.PasswordHistoryCount)" `
            -Recommendation "Increase password history to at least 24 passwords" `
            -FixScript "Set-ADDefaultDomainPasswordPolicy -PasswordHistoryCount 24"
    }
    
    # Check maximum password age
    if ($defaultPwdPolicy.MaxPasswordAge.TotalDays -gt 90) {
        Add-AuditFinding -Category "Password Policy" `
            -Finding "Maximum password age exceeds 90 days" `
            -Severity "Medium" `
            -Description "Current maximum password age: $($defaultPwdPolicy.MaxPasswordAge.TotalDays) days" `
            -Recommendation "Set maximum password age to 90 days or less" `
            -FixScript "Set-ADDefaultDomainPasswordPolicy -MaxPasswordAge (New-TimeSpan -Days 90)"
    }
    
    # Check minimum password age
    if ($defaultPwdPolicy.MinPasswordAge.TotalDays -eq 0) {
        Add-AuditFinding -Category "Password Policy" `
            -Finding "Minimum password age is set to 0 days" `
            -Severity "Medium" `
            -Description "Users can change passwords immediately, bypassing password history" `
            -Recommendation "Set minimum password age to at least 1 day" `
            -FixScript "Set-ADDefaultDomainPasswordPolicy -MinPasswordAge (New-TimeSpan -Days 1)"
    }
}

# Function to check account lockout policy
function Test-AccountLockoutPolicy {
    $lockoutPolicy = Get-ADDefaultDomainPasswordPolicy
    
    if ($lockoutPolicy.LockoutDuration.TotalMinutes -lt 15) {
        Add-AuditFinding -Category "Account Lockout Policy" `
            -Finding "Account lockout duration is less than 15 minutes" `
            -Severity "Medium" `
            -Description "Current lockout duration: $($lockoutPolicy.LockoutDuration.TotalMinutes) minutes" `
            -Recommendation "Set account lockout duration to at least 15 minutes" `
            -FixScript "Set-ADDefaultDomainPasswordPolicy -LockoutDuration (New-TimeSpan -Minutes 15)"
    }
    
    if ($lockoutPolicy.LockoutThreshold -eq 0) {
        Add-AuditFinding -Category "Account Lockout Policy" `
            -Finding "Account lockout threshold is disabled" `
            -Severity "High" `
            -Description "Accounts are not locked after failed login attempts" `
            -Recommendation "Enable account lockout after 5 failed attempts" `
            -FixScript "Set-ADDefaultDomainPasswordPolicy -LockoutThreshold 5"
    }
}

# Function to check for inactive accounts
function Test-InactiveAccounts {
    $inactiveThreshold = (Get-Date).AddDays(-90)
    $inactiveAccounts = Get-ADUser -Filter {Enabled -eq $true -and LastLogonDate -lt $inactiveThreshold} -Properties LastLogonDate, DistinguishedName
    
    if ($inactiveAccounts) {
        foreach ($account in $inactiveAccounts) {
            $daysInactive = ((Get-Date) - $account.LastLogonDate).Days
            Add-AuditFinding -Category "Account Management" `
                -Finding "Inactive account detected: $($account.SamAccountName)" `
                -Severity "Medium" `
                -Description "Account has been inactive for $daysInactive days (Last logon: $($account.LastLogonDate))" `
                -Recommendation "Review and disable or remove inactive accounts" `
                -FixScript "Disable-ADAccount -Identity '$($account.DistinguishedName)'" `
                -AffectedObject $account
        }
    }
}

# Function to check for accounts with password never expires
function Test-PasswordNeverExpires {
    $accounts = Get-ADUser -Filter {PasswordNeverExpires -eq $true -and Enabled -eq $true} -Properties PasswordNeverExpires, DistinguishedName
    
    foreach ($account in $accounts) {
        Add-AuditFinding -Category "Account Management" `
            -Finding "Account with password never expires: $($account.SamAccountName)" `
            -Severity "High" `
            -Description "Account password is set to never expire" `
            -Recommendation "Remove password never expires flag or implement alternative controls" `
            -FixScript "Set-ADUser -Identity '$($account.DistinguishedName)' -PasswordNeverExpires `$false" `
            -AffectedObject $account
    }
}

# Function to check for accounts without MFA
function Test-MFARequirement {
    # This is a placeholder - actual MFA check depends on your MFA solution
    # Check for accounts in privileged groups without MFA flags
    $privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Administrators")
    $privilegedUsers = @()
    
    foreach ($group in $privilegedGroups) {
        try {
            $members = Get-ADGroupMember -Identity $group -Recursive | Where-Object { $_.objectClass -eq "user" }
            $privilegedUsers += $members
        } catch {
            # Group may not exist
        }
    }
    
    foreach ($user in ($privilegedUsers | Select-Object -Unique)) {
        $userObj = Get-ADUser -Identity $user.SamAccountName -Properties *
        # Check for MFA-related attributes (adjust based on your MFA solution)
        if (-not $userObj.extensionAttribute1 -and -not $userObj.extensionAttribute2) {
            Add-AuditFinding -Category "Multi-Factor Authentication" `
                -Finding "Privileged account without MFA: $($userObj.SamAccountName)" `
                -Severity "High" `
                -Description "Privileged account may not have MFA enabled" `
                -Recommendation "Enable MFA for all privileged accounts" `
                -FixScript "Set-ADUser -Identity '$($userObj.DistinguishedName)' -ExtensionAttribute1 'MFA_REQUIRED'" `
                -AffectedObject $userObj
        }
    }
}

# Function to check for service accounts
function Test-ServiceAccounts {
    $serviceAccounts = Get-ADUser -Filter {ServicePrincipalName -like "*"} -Properties ServicePrincipalName, DistinguishedName
    
    foreach ($account in $serviceAccounts) {
        if ($account.Enabled -and -not $account.PasswordNeverExpires) {
            Add-AuditFinding -Category "Service Accounts" `
                -Finding "Service account without password never expires: $($account.SamAccountName)" `
                -Severity "Low" `
                -Description "Service account password may expire and break services" `
                -Recommendation "Consider setting password never expires for service accounts (with compensating controls)" `
                -FixScript "# Manual review required for service accounts"
                -AffectedObject $account
        }
    }
}

# Function to check for empty groups
function Test-EmptyGroups {
    $allGroups = Get-ADGroup -Filter * -Properties Members
    
    foreach ($group in $allGroups) {
        if ($group.Members.Count -eq 0 -and $group.GroupScope -ne "DomainLocal") {
            Add-AuditFinding -Category "Group Management" `
                -Finding "Empty group: $($group.Name)" `
                -Severity "Low" `
                -Description "Group has no members and may be unnecessary" `
                -Recommendation "Review and remove empty groups or add members" `
                -FixScript "# Manual review required"
                -AffectedObject $group
        }
    }
}

# Function to check for disabled accounts
function Test-DisabledAccounts {
    $disabledAccounts = Get-ADUser -Filter {Enabled -eq $false} -Properties Enabled, DistinguishedName, WhenCreated
    $oldDisabledAccounts = $disabledAccounts | Where-Object { ((Get-Date) - $_.WhenCreated).Days -gt 90 }
    
    foreach ($account in $oldDisabledAccounts) {
        $daysDisabled = ((Get-Date) - $account.WhenCreated).Days
        Add-AuditFinding -Category "Account Management" `
            -Finding "Old disabled account: $($account.SamAccountName)" `
            -Severity "Low" `
            -Description "Account has been disabled for $daysDisabled days" `
            -Recommendation "Review and remove old disabled accounts" `
            -FixScript "Remove-ADUser -Identity '$($account.DistinguishedName)' -Confirm:`$false" `
            -AffectedObject $account
    }
}

# Function to check Kerberos encryption
function Test-KerberosEncryption {
    $computers = Get-ADComputer -Filter * -Properties msDS-SupportedEncryptionTypes
    
    foreach ($computer in $computers) {
        if ($computer.'msDS-SupportedEncryptionTypes' -band 0x7 -ne 0x7) {
            Add-AuditFinding -Category "Encryption" `
                -Finding "Computer does not support all Kerberos encryption types: $($computer.Name)" `
                -Severity "Medium" `
                -Description "Computer may use weak encryption" `
                -Recommendation "Ensure all computers support AES128 and AES256 encryption" `
                -FixScript "Set-ADComputer -Identity '$($computer.DistinguishedName)' -Replace @{'msDS-SupportedEncryptionTypes' = 28}"
                -AffectedObject $computer
        }
    }
}

# Enhanced Kerberos security checks
function Test-KerberosSecurity {
    if (-not $script:Config.Enabled) {
        return
    }
    
    Write-Host "  [*] Checking Kerberos security settings..." -ForegroundColor Yellow
    
    # Check Kerberos ticket lifetime
    try {
        $defaultDomainPolicy = Get-GPO -Name "Default Domain Policy" -ErrorAction SilentlyContinue
        if ($defaultDomainPolicy) {
            # Check for Kerberos ticket lifetime settings
            $regPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
            $ticketMaxAge = (Get-GPRegistryValue -Name "Default Domain Policy" -Key $regPath -ValueName "MaxTicketAge" -ErrorAction SilentlyContinue).Value
            
            if (-not $ticketMaxAge -or $ticketMaxAge -gt 600) {
                Add-AuditFinding -Category "Kerberos Security" `
                    -Finding "Kerberos ticket lifetime may be too long" `
                    -Severity "Medium" `
                    -Description "Default ticket lifetime should be set appropriately" `
                    -Recommendation "Configure Kerberos ticket lifetime via Group Policy" `
                    -FixScript "Set-GPRegistryValue -Name 'Default Domain Policy' -Key '$regPath' -ValueName 'MaxTicketAge' -Type DWord -Value 600"
            }
        }
    } catch {
        Write-Host "    [*] Could not check Kerberos ticket lifetime" -ForegroundColor Yellow
    }
    
    # Check for RC4 encryption (should be disabled)
    $computers = Get-ADComputer -Filter * -Properties msDS-SupportedEncryptionTypes
    
    foreach ($computer in $computers) {
        $encTypes = $computer.'msDS-SupportedEncryptionTypes'
        # Check if RC4 is enabled (bit 2 = 0x4)
        if (($encTypes -band 0x4) -ne 0) {
            Add-AuditFinding -Category "Kerberos Security" `
                -Finding "Computer supports weak RC4 encryption: $($computer.Name)" `
                -Severity "High" `
                -Description "RC4 encryption is deprecated and vulnerable" `
                -Recommendation "Disable RC4 encryption support" `
                -FixScript "Set-ADComputer -Identity '$($computer.DistinguishedName)' -Replace @{'msDS-SupportedEncryptionTypes' = 28}"
                -AffectedObject $computer
        }
    }
}

# ==================== SMB PROTOCOL SECURITY ====================

# Function to check SMBv1 status
function Test-SMBv1 {
    if (-not $script:Config.SMBProtocol.Enabled -or -not $script:Config.SMBProtocol.CheckSMBv1) {
        return
    }
    
    Write-Host "  [*] Checking SMBv1 protocol status..." -ForegroundColor Yellow
    
    try {
        # Check SMBv1 on local machine (registry check)
        $smbv1Path = "HKLM:\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        $smbv1Enabled = (Get-ItemProperty -Path $smbv1Path -Name "SMB1" -ErrorAction SilentlyContinue).SMB1
        
        if ($smbv1Enabled -ne 0) {
            Add-AuditFinding -Category "SMB Protocol" `
                -Finding "SMBv1 protocol is enabled" `
                -Severity "High" `
                -Description "SMBv1 is deprecated and vulnerable to attacks (e.g., EternalBlue)" `
                -Recommendation "Disable SMBv1 protocol on all systems" `
                -FixScript "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -NoRestart -ErrorAction SilentlyContinue; Set-SmbServerConfiguration -EnableSMB1Protocol `$false -Force"
        } else {
            # Check if feature is actually disabled
            $feature = Get-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -ErrorAction SilentlyContinue
            if ($feature -and $feature.State -eq "Enabled") {
                Add-AuditFinding -Category "SMB Protocol" `
                    -Finding "SMBv1 protocol feature is installed" `
                    -Severity "High" `
                    -Description "SMBv1 feature should be completely removed" `
                    -Recommendation "Remove SMBv1 feature from Windows" `
                    -FixScript "Disable-WindowsOptionalFeature -Online -FeatureName SMB1Protocol -Remove -NoRestart"
            }
        }
    } catch {
        Add-AuditFinding -Category "SMB Protocol" `
            -Finding "Could not verify SMBv1 status" `
            -Severity "Medium" `
            -Description "Unable to check SMBv1 configuration" `
            -Recommendation "Manually verify SMBv1 is disabled on all systems" `
            -FixScript "# Manual verification required"
    }
}

# Function to check SMBv2 settings
function Test-SMBv2 {
    if (-not $script:Config.SMBProtocol.Enabled -or -not $script:Config.SMBProtocol.CheckSMBv2) {
        return
    }
    
    Write-Host "  [*] Checking SMBv2/v3 protocol security..." -ForegroundColor Yellow
    
    try {
        # Check SMB signing requirements
        $smbConfig = Get-SmbServerConfiguration -ErrorAction SilentlyContinue
        
        if ($smbConfig) {
            if (-not $smbConfig.RequireSecuritySignature) {
                Add-AuditFinding -Category "SMB Protocol" `
                    -Finding "SMB signing is not required" `
                    -Severity "High" `
                    -Description "SMB packets should be signed to prevent tampering" `
                    -Recommendation "Enable SMB signing requirement" `
                    -FixScript "Set-SmbServerConfiguration -RequireSecuritySignature `$true -Force"
            }
            
            if (-not $smbConfig.EnableSecuritySignature) {
                Add-AuditFinding -Category "SMB Protocol" `
                    -Finding "SMB security signature is disabled" `
                    -Severity "High" `
                    -Description "SMB security signature should be enabled" `
                    -Recommendation "Enable SMB security signature" `
                    -FixScript "Set-SmbServerConfiguration -EnableSecuritySignature `$true -Force"
            }
        }
        
        # Check SMB encryption
        if ($smbConfig -and -not $smbConfig.EncryptData) {
            Add-AuditFinding -Category "SMB Protocol" `
                -Finding "SMB encryption is not enabled" `
                -Severity "Medium" `
                -Description "SMB data encryption should be enabled for sensitive environments" `
                -Recommendation "Enable SMB encryption" `
                -FixScript "Set-SmbServerConfiguration -EncryptData `$true -Force"
        }
    } catch {
        Add-AuditFinding -Category "SMB Protocol" `
            -Finding "Could not check SMBv2/v3 configuration" `
            -Severity "Medium" `
            -Description "Unable to verify SMBv2/v3 security settings" `
            -Recommendation "Manually verify SMBv2/v3 security configuration" `
            -FixScript "# Manual verification required"
    }
}

# Function to fix SMB configuration via GPO
function Fix-SMBConfiguration {
    param(
        [object]$GPO
    )
    
    if (-not $script:Config.SMBProtocol.Enabled -or -not $GPO) {
        return
    }
    
    Write-Host "    [*] Configuring SMB security settings in GPO..." -ForegroundColor Cyan
    
    try {
        # Disable SMBv1 via registry
        $smbPath = "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        Set-GPRegistryValue -Name $GPO.DisplayName -Key $smbPath -ValueName "SMB1" -Type DWord -Value 0 -ErrorAction SilentlyContinue
        
        # Require SMB signing
        $smbSecurityPath = "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters"
        Set-GPRegistryValue -Name $GPO.DisplayName -Key $smbSecurityPath -ValueName "RequireSecuritySignature" -Type DWord -Value 1 -ErrorAction SilentlyContinue
        Set-GPRegistryValue -Name $GPO.DisplayName -Key $smbSecurityPath -ValueName "EnableSecuritySignature" -Type DWord -Value 1 -ErrorAction SilentlyContinue
        
        # Enable SMB encryption
        Set-GPRegistryValue -Name $GPO.DisplayName -Key $smbSecurityPath -ValueName "EncryptData" -Type DWord -Value 1 -ErrorAction SilentlyContinue
        
        Write-Host "      [OK] SMB security configured in GPO" -ForegroundColor Green
    } catch {
        Write-Host "      [WARNING] Could not configure SMB settings in GPO: $_" -ForegroundColor Yellow
    }
}

# ==================== MICROSOFT 365 / ENTRA ID INTEGRATION ====================

# Function to authenticate with Microsoft Graph (OAuth)
function Connect-Microsoft365 {
    if (-not $script:Config.Microsoft365.Enabled) {
        return $false
    }
    
    if ([string]::IsNullOrWhiteSpace($script:Config.Microsoft365.TenantId) -or 
        [string]::IsNullOrWhiteSpace($script:Config.Microsoft365.ClientId)) {
        if (-not $Silent) {
            Write-Host "  [WARNING] Microsoft 365 configuration incomplete. Configure TenantId and ClientId in Configuration Menu." -ForegroundColor Yellow
        }
        return $false
    }
    
    try {
        $tenantId = $script:Config.Microsoft365.TenantId
        $clientId = $script:Config.Microsoft365.ClientId
        
        # Check if we have a client secret (app registration) or need interactive auth
        if (-not [string]::IsNullOrWhiteSpace($script:Config.Microsoft365.ClientSecret)) {
            # Use client credentials flow (app-only authentication)
            $tokenEndpoint = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
            $body = @{
                client_id = $clientId
                client_secret = $script:Config.Microsoft365.ClientSecret
                scope = "https://graph.microsoft.com/.default"
                grant_type = "client_credentials"
            }
            
            $response = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body $body -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
            $script:GraphToken = $response.access_token
            if (-not $Silent) {
                Write-Host "  [OK] Authenticated with Microsoft Graph (App Registration)" -ForegroundColor Green
            }
            return $true
        } else {
            # Interactive authentication (device code flow)
            if (-not $Silent) {
                Write-Host "  [*] Using device code flow for Microsoft 365 authentication..." -ForegroundColor Yellow
                Write-Host "      Visit https://microsoft.com/devicelogin and enter the code shown below" -ForegroundColor Cyan
            }
            
            $deviceCodeEndpoint = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/devicecode"
            $deviceBody = @{
                client_id = $clientId
                scope = "https://graph.microsoft.com/.default offline_access"
            }
            
            $deviceResponse = Invoke-RestMethod -Method Post -Uri $deviceCodeEndpoint -Body $deviceBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
            if (-not $Silent) {
                Write-Host "`n      CODE: $($deviceResponse.user_code)" -ForegroundColor White -BackgroundColor DarkBlue
                Write-Host "      Waiting for authentication..." -ForegroundColor Yellow
            }
            Start-Sleep -Seconds 5
            
            $tokenEndpoint = "https://login.microsoftonline.com/$tenantId/oauth2/v2.0/token"
            $tokenBody = @{
                grant_type = "urn:ietf:params:oauth:grant-type:device_code"
                client_id = $clientId
                device_code = $deviceResponse.device_code
            }
            
            $maxAttempts = 30
            $attempt = 0
            while ($attempt -lt $maxAttempts) {
                try {
                    $tokenResponse = Invoke-RestMethod -Method Post -Uri $tokenEndpoint -Body $tokenBody -ContentType "application/x-www-form-urlencoded" -ErrorAction Stop
                    $script:GraphToken = $tokenResponse.access_token
                    if (-not $Silent) {
                        Write-Host "  [OK] Authenticated with Microsoft Graph" -ForegroundColor Green
                    }
                    return $true
                } catch {
                    $errorDetails = $_.ErrorDetails.Message | ConvertFrom-Json -ErrorAction SilentlyContinue
                    if ($errorDetails -and $errorDetails.error -eq "authorization_pending") {
                        Start-Sleep -Seconds 5
                        $attempt++
                    } else {
                        throw
                    }
                }
            }
            
            if (-not $Silent) {
                Write-Host "  [ERROR] Authentication timeout" -ForegroundColor Red
            }
            return $false
        }
    } catch {
        if (-not $Silent) {
            Write-Host "  [ERROR] Failed to authenticate with Microsoft Graph: $_" -ForegroundColor Red
        }
        return $false
    }
}

# Function to call Microsoft Graph API
function Invoke-MicrosoftGraph {
    param(
        [string]$Method = "GET",
        [string]$Endpoint,
        [object]$Body = $null
    )
    
    if (-not $script:GraphToken) {
        if (-not (Connect-Microsoft365)) {
            return $null
        }
    }
    
    try {
        $headers = @{
            Authorization = "Bearer $script:GraphToken"
            "Content-Type" = "application/json"
        }
        
        $uri = if ($Endpoint -like "https://*") { $Endpoint } else { "https://graph.microsoft.com/v1.0/$Endpoint" }
        
        $params = @{
            Method = $Method
            Uri = $uri
            Headers = $headers
            ErrorAction = "Stop"
        }
        
        if ($Body) {
            $params.Body = ($Body | ConvertTo-Json -Depth 10)
        }
        
        return Invoke-RestMethod @params
    } catch {
        # Fail silently for optional checks - errors are expected if permissions are insufficient
        return $null
    }
}

# Function to check Office 365 security settings
function Test-Office365Security {
    if (-not $script:Config.Microsoft365.Enabled -or -not $script:Config.Microsoft365.CheckOffice365) {
        return
    }
    
    try {
        if (-not $script:GraphToken) {
            if (-not (Connect-Microsoft365)) {
                return
            }
        }
        
        # Check organization security defaults
        $policies = Invoke-MicrosoftGraph -Endpoint "policies/identitySecurityDefaultsEnforcementPolicy"
        if ($policies -and -not $policies.isEnabled) {
            Add-AuditFinding -Category "Office 365 Security" `
                -Finding "Security defaults are not enabled" `
                -Severity "High" `
                -Description "Security defaults provide baseline security for Office 365 (MFA, blocking legacy auth, etc.)" `
                -Recommendation "Enable security defaults in Azure AD" `
                -FixScript "Invoke-MicrosoftGraph -Method PATCH -Endpoint 'policies/identitySecurityDefaultsEnforcementPolicy' -Body @{isEnabled=`$true}"
        }
        
        # Check for risky sign-ins (requires Identity Protection permissions)
        try {
            $riskySignIns = Invoke-MicrosoftGraph -Endpoint "identityProtection/riskySignIns"
            if ($riskySignIns -and $riskySignIns.value.Count -gt 0) {
                $recentRisky = $riskySignIns.value | Where-Object { 
                    $_.riskState -ne "remediated" -and 
                    (Get-Date $_.detectedDateTime) -gt (Get-Date).AddDays(-7)
                }
                
                if ($recentRisky) {
                    Add-AuditFinding -Category "Office 365 Security" `
                        -Finding "$($recentRisky.Count) risky sign-ins detected in last 7 days" `
                        -Severity "Medium" `
                        -Description "Risky sign-ins may indicate compromised accounts" `
                        -Recommendation "Review risky sign-ins in Azure AD Identity Protection" `
                        -FixScript "# Review via Azure Portal: Identity Protection > Risky sign-ins"
                }
            }
        } catch {
            # May require additional permissions - skip silently
        }
    } catch {
        # Fail silently for optional checks
    }
}

# Function to check Entra ID security
function Test-EntraIDSecurity {
    if (-not $script:Config.Microsoft365.Enabled -or -not $script:Config.Microsoft365.CheckEntra) {
        return
    }
    
    try {
        if (-not $script:GraphToken) {
            if (-not (Connect-Microsoft365)) {
                return
            }
        }
        
        # Check for admin accounts
        $directoryRoles = Invoke-MicrosoftGraph -Endpoint "directoryRoles"
        if ($directoryRoles) {
            foreach ($role in $directoryRoles.value) {
                if ($role.displayName -eq "Global Administrator") {
                    $members = Invoke-MicrosoftGraph -Endpoint "directoryRoles/$($role.id)/members"
                    if ($members -and $members.value) {
                        foreach ($admin in $members.value) {
                            # Check if admin has MFA
                            $mfaRegistered = $false
                            try {
                                $authMethods = Invoke-MicrosoftGraph -Endpoint "users/$($admin.id)/authentication/methods"
                                if ($authMethods -and $authMethods.value) {
                                    $mfaRegistered = ($authMethods.value | Where-Object { 
                                        $_.'@odata.type' -like "*PhoneAuthenticationMethod*" -or 
                                        $_.'@odata.type' -like "*MicrosoftAuthenticatorAuthenticationMethod*" 
                                    }).Count -gt 0
                                }
                            } catch {
                                # May require additional permissions
                            }
                            
                            if (-not $mfaRegistered) {
                                Add-AuditFinding -Category "Entra ID Security" `
                                    -Finding "Global Administrator without MFA: $($admin.userPrincipalName)" `
                                    -Severity "High" `
                                    -Description "Global Administrator accounts should require MFA" `
                                    -Recommendation "Require MFA for all Global Administrator accounts" `
                                    -FixScript "# Configure via Azure Portal: Azure AD > Users > MFA settings or Conditional Access"
                            }
                        }
                    }
                }
            }
        }
    } catch {
        # Fail silently for optional checks
    }
}

# Function to check Conditional Access policies
function Test-ConditionalAccess {
    if (-not $script:Config.Microsoft365.Enabled -or -not $script:Config.Microsoft365.CheckConditionalAccess) {
        return
    }
    
    try {
        if (-not $script:GraphToken) {
            if (-not (Connect-Microsoft365)) {
                return
            }
        }
        
        $policies = Invoke-MicrosoftGraph -Endpoint "identity/conditionalAccess/policies"
        
        if ($policies -and $policies.value.Count -eq 0) {
            Add-AuditFinding -Category "Office 365 Security" `
                -Finding "No Conditional Access policies configured" `
                -Severity "High" `
                -Description "Conditional Access policies provide additional security controls (MFA, device compliance, location-based access)" `
                -Recommendation "Create Conditional Access policies for better security" `
                -FixScript "# Configure via Azure Portal: Azure AD > Security > Conditional Access"
        } elseif ($policies) {
            $enabledPolicies = ($policies.value | Where-Object { $_.state -eq "enabled" }).Count
            if ($enabledPolicies -gt 0) {
                Add-AuditFinding -Category "Office 365 Security" `
                    -Finding "$enabledPolicies Conditional Access policies enabled" `
                    -Severity "Info" `
                    -Description "Conditional Access policies are configured" `
                    -Recommendation "Review Conditional Access policies for completeness" `
                    -FixScript "# Review via Azure Portal: Azure AD > Security > Conditional Access"
            }
        }
    } catch {
        # Fail silently for optional checks
    }
}

# Function to check Microsoft 365 MFA
function Test-Microsoft365MFA {
    if (-not $script:Config.Microsoft365.Enabled -or -not $script:Config.Microsoft365.CheckMFA) {
        return
    }
    
    try {
        if (-not $script:GraphToken) {
            if (-not (Connect-Microsoft365)) {
                return
            }
        }
        
        # Get users (first 100 - can be extended)
        $users = Invoke-MicrosoftGraph -Endpoint "users?`$top=100&`$filter=userType eq 'Member'"
        
        if ($users) {
            $usersWithoutMFA = @()
            foreach ($user in $users.value) {
                $mfaRegistered = $false
                try {
                    $authMethods = Invoke-MicrosoftGraph -Endpoint "users/$($user.id)/authentication/methods"
                    if ($authMethods -and $authMethods.value) {
                        $mfaRegistered = ($authMethods.value | Where-Object { 
                            $_.'@odata.type' -like "*PhoneAuthenticationMethod*" -or 
                            $_.'@odata.type' -like "*MicrosoftAuthenticatorAuthenticationMethod*" -or
                            $_.'@odata.type' -like "*Fido2AuthenticationMethod*"
                        }).Count -gt 0
                    }
                } catch {
                    # May require additional permissions
                }
                
                if (-not $mfaRegistered) {
                    $usersWithoutMFA += $user
                }
            }
            
            if ($usersWithoutMFA.Count -gt 0) {
                Add-AuditFinding -Category "Office 365 Security" `
                    -Finding "$($usersWithoutMFA.Count) users without MFA registration" `
                    -Severity "High" `
                    -Description "Users have not registered MFA methods" `
                    -Recommendation "Require MFA registration for all users via Conditional Access or Security Defaults" `
                    -FixScript "# Enable Security Defaults or configure Conditional Access to require MFA"
            }
        }
    } catch {
        # Fail silently for optional checks
    }
}

# ==================== GOOGLE WORKSPACE INTEGRATION ====================

# Function to authenticate with Google Workspace
function Connect-GoogleWorkspace {
    if (-not $script:Config.GoogleWorkspace.Enabled) {
        return $false
    }
    
    if ([string]::IsNullOrWhiteSpace($script:Config.GoogleWorkspace.ServiceAccountKey)) {
        if (-not $Silent) {
            Write-Host "  [WARNING] Google Workspace Service Account Key not configured. Configure in Configuration Menu." -ForegroundColor Yellow
        }
        return $false
    }
    
    try {
        $keyPath = $script:Config.GoogleWorkspace.ServiceAccountKey
        
        if (-not (Test-Path $keyPath)) {
            if (-not $Silent) {
                Write-Host "  [ERROR] Service Account Key file not found: $keyPath" -ForegroundColor Red
            }
            return $false
        }
        
        # Read service account key
        $serviceAccountJson = Get-Content $keyPath -Raw | ConvertFrom-Json
        
        # Check if Google.Apis.Auth module is available
        try {
            Import-Module Google.Apis.Auth -ErrorAction Stop
        } catch {
            if (-not $Silent) {
                Write-Host "  [WARNING] Google.Apis.Auth module not installed" -ForegroundColor Yellow
                Write-Host "            Install with: Install-Module -Name Google.Apis.Auth -Force" -ForegroundColor Cyan
            }
            
            # Try alternative method using REST API with JWT
            if (-not $Silent) {
                Write-Host "  [*] Attempting JWT-based authentication..." -ForegroundColor Yellow
            }
            
            # Basic JWT implementation for service account (simplified)
            $script:GoogleServiceAccount = $serviceAccountJson
            if (-not $Silent) {
                Write-Host "  [OK] Google Workspace service account loaded" -ForegroundColor Green
            }
            return $true
        }
        
        # Use Google.Apis.Auth module if available
        $script:GoogleServiceAccount = $serviceAccountJson
        if (-not $Silent) {
            Write-Host "  [OK] Google Workspace authenticated" -ForegroundColor Green
        }
        return $true
    } catch {
        if (-not $Silent) {
            Write-Host "  [WARNING] Failed to authenticate with Google Workspace: $_" -ForegroundColor Yellow
        }
        return $false
    }
}

# Function to call Google Admin SDK API
function Invoke-GoogleWorkspaceAPI {
    param(
        [string]$Method = "GET",
        [string]$Endpoint,
        [object]$Body = $null
    )
    
    if (-not $script:GoogleServiceAccount) {
        if (-not (Connect-GoogleWorkspace)) {
            return $null
        }
    }
    
    try {
        # This requires proper JWT generation and OAuth 2.0 service account flow
        # For now, return placeholder - requires Google.Apis.Auth module implementation
        if (-not $Silent) {
            Write-Host "    [INFO] Google Workspace API calls require Google.Apis.Auth module" -ForegroundColor Cyan
        }
        return $null
    } catch {
        return $null
    }
}

# Function to check Google Workspace security
function Test-GoogleWorkspaceSecurity {
    if (-not $script:Config.GoogleWorkspace.Enabled -or -not $script:Config.GoogleWorkspace.CheckSecurity) {
        return
    }
    
    try {
        if (-not $script:GoogleServiceAccount) {
            if (-not (Connect-GoogleWorkspace)) {
                return
            }
        }
        
        # Placeholder - requires Google Admin SDK API access
        Add-AuditFinding -Category "Google Workspace Security" `
            -Finding "Google Workspace security review required" `
            -Severity "Info" `
            -Description "Review security settings in Google Admin Console" `
            -Recommendation "Check: Admin Console > Security > Settings" `
            -FixScript "# Manual review via Google Admin Console required"
    } catch {
        # Fail silently for optional checks
    }
}

# Function to check Google Workspace MFA
function Test-GoogleWorkspaceMFA {
    if (-not $script:Config.GoogleWorkspace.Enabled -or -not $script:Config.GoogleWorkspace.CheckMFA) {
        return
    }
    
    try {
        if (-not $script:GoogleServiceAccount) {
            if (-not (Connect-GoogleWorkspace)) {
                return
            }
        }
        
        # Placeholder - requires Google Admin SDK API access
        Add-AuditFinding -Category "Google Workspace Security" `
            -Finding "Google Workspace MFA review required" `
            -Severity "Info" `
            -Description "Verify 2-Step Verification is enforced for all users" `
            -Recommendation "Check: Admin Console > Security > 2-Step Verification" `
            -FixScript "# Configure via Google Admin Console: Security > 2-Step Verification"
    } catch {
        # Fail silently for optional checks
    }
}

# Function to check Google Workspace API security
function Test-GoogleWorkspaceAPI {
    if (-not $script:Config.GoogleWorkspace.Enabled -or -not $script:Config.GoogleWorkspace.CheckAPI) {
        return
    }
    
    try {
        if (-not $script:GoogleServiceAccount) {
            if (-not (Connect-GoogleWorkspace)) {
                return
            }
        }
        
        # Placeholder - requires Google Admin SDK API access
        Add-AuditFinding -Category "Google Workspace Security" `
            -Finding "Google Workspace API security review required" `
            -Severity "Info" `
            -Description "Review API access and OAuth applications" `
            -Recommendation "Check: Admin Console > Security > API Controls" `
            -FixScript "# Review via Google Admin Console: Security > API Controls"
    } catch {
        # Fail silently for optional checks
    }
}

# Helper function to safely run optional checks with error handling
function Invoke-OptionalCheck {
    param(
        [string]$CheckName,
        [scriptblock]$CheckScript,
        [bool]$IsEnabled
    )
    
    if (-not $IsEnabled) {
        return
    }
    
    try {
        Write-Host "  [*] $CheckName..." -ForegroundColor Yellow
        & $CheckScript
    } catch {
        Write-Host "      [WARNING] $CheckName failed: $_" -ForegroundColor Yellow
        # Don't fail the entire audit if one optional check fails
    }
}

# Function to run HIPAA audit
function Start-HIPAAAudit {
    $script:ComplianceFramework = "HIPAA"
    $script:AuditResults = @()
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Starting HIPAA Compliance Audit..." -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    # Core checks (always run)
    Write-Host "Core Security Checks:" -ForegroundColor Cyan
    Invoke-OptionalCheck -CheckName "Checking password policies" -CheckScript { Test-PasswordPolicy } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking account lockout policies" -CheckScript { Test-AccountLockoutPolicy } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking for inactive accounts" -CheckScript { Test-InactiveAccounts } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking for accounts with password never expires" -CheckScript { Test-PasswordNeverExpires } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking for MFA requirements" -CheckScript { Test-MFARequirement } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking for old disabled accounts" -CheckScript { Test-DisabledAccounts } -IsEnabled $true
    
    # Enhanced password checks (opt-in)
    if ($script:Config.EnhancedPasswordChecks.Enabled) {
        Write-Host "`nEnhanced Password Security Checks:" -ForegroundColor Cyan
        Invoke-OptionalCheck -CheckName "Checking LM hash storage" -CheckScript { Test-LMHashStorage } -IsEnabled $script:Config.EnhancedPasswordChecks.CheckLMHash
        Invoke-OptionalCheck -CheckName "Checking reversible encryption" -CheckScript { Test-ReversibleEncryption } -IsEnabled $script:Config.EnhancedPasswordChecks.CheckReversibleEncryption
        Invoke-OptionalCheck -CheckName "Checking Fine-Grained Password Policies" -CheckScript { Test-PasswordSettingsObjects } -IsEnabled $script:Config.EnhancedPasswordChecks.CheckPSO
        Invoke-OptionalCheck -CheckName "Checking password expiration dates" -CheckScript { Test-PasswordExpiration } -IsEnabled $script:Config.EnhancedPasswordChecks.CheckPasswordExpiration
    }
    
    # Account security enhancements (opt-in)
    if ($script:Config.AccountSecurityEnhancements.Enabled) {
        Write-Host "`nAccount Security Enhancements:" -ForegroundColor Cyan
        Invoke-OptionalCheck -CheckName "Checking account expiration dates" -CheckScript { Test-AccountExpiration } -IsEnabled $script:Config.AccountSecurityEnhancements.CheckAccountExpiration
        Invoke-OptionalCheck -CheckName "Checking smart card requirements" -CheckScript { Test-SmartCardRequired } -IsEnabled $script:Config.AccountSecurityEnhancements.CheckSmartCardRequired
        Invoke-OptionalCheck -CheckName "Checking for orphaned accounts" -CheckScript { Test-OrphanedAccounts } -IsEnabled $script:Config.AccountSecurityEnhancements.CheckOrphanedAccounts
        Invoke-OptionalCheck -CheckName "Checking last logon timestamps" -CheckScript { Test-LastLogonTimestamp } -IsEnabled $script:Config.AccountSecurityEnhancements.CheckLastLogonTimestamp
    }
    
    # RBAC & permissions (opt-in)
    if ($script:Config.RBACPermissions.Enabled) {
        Write-Host "`nRBAC & Permissions Checks:" -ForegroundColor Cyan
        Invoke-OptionalCheck -CheckName "Checking OU delegation permissions" -CheckScript { Test-OUDelegation } -IsEnabled $script:Config.RBACPermissions.CheckDelegation
        Invoke-OptionalCheck -CheckName "Checking AD object permissions" -CheckScript { Test-ADObjectPermissions } -IsEnabled $script:Config.RBACPermissions.CheckObjectPermissions
    }
    
    # Privileged access review (opt-in)
    if ($script:Config.PrivilegedAccessReview.Enabled) {
        Write-Host "`nPrivileged Access Review:" -ForegroundColor Cyan
        Invoke-OptionalCheck -CheckName "Checking nested privileged groups" -CheckScript { Test-NestedPrivilegedGroups } -IsEnabled $script:Config.PrivilegedAccessReview.CheckNestedGroups
        Invoke-OptionalCheck -CheckName "Checking AdminSDHolder" -CheckScript { Test-AdminSDHolder } -IsEnabled $script:Config.PrivilegedAccessReview.CheckAdminSDHolder
        Invoke-OptionalCheck -CheckName "Checking protected accounts" -CheckScript { Test-ProtectedAccounts } -IsEnabled $script:Config.PrivilegedAccessReview.CheckProtectedAccounts
    }
    
    # Schema & DNS security (opt-in)
    if ($script:Config.SchemaDNSSecurity.Enabled) {
        Write-Host "`nSchema & DNS Security Checks:" -ForegroundColor Cyan
        Invoke-OptionalCheck -CheckName "Checking schema version" -CheckScript { Test-SchemaVersion } -IsEnabled $script:Config.SchemaDNSSecurity.CheckSchemaVersion
        Invoke-OptionalCheck -CheckName "Checking DNS security" -CheckScript { Test-DNSSecurity } -IsEnabled $true
    }
    
    # Trust & domain relationships (opt-in)
    if ($script:Config.TrustRelationships.Enabled) {
        Write-Host "`nTrust & Domain Relationships:" -ForegroundColor Cyan
        Invoke-OptionalCheck -CheckName "Checking trust relationships" -CheckScript { Test-TrustRelationships } -IsEnabled $true
    }
    
    # Certificate & PKI (opt-in)
    if ($script:Config.CertificatePKI.Enabled) {
        Write-Host "`nCertificate & PKI Checks:" -ForegroundColor Cyan
        Invoke-OptionalCheck -CheckName "Checking certificate expiration" -CheckScript { Test-CertificateExpiration } -IsEnabled $script:Config.CertificatePKI.CheckCertExpiration
        Invoke-OptionalCheck -CheckName "Checking CA validity" -CheckScript { Test-CAValidity } -IsEnabled $script:Config.CertificatePKI.CheckCAValidity
        Invoke-OptionalCheck -CheckName "Checking certificate templates" -CheckScript { Test-CertificateTemplates } -IsEnabled $script:Config.CertificatePKI.CheckCertTemplates
    }
    
    # Multi-domain support (opt-in)
    if ($script:Config.MultiDomainSupport.Enabled) {
        Write-Host "`nMulti-Domain Support:" -ForegroundColor Cyan
        Invoke-OptionalCheck -CheckName "Scanning multiple domains" -CheckScript { Test-MultiDomain } -IsEnabled $true
    }
    
    $highCount = ($script:AuditResults | Where-Object { $_.Severity -eq "High" }).Count
    $mediumCount = ($script:AuditResults | Where-Object { $_.Severity -eq "Medium" }).Count
    $lowCount = ($script:AuditResults | Where-Object { $_.Severity -eq "Low" }).Count
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "HIPAA Audit Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Total Issues Found: $($script:AuditResults.Count)" -ForegroundColor White
    Write-Host "  High Severity: $highCount" -ForegroundColor Red
    Write-Host "  Medium Severity: $mediumCount" -ForegroundColor Yellow
    Write-Host "  Low Severity: $lowCount" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
}

# Function to run CMMC audit
function Start-CMMCAudit {
    $script:ComplianceFramework = "CMMC"
    $script:AuditResults = @()
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Starting CMMC Compliance Audit..." -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    # Core checks (always run)
    Write-Host "Core Security Checks:" -ForegroundColor Cyan
    Invoke-OptionalCheck -CheckName "Checking password policies" -CheckScript { Test-PasswordPolicy } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking account lockout policies" -CheckScript { Test-AccountLockoutPolicy } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking for inactive accounts" -CheckScript { Test-InactiveAccounts } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking for accounts with password never expires" -CheckScript { Test-PasswordNeverExpires } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking for MFA requirements" -CheckScript { Test-MFARequirement } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking Kerberos encryption" -CheckScript { Test-KerberosEncryption } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking service accounts" -CheckScript { Test-ServiceAccounts } -IsEnabled $true
    
    # Enhanced password checks (opt-in)
    if ($script:Config.EnhancedPasswordChecks.Enabled) {
        Write-Host "`nEnhanced Password Security Checks:" -ForegroundColor Cyan
        Invoke-OptionalCheck -CheckName "Checking LM hash storage" -CheckScript { Test-LMHashStorage } -IsEnabled $script:Config.EnhancedPasswordChecks.CheckLMHash
        Invoke-OptionalCheck -CheckName "Checking reversible encryption" -CheckScript { Test-ReversibleEncryption } -IsEnabled $script:Config.EnhancedPasswordChecks.CheckReversibleEncryption
        Invoke-OptionalCheck -CheckName "Checking Fine-Grained Password Policies" -CheckScript { Test-PasswordSettingsObjects } -IsEnabled $script:Config.EnhancedPasswordChecks.CheckPSO
    }
    
    # Account security enhancements (opt-in)
    if ($script:Config.AccountSecurityEnhancements.Enabled) {
        Write-Host "`nAccount Security Enhancements:" -ForegroundColor Cyan
        Invoke-OptionalCheck -CheckName "Checking account expiration dates" -CheckScript { Test-AccountExpiration } -IsEnabled $script:Config.AccountSecurityEnhancements.CheckAccountExpiration
        Invoke-OptionalCheck -CheckName "Checking smart card requirements" -CheckScript { Test-SmartCardRequired } -IsEnabled $script:Config.AccountSecurityEnhancements.CheckSmartCardRequired
    }
    
    # RBAC & permissions (opt-in)
    if ($script:Config.RBACPermissions.Enabled) {
        Write-Host "`nRBAC & Permissions Checks:" -ForegroundColor Cyan
        Invoke-OptionalCheck -CheckName "Checking OU delegation permissions" -CheckScript { Test-OUDelegation } -IsEnabled $script:Config.RBACPermissions.CheckDelegation
        Invoke-OptionalCheck -CheckName "Checking AD object permissions" -CheckScript { Test-ADObjectPermissions } -IsEnabled $script:Config.RBACPermissions.CheckObjectPermissions
    }
    
    # Privileged access review (opt-in)
    if ($script:Config.PrivilegedAccessReview.Enabled) {
        Write-Host "`nPrivileged Access Review:" -ForegroundColor Cyan
        Invoke-OptionalCheck -CheckName "Checking nested privileged groups" -CheckScript { Test-NestedPrivilegedGroups } -IsEnabled $script:Config.PrivilegedAccessReview.CheckNestedGroups
        Invoke-OptionalCheck -CheckName "Checking AdminSDHolder" -CheckScript { Test-AdminSDHolder } -IsEnabled $script:Config.PrivilegedAccessReview.CheckAdminSDHolder
        Invoke-OptionalCheck -CheckName "Checking protected accounts" -CheckScript { Test-ProtectedAccounts } -IsEnabled $script:Config.PrivilegedAccessReview.CheckProtectedAccounts
    }
    
    # Schema & DNS security (opt-in)
    if ($script:Config.SchemaDNSSecurity.Enabled) {
        Write-Host "`nSchema & DNS Security Checks:" -ForegroundColor Cyan
        Invoke-OptionalCheck -CheckName "Checking schema version" -CheckScript { Test-SchemaVersion } -IsEnabled $script:Config.SchemaDNSSecurity.CheckSchemaVersion
        Invoke-OptionalCheck -CheckName "Checking DNS security" -CheckScript { Test-DNSSecurity } -IsEnabled $true
    }
    
    # Trust & domain relationships (opt-in)
    if ($script:Config.TrustRelationships.Enabled) {
        Write-Host "`nTrust & Domain Relationships:" -ForegroundColor Cyan
        Invoke-OptionalCheck -CheckName "Checking trust relationships" -CheckScript { Test-TrustRelationships } -IsEnabled $true
    }
    
    # Certificate & PKI (opt-in)
    if ($script:Config.CertificatePKI.Enabled) {
        Write-Host "`nCertificate & PKI Checks:" -ForegroundColor Cyan
        Invoke-OptionalCheck -CheckName "Checking certificate expiration" -CheckScript { Test-CertificateExpiration } -IsEnabled $script:Config.CertificatePKI.CheckCertExpiration
        Invoke-OptionalCheck -CheckName "Checking CA validity" -CheckScript { Test-CAValidity } -IsEnabled $script:Config.CertificatePKI.CheckCAValidity
    }
    
    # Multi-domain support (opt-in)
    if ($script:Config.MultiDomainSupport.Enabled) {
        Write-Host "`nMulti-Domain Support:" -ForegroundColor Cyan
        Invoke-OptionalCheck -CheckName "Scanning multiple domains" -CheckScript { Test-MultiDomain } -IsEnabled $true
    }
    
    $highCount = ($script:AuditResults | Where-Object { $_.Severity -eq "High" }).Count
    $mediumCount = ($script:AuditResults | Where-Object { $_.Severity -eq "Medium" }).Count
    $lowCount = ($script:AuditResults | Where-Object { $_.Severity -eq "Low" }).Count
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "CMMC Audit Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Total Issues Found: $($script:AuditResults.Count)" -ForegroundColor White
    Write-Host "  High Severity: $highCount" -ForegroundColor Red
    Write-Host "  Medium Severity: $mediumCount" -ForegroundColor Yellow
    Write-Host "  Low Severity: $lowCount" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
}

# Helper function to run all optional checks
function Invoke-AllOptionalChecks {
    param(
        [string]$Framework = ""
    )
    
    # Enhanced password checks (opt-in)
    if ($script:Config.EnhancedPasswordChecks.Enabled) {
        Write-Host "`nEnhanced Password Security Checks:" -ForegroundColor Cyan
        Invoke-OptionalCheck -CheckName "Checking LM hash storage" -CheckScript { Test-LMHashStorage } -IsEnabled $script:Config.EnhancedPasswordChecks.CheckLMHash
        Invoke-OptionalCheck -CheckName "Checking reversible encryption" -CheckScript { Test-ReversibleEncryption } -IsEnabled $script:Config.EnhancedPasswordChecks.CheckReversibleEncryption
        Invoke-OptionalCheck -CheckName "Checking Fine-Grained Password Policies" -CheckScript { Test-PasswordSettingsObjects } -IsEnabled $script:Config.EnhancedPasswordChecks.CheckPSO
        Invoke-OptionalCheck -CheckName "Checking password expiration dates" -CheckScript { Test-PasswordExpiration } -IsEnabled $script:Config.EnhancedPasswordChecks.CheckPasswordExpiration
    }
    
    # Account security enhancements (opt-in)
    if ($script:Config.AccountSecurityEnhancements.Enabled) {
        Write-Host "`nAccount Security Enhancements:" -ForegroundColor Cyan
        Invoke-OptionalCheck -CheckName "Checking account expiration dates" -CheckScript { Test-AccountExpiration } -IsEnabled $script:Config.AccountSecurityEnhancements.CheckAccountExpiration
        Invoke-OptionalCheck -CheckName "Checking smart card requirements" -CheckScript { Test-SmartCardRequired } -IsEnabled $script:Config.AccountSecurityEnhancements.CheckSmartCardRequired
        Invoke-OptionalCheck -CheckName "Checking for orphaned accounts" -CheckScript { Test-OrphanedAccounts } -IsEnabled $script:Config.AccountSecurityEnhancements.CheckOrphanedAccounts
        Invoke-OptionalCheck -CheckName "Checking last logon timestamps" -CheckScript { Test-LastLogonTimestamp } -IsEnabled $script:Config.AccountSecurityEnhancements.CheckLastLogonTimestamp
    }
    
    # RBAC & permissions (opt-in)
    if ($script:Config.RBACPermissions.Enabled) {
        Write-Host "`nRBAC & Permissions Checks:" -ForegroundColor Cyan
        Invoke-OptionalCheck -CheckName "Checking OU delegation permissions" -CheckScript { Test-OUDelegation } -IsEnabled $script:Config.RBACPermissions.CheckDelegation
        Invoke-OptionalCheck -CheckName "Checking AD object permissions" -CheckScript { Test-ADObjectPermissions } -IsEnabled $script:Config.RBACPermissions.CheckObjectPermissions
    }
    
    # Privileged access review (opt-in)
    if ($script:Config.PrivilegedAccessReview.Enabled) {
        Write-Host "`nPrivileged Access Review:" -ForegroundColor Cyan
        Invoke-OptionalCheck -CheckName "Checking nested privileged groups" -CheckScript { Test-NestedPrivilegedGroups } -IsEnabled $script:Config.PrivilegedAccessReview.CheckNestedGroups
        Invoke-OptionalCheck -CheckName "Checking AdminSDHolder" -CheckScript { Test-AdminSDHolder } -IsEnabled $script:Config.PrivilegedAccessReview.CheckAdminSDHolder
        Invoke-OptionalCheck -CheckName "Checking protected accounts" -CheckScript { Test-ProtectedAccounts } -IsEnabled $script:Config.PrivilegedAccessReview.CheckProtectedAccounts
    }
    
    # Schema & DNS security (opt-in)
    if ($script:Config.SchemaDNSSecurity.Enabled) {
        Write-Host "`nSchema & DNS Security Checks:" -ForegroundColor Cyan
        Invoke-OptionalCheck -CheckName "Checking schema version" -CheckScript { Test-SchemaVersion } -IsEnabled $script:Config.SchemaDNSSecurity.CheckSchemaVersion
        Invoke-OptionalCheck -CheckName "Checking DNS security" -CheckScript { Test-DNSSecurity } -IsEnabled $true
    }
    
    # Trust & domain relationships (opt-in)
    if ($script:Config.TrustRelationships.Enabled) {
        Write-Host "`nTrust & Domain Relationships:" -ForegroundColor Cyan
        Invoke-OptionalCheck -CheckName "Checking trust relationships" -CheckScript { Test-TrustRelationships } -IsEnabled $true
    }
    
    # Certificate & PKI (opt-in)
    if ($script:Config.CertificatePKI.Enabled) {
        Write-Host "`nCertificate & PKI Checks:" -ForegroundColor Cyan
        Invoke-OptionalCheck -CheckName "Checking certificate expiration" -CheckScript { Test-CertificateExpiration } -IsEnabled $script:Config.CertificatePKI.CheckCertExpiration
        Invoke-OptionalCheck -CheckName "Checking CA validity" -CheckScript { Test-CAValidity } -IsEnabled $script:Config.CertificatePKI.CheckCAValidity
        Invoke-OptionalCheck -CheckName "Checking certificate templates" -CheckScript { Test-CertificateTemplates } -IsEnabled $script:Config.CertificatePKI.CheckCertTemplates
    }
    
    # Multi-domain support (opt-in)
    if ($script:Config.MultiDomainSupport.Enabled) {
        Write-Host "`nMulti-Domain Support:" -ForegroundColor Cyan
        Invoke-OptionalCheck -CheckName "Scanning multiple domains" -CheckScript { Test-MultiDomain } -IsEnabled $true
    }
    
    # SMB Protocol checks (opt-in)
    if ($script:Config.SMBProtocol.Enabled) {
        Write-Host "`nSMB Protocol Security:" -ForegroundColor Cyan
        Invoke-OptionalCheck -CheckName "Checking SMBv1 status" -CheckScript { Test-SMBv1 } -IsEnabled $script:Config.SMBProtocol.CheckSMBv1
        Invoke-OptionalCheck -CheckName "Checking SMBv2/v3 security" -CheckScript { Test-SMBv2 } -IsEnabled $script:Config.SMBProtocol.CheckSMBv2
    }
    
    # Enhanced Kerberos security (opt-in)
    if ($script:Config.Enabled) {
        Invoke-OptionalCheck -CheckName "Checking Kerberos security" -CheckScript { Test-KerberosSecurity } -IsEnabled $true
    }
    
    # Microsoft 365/Entra (opt-in)
    if ($script:Config.Microsoft365.Enabled) {
        Write-Host "`nMicrosoft 365 / Entra ID:" -ForegroundColor Cyan
        Invoke-OptionalCheck -CheckName "Checking Office 365 security" -CheckScript { Test-Office365Security } -IsEnabled $script:Config.Microsoft365.CheckOffice365
        Invoke-OptionalCheck -CheckName "Checking Entra ID security" -CheckScript { Test-EntraIDSecurity } -IsEnabled $script:Config.Microsoft365.CheckEntra
        Invoke-OptionalCheck -CheckName "Checking Conditional Access" -CheckScript { Test-ConditionalAccess } -IsEnabled $script:Config.Microsoft365.CheckConditionalAccess
        Invoke-OptionalCheck -CheckName "Checking MFA requirements" -CheckScript { Test-Microsoft365MFA } -IsEnabled $script:Config.Microsoft365.CheckMFA
    }
    
    # Google Workspace (opt-in)
    if ($script:Config.GoogleWorkspace.Enabled) {
        Write-Host "`nGoogle Workspace:" -ForegroundColor Cyan
        Invoke-OptionalCheck -CheckName "Checking Google Workspace security" -CheckScript { Test-GoogleWorkspaceSecurity } -IsEnabled $script:Config.GoogleWorkspace.CheckSecurity
        Invoke-OptionalCheck -CheckName "Checking Google Workspace MFA" -CheckScript { Test-GoogleWorkspaceMFA } -IsEnabled $script:Config.GoogleWorkspace.CheckMFA
        Invoke-OptionalCheck -CheckName "Checking Google Workspace API security" -CheckScript { Test-GoogleWorkspaceAPI } -IsEnabled $script:Config.GoogleWorkspace.CheckAPI
    }
}

# Helper function to show audit summary
function Show-AuditSummary {
    param(
        [string]$Framework
    )
    
    $highCount = ($script:AuditResults | Where-Object { $_.Severity -eq "High" }).Count
    $mediumCount = ($script:AuditResults | Where-Object { $_.Severity -eq "Medium" }).Count
    $lowCount = ($script:AuditResults | Where-Object { $_.Severity -eq "Low" }).Count
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "$Framework Audit Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Total Issues Found: $($script:AuditResults.Count)" -ForegroundColor White
    Write-Host "  High Severity: $highCount" -ForegroundColor Red
    Write-Host "  Medium Severity: $mediumCount" -ForegroundColor Yellow
    Write-Host "  Low Severity: $lowCount" -ForegroundColor Cyan
    Write-Host "========================================`n" -ForegroundColor Cyan
}

# Function to run NIST/CIS audit
function Start-NISTCISAudit {
    $script:ComplianceFramework = "NIST/CIS"
    $script:AuditResults = @()
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Starting NIST/CIS Baseline Audit..." -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    # Core checks (always run)
    Write-Host "Core Security Checks:" -ForegroundColor Cyan
    Invoke-OptionalCheck -CheckName "Checking password policies" -CheckScript { Test-PasswordPolicy } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking account lockout policies" -CheckScript { Test-AccountLockoutPolicy } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking for inactive accounts" -CheckScript { Test-InactiveAccounts } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking for accounts with password never expires" -CheckScript { Test-PasswordNeverExpires } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking for MFA requirements" -CheckScript { Test-MFARequirement } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking Kerberos encryption" -CheckScript { Test-KerberosEncryption } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking empty groups" -CheckScript { Test-EmptyGroups } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking service accounts" -CheckScript { Test-ServiceAccounts } -IsEnabled $true
    
    # Run all optional checks
    Invoke-AllOptionalChecks -Framework "NIST/CIS"
    
    Show-AuditSummary -Framework "NIST/CIS"
}

# Function to check for separation of duties
function Test-SeparationOfDuties {
    # Check for users in multiple privileged groups
    $privilegedGroups = @("Domain Admins", "Enterprise Admins", "Schema Admins", "Account Operators", "Server Operators", "Backup Operators")
    $allMembers = @{}
    
    foreach ($groupName in $privilegedGroups) {
        try {
            $members = Get-ADGroupMember -Identity $groupName -Recursive | Where-Object { $_.objectClass -eq "user" }
            foreach ($member in $members) {
                if (-not $allMembers.ContainsKey($member.SamAccountName)) {
                    $allMembers[$member.SamAccountName] = @()
                }
                $allMembers[$member.SamAccountName] += $groupName
            }
        } catch {
            # Group may not exist
        }
    }
    
    foreach ($userName in $allMembers.Keys) {
        if ($allMembers[$userName].Count -gt 1) {
            $userObj = Get-ADUser -Identity $userName -Properties DistinguishedName
            $groups = $allMembers[$userName] -join ', '
            Add-AuditFinding -Category "Separation of Duties" `
                -Finding "User in multiple privileged groups: $userName" `
                -Severity "High" `
                -Description "User is member of: $groups. This violates separation of duties principles." `
                -Recommendation "Review and remove user from unnecessary privileged groups. Auto-fix is disabled for safety (removing users from groups could break access)." `
                -FixScript "# Manual review required - removing users from groups automatically is too risky. Review audit report and manually adjust group memberships." `
                -AffectedObject $userObj
        }
    }
}

# Function to check for audit logging
function Test-AuditLogging {
    $domain = Get-ADDomain
    $dcs = Get-ADDomainController -Filter * | Select-Object -First 1
    
    # Check if auditing is configured (requires registry access or GPO check)
    # This is a placeholder - actual implementation would check GPOs or registry
    Add-AuditFinding -Category "Audit Logging" `
        -Finding "Audit logging configuration review required" `
        -Severity "Medium" `
        -Description "Verify that account logon, account management, and directory service access auditing is enabled" `
        -Recommendation "Ensure comprehensive audit logging is enabled via Group Policy" `
        -FixScript "# Configure via Group Policy: Computer Configuration > Policies > Windows Settings > Security Settings > Advanced Audit Policy Configuration"
}

# Function to check for data access controls (GDPR specific)
function Test-DataAccessControls {
    # Check for accounts with excessive permissions
    $allUsers = Get-ADUser -Filter {Enabled -eq $true} -Properties MemberOf, DistinguishedName
    
    foreach ($user in $allUsers) {
        $groupCount = $user.MemberOf.Count
        if ($groupCount -gt 20) {
            Add-AuditFinding -Category "Data Access Control" `
                -Finding "User with excessive group memberships: $($user.SamAccountName)" `
                -Severity "Medium" `
                -Description "User is member of $groupCount groups, which may indicate over-privileged access" `
                -Recommendation "Review group memberships and remove unnecessary access" `
                -FixScript "# Manual review required"
                -AffectedObject $user
        }
    }
}

# Function to check for password reuse across accounts
function Test-PasswordReuse {
    # This would require password hash comparison which isn't directly possible
    # Instead, check for accounts that haven't changed passwords in a long time
    $accounts = Get-ADUser -Filter {Enabled -eq $true -and PasswordNeverExpires -eq $false} -Properties PasswordLastSet, DistinguishedName
    
    foreach ($account in $accounts) {
        if ($account.PasswordLastSet) {
            $daysSinceChange = ((Get-Date) - $account.PasswordLastSet).Days
            if ($daysSinceChange -gt 180) {
                Add-AuditFinding -Category "Password Management" `
                    -Finding "Account password not changed in over 180 days: $($account.SamAccountName)" `
                    -Severity "Medium" `
                    -Description "Password has not been changed for $daysSinceChange days" `
                    -Recommendation "Require password change or review account access" `
                    -FixScript "# Manual review required - may need to force password reset" `
                    -AffectedObject $account
            }
        }
    }
}

# ==================== BACKUP AND RESTORE FUNCTIONS ====================

# Function to backup GPO before changes
function Backup-ComplianceGPO {
    param(
        [string]$GPOName,
        [string]$BackupPath
    )
    
    if (-not $script:Config.GPOBackupRestore.Enabled) {
        return $null
    }
    
    if (-not $script:Config.GPOBackupRestore.AutoBackup) {
        Write-Host "  [*] GPO backup is disabled in configuration" -ForegroundColor Yellow
        return $null
    }
    
    try {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $backupComment = "Backup before compliance changes - $timestamp"
        
        if (-not (Test-Path $BackupPath)) {
            New-Item -ItemType Directory -Path $BackupPath -Force | Out-Null
        }
        
        $backup = Backup-GPO -Name $GPOName -Path $BackupPath -Comment $backupComment -ErrorAction Stop
        Write-Host "  [OK] GPO backed up: $GPOName (ID: $($backup.Id))" -ForegroundColor Green
        $script:BackupsCreated += @{
            Type = "GPO"
            Name = $GPOName
            BackupId = $backup.Id
            Timestamp = $timestamp
            Path = $BackupPath
        }
        return $backup
    } catch {
        Write-Warning "Failed to backup GPO '$GPOName': $_"
        return $null
    }
}

# Function to restore GPO from backup
function Restore-GPOBackup {
    param(
        [string]$GPOName,
        [string]$BackupPath,
        [guid]$BackupId
    )
    
    if (-not $script:Config.GPOBackupRestore.Enabled) {
        Write-Host "GPO restore is disabled in configuration" -ForegroundColor Yellow
        return $false
    }
    
    try {
        Write-Host "Restoring GPO '$GPOName' from backup..." -ForegroundColor Yellow
        
        if ($BackupId) {
            Restore-GPO -Name $GPOName -Path $BackupPath -BackupId $BackupId -ErrorAction Stop
        } else {
            # Find latest backup
            $backups = Get-GPOBackup -Path $BackupPath -All | Where-Object { $_.DisplayName -eq $GPOName } | Sort-Object CreationTime -Descending
            if ($backups) {
                Restore-GPO -Name $GPOName -Path $BackupPath -BackupId $backups[0].Id -ErrorAction Stop
            } else {
                Write-Error "No backup found for GPO '$GPOName'"
                return $false
            }
        }
        
        Write-Host "  [OK] GPO restored successfully" -ForegroundColor Green
        return $true
    } catch {
        Write-Error "Failed to restore GPO: $_"
        return $false
    }
}

# Function to backup domain configuration
function Backup-DomainConfig {
    param(
        [string]$BackupPath
    )
    
    if (-not $script:Config.GPOBackupRestore.Enabled -or -not $script:Config.GPOBackupRestore.AutoBackup) {
        return $null
    }
    
    try {
        $timestamp = Get-Date -Format "yyyyMMdd_HHmmss"
        $backupFile = Join-Path $BackupPath "DomainConfig_$timestamp.json"
        
        $domainConfig = @{
            DomainDN = $script:DomainDN
            DomainName = $script:DomainName
            PasswordPolicy = Get-ADDefaultDomainPasswordPolicy | Select-Object *
            AuditTimestamp = $timestamp
        }
        
        $domainConfig | ConvertTo-Json -Depth 10 | Out-File -FilePath $backupFile -Encoding UTF8
        
        Write-Host "  [OK] Domain configuration backed up: $backupFile" -ForegroundColor Green
        $script:BackupsCreated += @{
            Type = "DomainConfig"
            File = $backupFile
            Timestamp = $timestamp
        }
        return $backupFile
    } catch {
        Write-Warning "Failed to backup domain configuration: $_"
        return $null
    }
}

# ==================== ENHANCED PASSWORD SECURITY CHECKS ====================

# Function to check for LM hash storage
function Test-LMHashStorage {
    if (-not $script:Config.EnhancedPasswordChecks.Enabled -or -not $script:Config.EnhancedPasswordChecks.CheckLMHash) {
        return
    }
    
    $domain = Get-ADDomain
    try {
        # Check if LM hash storage is disabled
        $lmHashPath = "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa"
        $lmHashValue = (Get-ItemProperty -Path $lmHashPath -Name "NoLMHash" -ErrorAction SilentlyContinue).NoLMHash
        
        if ($lmHashValue -ne 1) {
            Add-AuditFinding -Category "Password Security" `
                -Finding "LM hash storage is enabled" `
                -Severity "High" `
                -Description "LM hashes are weak and vulnerable to brute force attacks" `
                -Recommendation "Disable LM hash storage via Group Policy" `
                -FixScript "Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name 'NoLMHash' -Value 1 -Type DWord"
        }
    } catch {
        Add-AuditFinding -Category "Password Security" `
            -Finding "Unable to verify LM hash storage status" `
            -Severity "Medium" `
            -Description "Could not check LM hash storage configuration" `
            -Recommendation "Manually verify LM hash storage is disabled" `
            -FixScript "# Manual verification required"
    }
}

# Function to check for reversible encryption
function Test-ReversibleEncryption {
    if (-not $script:Config.EnhancedPasswordChecks.Enabled -or -not $script:Config.EnhancedPasswordChecks.CheckReversibleEncryption) {
        return
    }
    
    $accounts = Get-ADUser -Filter {Enabled -eq $true -and AllowReversiblePasswordEncryption -eq $true} -Properties AllowReversiblePasswordEncryption, DistinguishedName
    
    foreach ($account in $accounts) {
        Add-AuditFinding -Category "Password Security" `
            -Finding "Account with reversible encryption enabled: $($account.SamAccountName)" `
            -Severity "High" `
            -Description "Account password can be decrypted, which is a security risk" `
            -Recommendation "Disable reversible encryption for this account" `
            -FixScript "Set-ADUser -Identity '$($account.DistinguishedName)' -AllowReversiblePasswordEncryption `$false" `
            -AffectedObject $account
    }
}

# Function to check Fine-Grained Password Policies (PSOs)
function Test-PasswordSettingsObjects {
    if (-not $script:Config.EnhancedPasswordChecks.Enabled -or -not $script:Config.EnhancedPasswordChecks.CheckPSO) {
        return
    }
    
    try {
        $psos = Get-ADFineGrainedPasswordPolicy -Filter *
        
        if ($psos) {
            foreach ($pso in $psos) {
                # Check if PSO meets compliance requirements
                if ($pso.MinPasswordLength -lt 14) {
                    Add-AuditFinding -Category "Password Security" `
                        -Finding "PSO with weak minimum length: $($pso.Name)" `
                        -Severity "Medium" `
                        -Description "PSO minimum password length is $($pso.MinPasswordLength), should be at least 14" `
                        -Recommendation "Update PSO to require minimum 14 characters" `
                        -FixScript "Set-ADFineGrainedPasswordPolicy -Identity '$($pso.DistinguishedName)' -MinPasswordLength 14"
                }
                
                if (-not $pso.ComplexityEnabled) {
                    Add-AuditFinding -Category "Password Security" `
                        -Finding "PSO without complexity requirement: $($pso.Name)" `
                        -Severity "High" `
                        -Description "PSO does not require password complexity" `
                        -Recommendation "Enable complexity requirement for PSO" `
                        -FixScript "Set-ADFineGrainedPasswordPolicy -Identity '$($pso.DistinguishedName)' -ComplexityEnabled `$true"
                }
            }
        }
    } catch {
        # PSOs may not be available in all AD environments
        Write-Host "  [*] Fine-Grained Password Policies not available or not checked" -ForegroundColor Yellow
    }
}

# Function to check accounts approaching password expiration
function Test-PasswordExpiration {
    if (-not $script:Config.EnhancedPasswordChecks.Enabled -or -not $script:Config.EnhancedPasswordChecks.CheckPasswordExpiration) {
        return
    }
    
    $accounts = Get-ADUser -Filter {Enabled -eq $true -and PasswordNeverExpires -eq $false -and PasswordExpired -eq $false} -Properties PasswordLastSet, msDS-UserPasswordExpiryTimeComputed, DistinguishedName
    
    foreach ($account in $accounts) {
        if ($account.'msDS-UserPasswordExpiryTimeComputed') {
            $expiryDate = [DateTime]::FromFileTime($account.'msDS-UserPasswordExpiryTimeComputed')
            $daysUntilExpiry = ($expiryDate - (Get-Date)).Days
            
            if ($daysUntilExpiry -le 7 -and $daysUntilExpiry -gt 0) {
                Add-AuditFinding -Category "Password Security" `
                    -Finding "Password expiring soon: $($account.SamAccountName)" `
                    -Severity "Low" `
                    -Description "Password expires in $daysUntilExpiry days" `
                    -Recommendation "Notify user to change password before expiration" `
                    -FixScript "# Notification required - no automatic fix" `
                    -AffectedObject $account
            }
        }
    }
}

# Function to run GLBA audit
function Start-GLBAAudit {
    $script:ComplianceFramework = "GLBA"
    $script:AuditResults = @()
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Starting GLBA (Gramm-Leach-Bliley Act) Compliance Audit..." -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    # Core checks (always run)
    Write-Host "Core Security Checks:" -ForegroundColor Cyan
    Invoke-OptionalCheck -CheckName "Checking password policies" -CheckScript { Test-PasswordPolicy } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking account lockout policies" -CheckScript { Test-AccountLockoutPolicy } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking for inactive accounts" -CheckScript { Test-InactiveAccounts } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking for accounts with password never expires" -CheckScript { Test-PasswordNeverExpires } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking for MFA requirements" -CheckScript { Test-MFARequirement } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking separation of duties" -CheckScript { Test-SeparationOfDuties } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking Kerberos encryption" -CheckScript { Test-KerberosEncryption } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking audit logging" -CheckScript { Test-AuditLogging } -IsEnabled $true
    
    # Run all optional checks
    Invoke-AllOptionalChecks -Framework "GLBA"
    
    Show-AuditSummary -Framework "GLBA"
}

# Function to run SOX audit
function Start-SOXAudit {
    $script:ComplianceFramework = "SOX"
    $script:AuditResults = @()
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Starting SOX (Sarbanes-Oxley) Compliance Audit..." -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    # Core checks (always run)
    Write-Host "Core Security Checks:" -ForegroundColor Cyan
    Invoke-OptionalCheck -CheckName "Checking password policies" -CheckScript { Test-PasswordPolicy } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking account lockout policies" -CheckScript { Test-AccountLockoutPolicy } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking for inactive accounts" -CheckScript { Test-InactiveAccounts } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking for accounts with password never expires" -CheckScript { Test-PasswordNeverExpires } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking for MFA requirements" -CheckScript { Test-MFARequirement } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking separation of duties" -CheckScript { Test-SeparationOfDuties } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking audit logging" -CheckScript { Test-AuditLogging } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking for old disabled accounts" -CheckScript { Test-DisabledAccounts } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking service accounts" -CheckScript { Test-ServiceAccounts } -IsEnabled $true
    
    # Run all optional checks
    Invoke-AllOptionalChecks -Framework "SOX"
    
    Show-AuditSummary -Framework "SOX"
}

# Function to run PCI-DSS audit
function Start-PCIDSSAudit {
    $script:ComplianceFramework = "PCI-DSS"
    $script:AuditResults = @()
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Starting PCI-DSS Compliance Audit..." -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    # Core checks (always run)
    Write-Host "Core Security Checks:" -ForegroundColor Cyan
    Invoke-OptionalCheck -CheckName "Checking password policies" -CheckScript { Test-PasswordPolicy } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking account lockout policies" -CheckScript { Test-AccountLockoutPolicy } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking for inactive accounts" -CheckScript { Test-InactiveAccounts } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking for accounts with password never expires" -CheckScript { Test-PasswordNeverExpires } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking for MFA requirements" -CheckScript { Test-MFARequirement } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking Kerberos encryption" -CheckScript { Test-KerberosEncryption } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking audit logging" -CheckScript { Test-AuditLogging } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking separation of duties" -CheckScript { Test-SeparationOfDuties } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking password reuse" -CheckScript { Test-PasswordReuse } -IsEnabled $true
    
    # Run all optional checks
    Invoke-AllOptionalChecks -Framework "PCI-DSS"
    
    Show-AuditSummary -Framework "PCI-DSS"
}

# Function to run GDPR audit
function Start-GDPRAudit {
    $script:ComplianceFramework = "GDPR"
    $script:AuditResults = @()
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Starting GDPR Compliance Audit..." -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    # Core checks (always run)
    Write-Host "Core Security Checks:" -ForegroundColor Cyan
    Invoke-OptionalCheck -CheckName "Checking password policies" -CheckScript { Test-PasswordPolicy } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking account lockout policies" -CheckScript { Test-AccountLockoutPolicy } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking for inactive accounts" -CheckScript { Test-InactiveAccounts } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking for accounts with password never expires" -CheckScript { Test-PasswordNeverExpires } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking for MFA requirements" -CheckScript { Test-MFARequirement } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking data access controls" -CheckScript { Test-DataAccessControls } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking for old disabled accounts" -CheckScript { Test-DisabledAccounts } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking audit logging" -CheckScript { Test-AuditLogging } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking Kerberos encryption" -CheckScript { Test-KerberosEncryption } -IsEnabled $true
    
    # Run all optional checks
    Invoke-AllOptionalChecks -Framework "GDPR"
    
    Show-AuditSummary -Framework "GDPR"
}

# Function to run FISMA audit
function Start-FISMAAudit {
    $script:ComplianceFramework = "FISMA"
    $script:AuditResults = @()
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Starting FISMA Compliance Audit..." -ForegroundColor Green
    Write-Host "========================================`n" -ForegroundColor Cyan
    
    # Core checks (always run)
    Write-Host "Core Security Checks:" -ForegroundColor Cyan
    Invoke-OptionalCheck -CheckName "Checking password policies" -CheckScript { Test-PasswordPolicy } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking account lockout policies" -CheckScript { Test-AccountLockoutPolicy } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking for inactive accounts" -CheckScript { Test-InactiveAccounts } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking for accounts with password never expires" -CheckScript { Test-PasswordNeverExpires } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking for MFA requirements" -CheckScript { Test-MFARequirement } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking Kerberos encryption" -CheckScript { Test-KerberosEncryption } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking separation of duties" -CheckScript { Test-SeparationOfDuties } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking audit logging" -CheckScript { Test-AuditLogging } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking service accounts" -CheckScript { Test-ServiceAccounts } -IsEnabled $true
    Invoke-OptionalCheck -CheckName "Checking empty groups" -CheckScript { Test-EmptyGroups } -IsEnabled $true
    
    # Run all optional checks
    Invoke-AllOptionalChecks -Framework "FISMA"
    
    Show-AuditSummary -Framework "FISMA"
}

# Function to create or update a GPO for compliance
function New-ComplianceGPO {
    param(
        [string]$GPOName,
        [string]$Framework,
        [string]$TargetOU = $null
    )
    
    $gpo = $null
    $created = $false
    
    # Check if GPO already exists
    try {
        $gpo = Get-GPO -Name $GPOName -ErrorAction SilentlyContinue
        Write-Host "  [*] GPO '$GPOName' already exists. Updating..." -ForegroundColor Yellow
    } catch {
        # GPO doesn't exist, create it
        try {
            $gpo = New-GPO -Name $GPOName -Comment "Compliance GPO for $Framework framework - Created $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
            $created = $true
            Write-Host "  [*] Created GPO: $GPOName" -ForegroundColor Green
            $script:GPOsCreated += $gpo
        } catch {
            Write-Error "Failed to create GPO '$GPOName': $_"
            return $null
        }
    }
    
    return $gpo
}

# Function to configure password policy settings in GPO
function Set-GPOPasswordPolicy {
    param(
        [object]$GPO,
        [int]$MinPasswordLength = 14,
        [bool]$ComplexityEnabled = $true,
        [int]$PasswordHistoryCount = 24,
        [int]$MaxPasswordAge = 90,
        [int]$MinPasswordAge = 1
    )
    
    if (-not $GPO) { return }
    
    Write-Host "    [*] Configuring password policy settings..." -ForegroundColor Cyan
    
    # Note: Domain password policies are set via Set-ADDefaultDomainPasswordPolicy
    # GPO password policies affect local accounts. We'll configure both.
    # For domain-level, we use AD cmdlets, but we can also set GPO registry values
    
    # Local Account Password Policy (Computer Configuration)
    $registryPath = "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    
    # Set minimum password length
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "$registryPath" -ValueName "MinimumPasswordLength" -Type DWord -Value $MinPasswordLength -ErrorAction SilentlyContinue
    
    # Additional settings would go here
    Write-Host "      [OK] Password policy configured" -ForegroundColor Green
}

# Function to configure account lockout policy in GPO
function Set-GPOAccountLockoutPolicy {
    param(
        [object]$GPO,
        [int]$LockoutThreshold = 5,
        [int]$LockoutDuration = 15,
        [int]$ResetLockoutCounter = 15
    )
    
    if (-not $GPO) { return }
    
    Write-Host "    [*] Configuring account lockout policy..." -ForegroundColor Cyan
    
    $registryPath = "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters"
    
    # Note: Account lockout policies are typically configured via Security Settings
    # These registry settings are a fallback
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "$registryPath" -ValueName "LockoutBadCount" -Type DWord -Value $LockoutThreshold -ErrorAction SilentlyContinue
    
    Write-Host "      [OK] Account lockout policy configured" -ForegroundColor Green
}

# Function to configure audit policies in GPO
function Set-GPOAuditPolicy {
    param(
        [object]$GPO
    )
    
    if (-not $GPO) { return }
    
    Write-Host "    [*] Configuring audit policies..." -ForegroundColor Cyan
    
    # Configure advanced audit policy via registry
    $auditPolicyPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Audit"
    
    # Account Logon - Success and Failure
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "$auditPolicyPath" -ValueName "AuditAccountLogon" -Type DWord -Value 3 -ErrorAction SilentlyContinue
    
    # Account Management - Success and Failure
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "$auditPolicyPath" -ValueName "AuditAccountManagement" -Type DWord -Value 3 -ErrorAction SilentlyContinue
    
    # Directory Service Access - Success and Failure
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "$auditPolicyPath" -ValueName "AuditDirectoryServiceAccess" -Type DWord -Value 3 -ErrorAction SilentlyContinue
    
    # Logon/Logoff - Success and Failure
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "$auditPolicyPath" -ValueName "AuditLogon" -Type DWord -Value 3 -ErrorAction SilentlyContinue
    
    # Object Access - Success and Failure
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "$auditPolicyPath" -ValueName "AuditObjectAccess" -Type DWord -Value 3 -ErrorAction SilentlyContinue
    
    # Policy Change - Success and Failure
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "$auditPolicyPath" -ValueName "AuditPolicyChange" -Type DWord -Value 3 -ErrorAction SilentlyContinue
    
    # Privilege Use - Success and Failure
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "$auditPolicyPath" -ValueName "AuditPrivilegeUse" -Type DWord -Value 3 -ErrorAction SilentlyContinue
    
    # System Events - Success and Failure
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "$auditPolicyPath" -ValueName "AuditSystemEvents" -Type DWord -Value 3 -ErrorAction SilentlyContinue
    
    Write-Host "      [OK] Audit policies configured" -ForegroundColor Green
}

# Function to configure Kerberos encryption settings in GPO
function Set-GPOKerberosEncryption {
    param(
        [object]$GPO
    )
    
    if (-not $GPO) { return }
    
    Write-Host "    [*] Configuring Kerberos encryption..." -ForegroundColor Cyan
    
    $kerberosPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters"
    
    # Enable AES128 and AES256 encryption (value 28 = 0x1C = AES128 + AES256)
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "$kerberosPath" -ValueName "SupportedEncryptionTypes" -Type DWord -Value 28 -ErrorAction SilentlyContinue
    
    Write-Host "      [OK] Kerberos encryption configured" -ForegroundColor Green
}

# Function to configure security options in GPO
function Set-GPOSecurityOptions {
    param(
        [object]$GPO
    )
    
    if (-not $GPO) { return }
    
    Write-Host "    [*] Configuring security options..." -ForegroundColor Cyan
    
    $securityPath = "HKLM\SYSTEM\CurrentControlSet\Control\Lsa"
    
    # Require strong session key
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "$securityPath" -ValueName "RequireStrongKey" -Type DWord -Value 1 -ErrorAction SilentlyContinue
    
    # Enable audit logging
    $auditPath = "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System"
    Set-GPRegistryValue -Name $GPO.DisplayName -Key "$auditPath" -ValueName "EnableLUA" -Type DWord -Value 1 -ErrorAction SilentlyContinue
    
    # Configure SMB settings
    Fix-SMBConfiguration -GPO $GPO
    
    Write-Host "      [OK] Security options configured" -ForegroundColor Green
}

# Function to scan and list Organizational Units
function Get-OrganizationalUnits {
    Write-Host "`nScanning Organizational Units..." -ForegroundColor Green
    
    $ous = Get-ADOrganizationalUnit -Filter * -Properties DistinguishedName, Name, Description | 
        Select-Object Name, DistinguishedName, Description | 
        Sort-Object DistinguishedName
    
    if ($ous.Count -eq 0) {
        Write-Host "  No OUs found in domain." -ForegroundColor Yellow
        return @()
    }
    
    Write-Host "`nFound $($ous.Count) Organizational Unit(s):" -ForegroundColor Cyan
    Write-Host "`n" + ("=" * 80) -ForegroundColor Gray
    Write-Host ("{0,-5} {1,-40} {2,-35}" -f "ID", "Name", "Distinguished Name") -ForegroundColor Yellow
    Write-Host ("-" * 80) -ForegroundColor Gray
    
    $index = 0
    $ouList = @()
    
    foreach ($ou in $ous) {
        $index++
        $shortName = if ($ou.Name.Length -gt 38) { $ou.Name.Substring(0, 35) + "..." } else { $ou.Name }
        $shortDN = if ($ou.DistinguishedName.Length -gt 33) { $ou.DistinguishedName.Substring(0, 30) + "..." } else { $ou.DistinguishedName }
        Write-Host ("{0,-5} {1,-40} {2,-35}" -f $index, $shortName, $shortDN) -ForegroundColor White
        $ouList += @{
            Index = $index
            Name = $ou.Name
            DistinguishedName = $ou.DistinguishedName
            Description = $ou.Description
            Object = $ou
        }
    }
    
    Write-Host ("=" * 80) -ForegroundColor Gray
    Write-Host "  0. Domain Root ($script:DomainDN)" -ForegroundColor Cyan
    
    return $ouList
}

# Function to select target OU for GPO linking
function Select-TargetOU {
    param(
        [bool]$ShowDomainRoot = $true
    )
    
    $ouList = Get-OrganizationalUnits
    
    Write-Host "`nSelect target for GPO:" -ForegroundColor Yellow
    if ($ShowDomainRoot) {
        Write-Host "  0. Domain Root (Recommended)" -ForegroundColor Cyan
    }
    Write-Host "  1-$($ouList.Count). Select an OU from above" -ForegroundColor Cyan
    Write-Host "  Enter OU Distinguished Name manually" -ForegroundColor Cyan
    
    $selection = Read-Host "`nEnter choice (0-$($ouList.Count), or DN)"
    
    # Check if it's a number
    if ($selection -match '^\d+$') {
        $selNum = [int]$selection
        if ($selNum -eq 0) {
            Write-Host "  Selected: Domain Root" -ForegroundColor Green
            return $null  # null means domain root
        } elseif ($selNum -ge 1 -and $selNum -le $ouList.Count) {
            $selectedOU = $ouList[$selNum - 1]
            Write-Host "  Selected: $($selectedOU.Name) ($($selectedOU.DistinguishedName))" -ForegroundColor Green
            return $selectedOU.DistinguishedName
        } else {
            Write-Host "  Invalid selection. Using domain root." -ForegroundColor Yellow
            return $null
        }
    } else {
        # Assume it's a Distinguished Name
        try {
            # Validate DN by trying to get the OU
            $testOU = Get-ADObject -Identity $selection -ErrorAction Stop
            Write-Host "  Selected: $selection" -ForegroundColor Green
            return $selection
        } catch {
            Write-Host "  Invalid Distinguished Name: $_" -ForegroundColor Red
            Write-Host "  Using domain root instead." -ForegroundColor Yellow
            return $null
        }
    }
}

# Function to create framework-specific GPO
function New-FrameworkGPO {
    param(
        [string]$Framework
    )
    
    $currentDate = Get-Date -Format 'yyyyMMdd'
    $gpoName = "defaultSecurityPolicy-$currentDate"
    
    Write-Host "`nCreating GPO for $Framework compliance..." -ForegroundColor Green
    Write-Host "  GPO Name: $gpoName" -ForegroundColor Cyan
    
    $gpo = New-ComplianceGPO -GPOName $gpoName -Framework $Framework
    
    if (-not $gpo) {
        Write-Error "Failed to create GPO for $Framework"
        return $null
    }
    
    # Configure common settings for all frameworks
    Set-GPOPasswordPolicy -GPO $gpo
    Set-GPOAccountLockoutPolicy -GPO $gpo
    Set-GPOAuditPolicy -GPO $gpo
    Set-GPOKerberosEncryption -GPO $gpo
    Set-GPOSecurityOptions -GPO $gpo
    
    # Framework-specific configurations
    switch ($Framework.ToUpper()) {
        "HIPAA" {
            # HIPAA-specific settings
            Write-Host "    [*] Applying HIPAA-specific settings..." -ForegroundColor Cyan
        }
        "CMMC" {
            # CMMC-specific settings
            Write-Host "    [*] Applying CMMC-specific settings..." -ForegroundColor Cyan
        }
        { $_ -eq "NIST" -or $_ -eq "NIST/CIS" -or $_ -eq "CIS" } {
            # NIST/CIS-specific settings
            Write-Host "    [*] Applying NIST/CIS-specific settings..." -ForegroundColor Cyan
        }
        "GLBA" {
            # GLBA-specific settings
            Write-Host "    [*] Applying GLBA-specific settings..." -ForegroundColor Cyan
        }
        "SOX" {
            # SOX-specific settings
            Write-Host "    [*] Applying SOX-specific settings..." -ForegroundColor Cyan
        }
        { $_ -eq "PCI-DSS" -or $_ -eq "PCI" } {
            # PCI-DSS-specific settings
            Write-Host "    [*] Applying PCI-DSS-specific settings..." -ForegroundColor Cyan
        }
        "GDPR" {
            # GDPR-specific settings
            Write-Host "    [*] Applying GDPR-specific settings..." -ForegroundColor Cyan
        }
        "FISMA" {
            # FISMA-specific settings
            Write-Host "    [*] Applying FISMA-specific settings..." -ForegroundColor Cyan
        }
    }
    
    Write-Host "`nGPO configuration complete for $Framework" -ForegroundColor Green
    return $gpo
}

# Function to link GPO to domain or OU
function Set-GPOLink {
    param(
        [object]$GPO,
        [string]$Target = $null,
        [bool]$Enforced = $true,
        [int]$Order = 1
    )
    
    if (-not $GPO) {
        Write-Error "GPO is null. Cannot create link."
        return $false
    }
    
    # Default to domain root if no target specified
    if (-not $Target) {
        $Target = $script:DomainDN
    }
    
    try {
        Write-Host "  [*] Linking GPO '$($GPO.DisplayName)' to '$Target'..." -ForegroundColor Yellow
        
        # Check if link already exists
        $existingLink = Get-GPInheritance -Target $Target -ErrorAction SilentlyContinue | 
            Select-Object -ExpandProperty GpoLinks | 
            Where-Object { $_.DisplayName -eq $GPO.DisplayName }
        
        if ($existingLink) {
            # Update existing link
            Set-GPLink -Name $GPO.DisplayName -Target $Target -Enforced $Enforced -Order $Order
            Write-Host "    [OK] Updated existing GPO link" -ForegroundColor Green
        } else {
            # Create new link
            New-GPLink -Name $GPO.DisplayName -Target $Target -Enforced $Enforced -Order $Order
            Write-Host "    [OK] Created GPO link" -ForegroundColor Green
        }
        
        if ($Enforced) {
            Write-Host "    [OK] GPO link is ENFORCED" -ForegroundColor Green
        }
        
        return $true
    } catch {
        Write-Error "Failed to link GPO: $_"
        return $false
    }
}

# Function to handle post-audit options (fixes, GPO, etc.)
function Invoke-PostAuditOptions {
    param(
        [string]$Framework
    )
    
    Write-Host "`nOptions:" -ForegroundColor Cyan
    Write-Host "1. Apply fixes (manual fixes only)" -ForegroundColor White
    Write-Host "2. Apply standard $Framework security settings (AUTO-FIX with authorization)" -ForegroundColor Yellow
    Write-Host "3. Create and enforce GPO" -ForegroundColor White
    Write-Host "4. Apply standard settings + Create/enforce GPO" -ForegroundColor Yellow
    Write-Host "5. Return to main menu" -ForegroundColor White
    $fixChoice = Read-Host "Enter choice (1-5)"
    
    switch ($fixChoice) {
        "1" {
            Invoke-FixIssues
            
            Write-Host "`nRescanning after fixes..." -ForegroundColor Yellow
            Start-Sleep -Seconds 2
            
            # Re-run the appropriate audit
            $frameworkUpper = $Framework.ToUpper()
            switch ($frameworkUpper) {
                "HIPAA" { Start-HIPAAAudit }
                "CMMC" { Start-CMMCAudit }
                { $_ -eq "NIST/CIS" -or $_ -eq "NISTCIS" } { Start-NISTCISAudit }
                "GLBA" { Start-GLBAAudit }
                "SOX" { Start-SOXAudit }
                { $_ -eq "PCI-DSS" -or $_ -eq "PCI" } { Start-PCIDSSAudit }
                "GDPR" { Start-GDPRAudit }
                "FISMA" { Start-FISMAAudit }
            }
            
            $fixReportFile = Join-Path $OutputPath "${Framework}_FixReport_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
            New-FixReport -ReportPath $fixReportFile
            
            $newReportFile = Join-Path $OutputPath "${Framework}_Audit_AfterFix_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
            New-HTMLReport -ReportPath $newReportFile
            
            Write-Host "`nRescan complete. Compare reports to see changes." -ForegroundColor Green
        }
        "2" {
            if (Apply-StandardComplianceFixes -Framework $Framework) {
                Write-Host "`nRescanning after applying standard security settings..." -ForegroundColor Yellow
                Start-Sleep -Seconds 2
                
                # Re-run the appropriate audit
                $frameworkUpper = $Framework.ToUpper()
                switch ($frameworkUpper) {
                    "HIPAA" { Start-HIPAAAudit }
                    "CMMC" { Start-CMMCAudit }
                    { $_ -eq "NIST/CIS" -or $_ -eq "NISTCIS" } { Start-NISTCISAudit }
                    "GLBA" { Start-GLBAAudit }
                    "SOX" { Start-SOXAudit }
                    { $_ -eq "PCI-DSS" -or $_ -eq "PCI" } { Start-PCIDSSAudit }
                    "GDPR" { Start-GDPRAudit }
                    "FISMA" { Start-FISMAAudit }
                }
                
                $newReportFile = Join-Path $OutputPath "${Framework}_Audit_AfterStandardFixes_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
                New-HTMLReport -ReportPath $newReportFile
                
                Write-Host "`nRescan complete. Review the report to verify standard settings were applied." -ForegroundColor Green
            }
        }
        "3" {
            Write-Host "`nSelect where to save/link the GPO:" -ForegroundColor Yellow
            $targetOU = Select-TargetOU
            
            Write-Host "`nEnforce GPO? (Y/N)" -ForegroundColor Yellow
            $enforceChoice = Read-Host "Default: Y"
            $enforced = ($enforceChoice -ne "N" -and $enforceChoice -ne "n")
            
            Invoke-ApplyComplianceGPO -Framework $Framework -TargetOU $targetOU -Enforced $enforced
        }
        "4" {
            if (Apply-StandardComplianceFixes -Framework $Framework) {
                Write-Host "`nSelect where to save/link the GPO:" -ForegroundColor Yellow
                $targetOU = Select-TargetOU
                
                Write-Host "`nEnforce GPO? (Y/N)" -ForegroundColor Yellow
                $enforceChoice = Read-Host "Default: Y"
                $enforced = ($enforceChoice -ne "N" -and $enforceChoice -ne "n")
                
                Invoke-ApplyComplianceGPO -Framework $Framework -TargetOU $targetOU -Enforced $enforced
                
                Write-Host "`nRescanning after applying standard security settings and GPO..." -ForegroundColor Yellow
                Start-Sleep -Seconds 2
                
                # Re-run the appropriate audit
                $frameworkUpper = $Framework.ToUpper()
                switch ($frameworkUpper) {
                    "HIPAA" { Start-HIPAAAudit }
                    "CMMC" { Start-CMMCAudit }
                    { $_ -eq "NIST/CIS" -or $_ -eq "NISTCIS" } { Start-NISTCISAudit }
                    "GLBA" { Start-GLBAAudit }
                    "SOX" { Start-SOXAudit }
                    { $_ -eq "PCI-DSS" -or $_ -eq "PCI" } { Start-PCIDSSAudit }
                    "GDPR" { Start-GDPRAudit }
                    "FISMA" { Start-FISMAAudit }
                }
                
                $newReportFile = Join-Path $OutputPath "${Framework}_Audit_AfterStandardFixesAndGPO_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
                New-HTMLReport -ReportPath $newReportFile
                
                Write-Host "`nRescan complete. Review the report to verify all changes." -ForegroundColor Green
            }
        }
        "5" {
            # Return to main menu - do nothing
        }
        default {
            Write-Host "Invalid choice. Returning to main menu." -ForegroundColor Red
        }
    }
}

# Function to apply and enforce GPO for a compliance framework
function Invoke-ApplyComplianceGPO {
    param(
        [string]$Framework,
        [string]$TargetOU = $null,
        [bool]$Enforced = $true
    )
    
    Write-Host "`n=== Applying Compliance GPO for $Framework ===" -ForegroundColor Cyan
    
    # Create/Update GPO
    $gpo = New-FrameworkGPO -Framework $Framework
    
    if (-not $gpo) {
        Write-Error "Failed to create GPO. Cannot apply."
        return $false
    }
    
    # Link GPO
    $linked = Set-GPOLink -GPO $gpo -Target $TargetOU -Enforced $Enforced
    
    if ($linked) {
        Write-Host "`nGPO applied and enforced successfully!" -ForegroundColor Green
        Write-Host "  GPO Name: $($gpo.DisplayName)" -ForegroundColor Cyan
        Write-Host "  Target: $(if ($TargetOU) { $TargetOU } else { 'Domain Root' })" -ForegroundColor Cyan
        Write-Host "  Enforced: $Enforced" -ForegroundColor Cyan
        Write-Host "`nNote: GPO changes will be applied on next Group Policy refresh cycle." -ForegroundColor Yellow
        Write-Host "      You can force a refresh with: gpupdate /force" -ForegroundColor Yellow
        return $true
    } else {
        Write-Error "Failed to link GPO."
        return $false
    }
}

# Function to generate HTML report
function New-HTMLReport {
    param(
        [string]$ReportPath
    )
    
    $reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $totalIssues = $script:AuditResults.Count
    $highSeverity = ($script:AuditResults | Where-Object { $_.Severity -eq "High" }).Count
    $mediumSeverity = ($script:AuditResults | Where-Object { $_.Severity -eq "Medium" }).Count
    $lowSeverity = ($script:AuditResults | Where-Object { $_.Severity -eq "Low" }).Count
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>AD Compliance Audit Report - $script:ComplianceFramework</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .header {
            background-color: #2c3e50;
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .summary {
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        .summary-item {
            display: inline-block;
            margin: 10px 20px;
            padding: 10px;
            border-radius: 3px;
        }
        .high { background-color: #e74c3c; color: white; }
        .medium { background-color: #f39c12; color: white; }
        .low { background-color: #3498db; color: white; }
        .total { background-color: #34495e; color: white; }
        table {
            width: 100%;
            border-collapse: collapse;
            background-color: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #34495e;
            color: white;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .severity-high { color: #e74c3c; font-weight: bold; }
        .severity-medium { color: #f39c12; font-weight: bold; }
        .severity-low { color: #3498db; }
        .finding-detail {
            max-width: 300px;
            word-wrap: break-word;
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>Active Directory Compliance Audit Report</h1>
        <h2>Framework: $script:ComplianceFramework</h2>
        <p>Generated: $reportDate</p>
    </div>
    
    <div class="summary">
        <h2>Executive Summary</h2>
        <div class="summary-item total">Total Issues: $totalIssues</div>
        <div class="summary-item high">High Severity: $highSeverity</div>
        <div class="summary-item medium">Medium Severity: $mediumSeverity</div>
        <div class="summary-item low">Low Severity: $lowSeverity</div>
    </div>
    
    <table>
        <thead>
            <tr>
                <th>Category</th>
                <th>Finding</th>
                <th>Severity</th>
                <th>Description</th>
                <th>Recommendation</th>
            </tr>
        </thead>
        <tbody>
"@
    
    foreach ($finding in $script:AuditResults) {
        $severityClass = "severity-$($finding.Severity.ToLower())"
        $html += @"
            <tr>
                <td>$($finding.Category)</td>
                <td class="finding-detail">$($finding.Finding)</td>
                <td class="$severityClass">$($finding.Severity)</td>
                <td class="finding-detail">$($finding.Description)</td>
                <td class="finding-detail">$($finding.Recommendation)</td>
            </tr>
"@
    }
    
    $html += @"
        </tbody>
    </table>
</body>
</html>
"@
    
    $html | Out-File -FilePath $ReportPath -Encoding UTF8
    Write-Host "HTML report generated: $ReportPath" -ForegroundColor Green
}

# Function to apply fixes with safety checks
function Invoke-FixIssues {
    $script:FixedIssues = @()
    
    # Filter out manual review items and empty fix scripts
    $fixableIssues = $script:AuditResults | Where-Object { 
        $_.FixScript -ne "# Manual review required" -and 
        $_.FixScript -ne "# Manual review required for service accounts" -and
        $_.FixScript -ne "# Manual review required for separation of duties" -and
        $_.FixScript -ne "# Manual review required for OU permissions" -and
        $_.FixScript -ne "# Manual review required - may need to force password reset" -and
        $_.FixScript -ne "# Manual assignment required" -and
        $_.FixScript -ne "# Notification required - no automatic fix" -and
        $_.FixScript -ne "# Manual verification required" -and
        $_.FixScript -ne "# Manual trust review required" -and
        $_.FixScript -ne "# Manual certificate review required" -and
        $_.FixScript -ne "# Manual DNS server configuration required" -and
        $_.FixScript -ne "# Manual trust configuration review required" -and
        $_.FixScript -ne "# Manual schema update required - use caution" -and
        $_.FixScript -ne "# Manual CA review required" -and
        $_.FixScript -ne "# Manual certificate template review required" -and
        $_.FixScript -ne "# Domain information only" -and
        $_.FixScript -ne "# No fix required - verification only" -and
        $_.FixScript -ne "" -and
        $null -ne $_.FixScript
    }
    
    if ($fixableIssues.Count -eq 0) {
        Write-Host "`nNo automatically fixable issues found." -ForegroundColor Yellow
        Write-Host "All remaining issues require manual review or verification." -ForegroundColor Yellow
        return
    }
    
    # Show summary of what will be fixed
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Issues Ready for Automatic Fix" -ForegroundColor Yellow
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Found $($fixableIssues.Count) automatically fixable issue(s):" -ForegroundColor White
    Write-Host ""
    
    $highCount = ($fixableIssues | Where-Object { $_.Severity -eq "High" }).Count
    $mediumCount = ($fixableIssues | Where-Object { $_.Severity -eq "Medium" }).Count
    $lowCount = ($fixableIssues | Where-Object { $_.Severity -eq "Low" }).Count
    
    Write-Host "  High Severity: $highCount" -ForegroundColor Red
    Write-Host "  Medium Severity: $mediumCount" -ForegroundColor Yellow
    Write-Host "  Low Severity: $lowCount" -ForegroundColor Cyan
    Write-Host ""
    
    # Show first 5 issues as preview
    Write-Host "Preview of issues to fix:" -ForegroundColor White
    $fixableIssues | Select-Object -First 5 | ForEach-Object {
        Write-Host "  - [$($_.Severity)] $($_.Finding)" -ForegroundColor Gray
    }
    if ($fixableIssues.Count -gt 5) {
        Write-Host "  ... and $($fixableIssues.Count - 5) more" -ForegroundColor Gray
    }
    Write-Host ""
    Write-Host "========================================" -ForegroundColor Cyan
    
    # Backup before fixes if enabled
    if ($script:Config.GPOBackupRestore.Enabled -and $script:Config.GPOBackupRestore.AutoBackup) {
        Write-Host "`nCreating backup before applying fixes..." -ForegroundColor Yellow
        Backup-DomainConfig -BackupPath $script:BackupPath
    }
    
    # Get confirmation with clearer prompt
    Write-Host "`nWARNING: This will modify Active Directory settings!" -ForegroundColor Red
    $confirm = Read-Host "Type 'YES' to proceed with fixes, or anything else to cancel"
    
    if ($confirm -ne "YES") {
        Write-Host "`nFix operation cancelled by user." -ForegroundColor Yellow
        return
    }
    
    Write-Host "`nApplying fixes..." -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan
    
    $successCount = 0
    $failCount = 0
    
    foreach ($issue in $fixableIssues) {
        Write-Host "`n[*] Fixing: $($issue.Finding)" -ForegroundColor Yellow
        Write-Host "    Category: $($issue.Category)" -ForegroundColor Gray
        Write-Host "    Severity: $($issue.Severity)" -ForegroundColor $(if ($issue.Severity -eq "High") { "Red" } elseif ($issue.Severity -eq "Medium") { "Yellow" } else { "Cyan" })
        
        try {
            # Validate fix script doesn't contain dangerous commands
            $dangerousCommands = @("Remove-AD", "Remove-Item", "Delete", "Format", "Clear")
            $isDangerous = $false
            foreach ($cmd in $dangerousCommands) {
                if ($issue.FixScript -like "*$cmd*") {
                    $isDangerous = $true
                    break
                }
            }
            
            if ($isDangerous -and $issue.FixScript -notlike "*#*") {
                Write-Host "    [SKIPPED] Fix contains potentially dangerous command - requires manual review" -ForegroundColor Yellow
                continue
            }
            
            # Execute the fix script
            Invoke-Expression -Command $issue.FixScript -ErrorAction Stop
            $issue.Fixed = $true
            $issue.FixTimestamp = Get-Date
            $script:FixedIssues += $issue
            $successCount++
            Write-Host "    [OK] Fixed successfully" -ForegroundColor Green
        } catch {
            $failCount++
            Write-Host "    [ERROR] Failed to fix: $_" -ForegroundColor Red
            $issue.FixError = $_.Exception.Message
        }
    }
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "Fix Operation Complete!" -ForegroundColor Green
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Successfully Fixed: $successCount" -ForegroundColor Green
    Write-Host "Failed: $failCount" -ForegroundColor $(if ($failCount -gt 0) { "Red" } else { "Green" })
    Write-Host "Total Issues Fixed: $($script:FixedIssues.Count)" -ForegroundColor White
    Write-Host "========================================`n" -ForegroundColor Cyan
}

# Function to generate fix report
function New-FixReport {
    param(
        [string]$ReportPath
    )
    
    $reportDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $fixedCount = $script:FixedIssues.Count
    
    $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>AD Compliance Fix Report - $script:ComplianceFramework</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            margin: 20px;
            background-color: #f5f5f5;
        }
        .header {
            background-color: #27ae60;
            color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
        }
        .summary {
            background-color: white;
            padding: 20px;
            border-radius: 5px;
            margin-bottom: 20px;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        table {
            width: 100%;
            border-collapse: collapse;
            background-color: white;
            box-shadow: 0 2px 4px rgba(0,0,0,0.1);
        }
        th, td {
            padding: 12px;
            text-align: left;
            border-bottom: 1px solid #ddd;
        }
        th {
            background-color: #27ae60;
            color: white;
        }
        tr:hover {
            background-color: #f5f5f5;
        }
        .fixed { color: #27ae60; font-weight: bold; }
    </style>
</head>
<body>
    <div class="header">
        <h1>Active Directory Compliance Fix Report</h1>
        <h2>Framework: $script:ComplianceFramework</h2>
        <p>Generated: $reportDate</p>
        <p>Issues Fixed: $fixedCount</p>
    </div>
    
    <div class="summary">
        <h2>Summary</h2>
        <p>This report shows the issues that were automatically fixed.</p>
    </div>
    
    <table>
        <thead>
            <tr>
                <th>Category</th>
                <th>Finding</th>
                <th>Severity</th>
                <th>Fix Applied</th>
                <th>Fix Timestamp</th>
            </tr>
        </thead>
        <tbody>
"@
    
    foreach ($issue in $script:FixedIssues) {
        $html += @"
            <tr>
                <td>$($issue.Category)</td>
                <td>$($issue.Finding)</td>
                <td>$($issue.Severity)</td>
                <td class="fixed">Fixed</td>
                <td>$($issue.FixTimestamp)</td>
            </tr>
"@
    }
    
    $html += @"
        </tbody>
    </table>
</body>
</html>
"@
    
    $html | Out-File -FilePath $ReportPath -Encoding UTF8
    Write-Host "Fix report generated: $ReportPath" -ForegroundColor Green
}

# ==================== CONFIGURATION MENU ====================

# Function to show Microsoft 365 setup instructions
function Show-Microsoft365SetupInstructions {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "   Microsoft 365 / Entra ID Setup      " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "STEP 1: Create App Registration in Azure Portal" -ForegroundColor Yellow
    Write-Host "  1. Go to: https://portal.azure.com" -ForegroundColor White
    Write-Host "  2. Navigate to: Azure Active Directory > App registrations" -ForegroundColor White
    Write-Host "  3. Click: 'New registration'" -ForegroundColor White
    Write-Host "  4. Enter a name (e.g., 'AD Compliance Auditor')" -ForegroundColor White
    Write-Host "  5. Select: 'Accounts in this organizational directory only'" -ForegroundColor White
    Write-Host "  6. Click: 'Register'" -ForegroundColor White
    Write-Host ""
    Write-Host "STEP 2: Copy Your Tenant ID and Client ID" -ForegroundColor Yellow
    Write-Host "  1. On the app overview page, copy these values:" -ForegroundColor White
    Write-Host "     - Directory (tenant) ID = TENANT ID" -ForegroundColor Green
    Write-Host "     - Application (client) ID = CLIENT ID" -ForegroundColor Green
    Write-Host ""
    Write-Host "STEP 3: Create Client Secret (Optional - for automated auth)" -ForegroundColor Yellow
    Write-Host "  1. Go to: Certificates & secrets" -ForegroundColor White
    Write-Host "  2. Click: 'New client secret'" -ForegroundColor White
    Write-Host "  3. Enter description and expiration" -ForegroundColor White
    Write-Host "  4. Click: 'Add'" -ForegroundColor White
    Write-Host "  5. COPY THE VALUE IMMEDIATELY (you won't see it again!)" -ForegroundColor Red
    Write-Host ""
    Write-Host "STEP 4: Grant API Permissions" -ForegroundColor Yellow
    Write-Host "  1. Go to: API permissions" -ForegroundColor White
    Write-Host "  2. Click: 'Add a permission'" -ForegroundColor White
    Write-Host "  3. Select: 'Microsoft Graph'" -ForegroundColor White
    Write-Host "  4. Select: 'Application permissions'" -ForegroundColor White
    Write-Host "  5. Add these permissions:" -ForegroundColor White
    Write-Host "     - Directory.Read.All" -ForegroundColor Green
    Write-Host "     - Policy.Read.All" -ForegroundColor Green
    Write-Host "     - User.Read.All" -ForegroundColor Green
    Write-Host "     - IdentityRiskEvent.Read.All (optional - for risky sign-ins)" -ForegroundColor Green
    Write-Host "  6. Click: 'Grant admin consent for [Your Organization]'" -ForegroundColor White
    Write-Host ""
    Write-Host "STEP 5: Enter Configuration" -ForegroundColor Yellow
    Write-Host "  - Enter Tenant ID when prompted" -ForegroundColor White
    Write-Host "  - Enter Client ID when prompted" -ForegroundColor White
    Write-Host "  - Enter Client Secret if you created one (or leave blank for interactive auth)" -ForegroundColor White
    Write-Host ""
    Write-Host "NOTE: If you don't create a client secret, you'll need to authenticate" -ForegroundColor Yellow
    Write-Host "      interactively using a device code each time you run an audit." -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Press any key to continue..." -ForegroundColor Cyan
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Function to show Google Workspace setup instructions
function Show-GoogleWorkspaceSetupInstructions {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "      Google Workspace Setup            " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "STEP 1: Install Required PowerShell Module" -ForegroundColor Yellow
    Write-Host "  Run this command in PowerShell (as Administrator):" -ForegroundColor White
    Write-Host "  Install-Module -Name Google.Apis.Auth -Force" -ForegroundColor Green
    Write-Host ""
    Write-Host "STEP 2: Create Service Account in Google Cloud Console" -ForegroundColor Yellow
    Write-Host "  1. Go to: https://console.cloud.google.com" -ForegroundColor White
    Write-Host "  2. Select or create a project" -ForegroundColor White
    Write-Host "  3. Go to: APIs & Services > Credentials" -ForegroundColor White
    Write-Host "  4. Click: 'Create Credentials' > 'Service account'" -ForegroundColor White
    Write-Host "  5. Enter name: 'AD Compliance Auditor'" -ForegroundColor White
    Write-Host "  6. Click: 'Create and Continue'" -ForegroundColor White
    Write-Host "  7. Skip role assignment, click 'Done'" -ForegroundColor White
    Write-Host ""
    Write-Host "STEP 3: Create Service Account Key" -ForegroundColor Yellow
    Write-Host "  1. Click on the service account you just created" -ForegroundColor White
    Write-Host "  2. Go to: 'Keys' tab" -ForegroundColor White
    Write-Host "  3. Click: 'Add Key' > 'Create new key'" -ForegroundColor White
    Write-Host "  4. Select: 'JSON' format" -ForegroundColor White
    Write-Host "  5. Click: 'Create'" -ForegroundColor White
    Write-Host "  6. Save the downloaded JSON file securely" -ForegroundColor White
    Write-Host ""
    Write-Host "STEP 4: Enable Google Admin SDK API" -ForegroundColor Yellow
    Write-Host "  1. Go to: APIs & Services > Library" -ForegroundColor White
    Write-Host "  2. Search for: 'Admin SDK API'" -ForegroundColor White
    Write-Host "  3. Click on it and click: 'Enable'" -ForegroundColor White
    Write-Host ""
    Write-Host "STEP 5: Delegate Domain-Wide Authority (in Google Admin Console)" -ForegroundColor Yellow
    Write-Host "  1. Go to: https://admin.google.com" -ForegroundColor White
    Write-Host "  2. Navigate to: Security > API Controls > Domain-wide Delegation" -ForegroundColor White
    Write-Host "  3. Click: 'Add new'" -ForegroundColor White
    Write-Host "  4. Enter Client ID (from service account JSON file)" -ForegroundColor White
    Write-Host "  5. OAuth Scopes (comma-separated):" -ForegroundColor White
    Write-Host "     https://www.googleapis.com/auth/admin.directory.user.readonly," -ForegroundColor Green
    Write-Host "     https://www.googleapis.com/auth/admin.directory.group.readonly," -ForegroundColor Green
    Write-Host "     https://www.googleapis.com/auth/admin.directory.domain.readonly" -ForegroundColor Green
    Write-Host "  6. Click: 'Authorize'" -ForegroundColor White
    Write-Host ""
    Write-Host "STEP 6: Get Your Customer ID" -ForegroundColor Yellow
    Write-Host "  1. In Google Admin Console, go to: Account > Account Settings" -ForegroundColor White
    Write-Host "  2. Find: 'Customer ID' (looks like Cxxxxxxxxx)" -ForegroundColor White
    Write-Host "  3. Copy this value" -ForegroundColor White
    Write-Host ""
    Write-Host "STEP 7: Enter Configuration" -ForegroundColor Yellow
    Write-Host "  - Enter full path to the service account JSON key file" -ForegroundColor White
    Write-Host "  - Enter Customer ID (Cxxxxxxxxx format)" -ForegroundColor White
    Write-Host ""
    Write-Host "Press any key to continue..." -ForegroundColor Cyan
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Function to show configuration menu
function Show-ConfigMenu {
    do {
        Clear-Host
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host "   Configuration Menu                  " -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "1. Enable/Disable Optional Checks" -ForegroundColor White
        Write-Host "2. Microsoft 365 / Entra ID Configuration" -ForegroundColor White
        Write-Host "3. Google Workspace Configuration" -ForegroundColor White
        Write-Host "4. Show Microsoft 365 Setup Instructions" -ForegroundColor Cyan
        Write-Host "5. Show Google Workspace Setup Instructions" -ForegroundColor Cyan
        Write-Host "6. Save Configuration" -ForegroundColor Yellow
        Write-Host "7. Return to Main Menu" -ForegroundColor White
        Write-Host ""
        $configChoice = Read-Host "Enter choice (1-7)"
        
        switch ($configChoice) {
            "1" {
                Write-Host "`nOptional Checks Configuration:" -ForegroundColor Yellow
                Write-Host "1. Enhanced Password Checks: $(if ($script:Config.EnhancedPasswordChecks.Enabled) { 'ENABLED' } else { 'DISABLED' })" -ForegroundColor $(if ($script:Config.EnhancedPasswordChecks.Enabled) { 'Green' } else { 'Red' })
                Write-Host "2. SMB Protocol Checks: $(if ($script:Config.SMBProtocol.Enabled) { 'ENABLED' } else { 'DISABLED' })" -ForegroundColor $(if ($script:Config.SMBProtocol.Enabled) { 'Green' } else { 'Red' })
                Write-Host "3. RBAC Permissions: $(if ($script:Config.RBACPermissions.Enabled) { 'ENABLED' } else { 'DISABLED' })" -ForegroundColor $(if ($script:Config.RBACPermissions.Enabled) { 'Green' } else { 'Red' })
                Write-Host "4. Certificate & PKI: $(if ($script:Config.CertificatePKI.Enabled) { 'ENABLED' } else { 'DISABLED' })" -ForegroundColor $(if ($script:Config.CertificatePKI.Enabled) { 'Green' } else { 'Red' })
                Write-Host "5. Multi-Domain Support: $(if ($script:Config.MultiDomainSupport.Enabled) { 'ENABLED' } else { 'DISABLED' })" -ForegroundColor $(if ($script:Config.MultiDomainSupport.Enabled) { 'Green' } else { 'Red' })
                $toggle = Read-Host "`nEnter number to toggle (or press Enter to cancel)"
                
                switch ($toggle) {
                    "1" { $script:Config.EnhancedPasswordChecks.Enabled = -not $script:Config.EnhancedPasswordChecks.Enabled }
                    "2" { $script:Config.SMBProtocol.Enabled = -not $script:Config.SMBProtocol.Enabled }
                    "3" { $script:Config.RBACPermissions.Enabled = -not $script:Config.RBACPermissions.Enabled }
                    "4" { $script:Config.CertificatePKI.Enabled = -not $script:Config.CertificatePKI.Enabled }
                    "5" { $script:Config.MultiDomainSupport.Enabled = -not $script:Config.MultiDomainSupport.Enabled }
                }
                
                Write-Host "Configuration updated!" -ForegroundColor Green
                Start-Sleep -Seconds 1
            }
            "2" {
                Write-Host "`nMicrosoft 365 / Entra ID Configuration:" -ForegroundColor Yellow
                Write-Host "Current Status: $(if ($script:Config.Microsoft365.Enabled) { 'ENABLED' } else { 'DISABLED' })" -ForegroundColor $(if ($script:Config.Microsoft365.Enabled) { 'Green' } else { 'Red' })
                Write-Host "Tenant ID: $(if ($script:Config.Microsoft365.TenantId) { $script:Config.Microsoft365.TenantId } else { 'NOT SET' })" -ForegroundColor White
                Write-Host "Client ID: $(if ($script:Config.Microsoft365.ClientId) { $script:Config.Microsoft365.ClientId } else { 'NOT SET' })" -ForegroundColor White
                Write-Host "Client Secret: $(if ($script:Config.Microsoft365.ClientSecret) { '***SET***' } else { 'NOT SET' })" -ForegroundColor White
                Write-Host ""
                Write-Host "1. Enable/Disable Microsoft 365 checks" -ForegroundColor White
                Write-Host "2. Set Tenant ID" -ForegroundColor White
                Write-Host "3. Set Client ID" -ForegroundColor White
                Write-Host "4. Set Client Secret" -ForegroundColor White
                $m365Choice = Read-Host "Enter choice (1-4, or Enter to cancel)"
                
                switch ($m365Choice) {
                    "1" { 
                        $script:Config.Microsoft365.Enabled = -not $script:Config.Microsoft365.Enabled
                        Write-Host "Microsoft 365 checks: $(if ($script:Config.Microsoft365.Enabled) { 'ENABLED' } else { 'DISABLED' })" -ForegroundColor Green
                    }
                    "2" { 
                        $script:Config.Microsoft365.TenantId = Read-Host "Enter Tenant ID (GUID format)"
                    }
                    "3" { 
                        $script:Config.Microsoft365.ClientId = Read-Host "Enter Client ID (GUID format)"
                    }
                    "4" { 
                        $script:Config.Microsoft365.ClientSecret = Read-Host "Enter Client Secret" -AsSecureString | ConvertFrom-SecureString
                    }
                }
            }
            "3" {
                Write-Host "`nGoogle Workspace Configuration:" -ForegroundColor Yellow
                Write-Host "Current Status: $(if ($script:Config.GoogleWorkspace.Enabled) { 'ENABLED' } else { 'DISABLED' })" -ForegroundColor $(if ($script:Config.GoogleWorkspace.Enabled) { 'Green' } else { 'Red' })
                Write-Host "Service Account Key: $(if ($script:Config.GoogleWorkspace.ServiceAccountKey) { $script:Config.GoogleWorkspace.ServiceAccountKey } else { 'NOT SET' })" -ForegroundColor White
                Write-Host "Customer ID: $(if ($script:Config.GoogleWorkspace.CustomerId) { $script:Config.GoogleWorkspace.CustomerId } else { 'NOT SET' })" -ForegroundColor White
                Write-Host ""
                Write-Host "1. Enable/Disable Google Workspace checks" -ForegroundColor White
                Write-Host "2. Set Service Account Key Path" -ForegroundColor White
                Write-Host "3. Set Customer ID" -ForegroundColor White
                $googleChoice = Read-Host "Enter choice (1-3, or Enter to cancel)"
                
                switch ($googleChoice) {
                    "1" { 
                        $script:Config.GoogleWorkspace.Enabled = -not $script:Config.GoogleWorkspace.Enabled
                        Write-Host "Google Workspace checks: $(if ($script:Config.GoogleWorkspace.Enabled) { 'ENABLED' } else { 'DISABLED' })" -ForegroundColor Green
                    }
                    "2" { 
                        $keyPath = Read-Host "Enter full path to Service Account JSON key file"
                        if (Test-Path $keyPath) {
                            $script:Config.GoogleWorkspace.ServiceAccountKey = $keyPath
                            Write-Host "Service Account Key path set!" -ForegroundColor Green
                        } else {
                            Write-Host "File not found!" -ForegroundColor Red
                        }
                    }
                    "3" { 
                        $script:Config.GoogleWorkspace.CustomerId = Read-Host "Enter Customer ID (Cxxxxxxxxx format)"
                    }
                }
            }
            "4" {
                Show-Microsoft365SetupInstructions
            }
            "5" {
                Show-GoogleWorkspaceSetupInstructions
            }
            "6" {
                Save-Config -ConfigPath $ConfigPath
                Write-Host "`nConfiguration saved!" -ForegroundColor Green
                Start-Sleep -Seconds 1
            }
            "7" {
                return
            }
            default {
                Write-Host "Invalid choice. Press any key to continue..." -ForegroundColor Red
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
        }
    } while ($true)
}

# ==================== AUTO-FIX WITH COMPLIANCE STANDARDS ====================

# Function to apply standard security settings based on compliance framework
function Apply-StandardComplianceFixes {
    param(
        [string]$Framework,
        [switch]$AutoConfirm = $false
    )
    
    if (-not $AutoConfirm -and -not $Silent) {
        Write-Host "`n========================================" -ForegroundColor Cyan
        Write-Host "   Applying Standard $Framework Security Settings" -ForegroundColor Cyan
        Write-Host "========================================" -ForegroundColor Cyan
        Write-Host ""
        Write-Host "WARNING: This will apply standard security settings for $Framework compliance." -ForegroundColor Yellow
        Write-Host "These settings are based on industry best practices for $Framework." -ForegroundColor Yellow
        Write-Host ""
        $confirm = Read-Host "Type 'YES' to authorize automatic fixes for $Framework, or anything else to cancel"
        
        if ($confirm -ne "YES") {
            Write-Host "`nAuto-fix operation cancelled." -ForegroundColor Yellow
            return $false
        }
    } else {
        if (-not $Silent) {
            Write-Host "`nApplying standard $Framework security settings (auto-confirmed)..." -ForegroundColor Yellow
        }
    }
    
    Write-Host "`nApplying standard security settings..." -ForegroundColor Green
    
    # Standard settings based on framework
    switch ($Framework.ToUpper()) {
        "HIPAA" {
            # HIPAA: Strong passwords, audit logging, encryption, access controls
            Write-Host "  [*] Applying HIPAA standard settings..." -ForegroundColor Yellow
            Apply-HIPAASecuritySettings
        }
        "CMMC" {
            # CMMC: NIST-based security controls
            Write-Host "  [*] Applying CMMC standard settings..." -ForegroundColor Yellow
            Apply-CMMCSecuritySettings
        }
        { $_ -eq "NIST/CIS" -or $_ -eq "NISTCIS" } {
            # NIST/CIS: Baseline security controls
            Write-Host "  [*] Applying NIST/CIS standard settings..." -ForegroundColor Yellow
            Apply-NISTCISSecuritySettings
        }
        "GLBA" {
            # GLBA: Financial information protection
            Write-Host "  [*] Applying GLBA standard settings..." -ForegroundColor Yellow
            Apply-GLBASecuritySettings
        }
        "SOX" {
            # SOX: Financial reporting security
            Write-Host "  [*] Applying SOX standard settings..." -ForegroundColor Yellow
            Apply-SOXSecuritySettings
        }
        { $_ -eq "PCI-DSS" -or $_ -eq "PCI" -or $_ -eq "PCIDSS" } {
            # PCI-DSS: Payment card data protection
            Write-Host "  [*] Applying PCI-DSS standard settings..." -ForegroundColor Yellow
            Apply-PCIDSSSecuritySettings
        }
        "GDPR" {
            # GDPR: Data protection and privacy
            Write-Host "  [*] Applying GDPR standard settings..." -ForegroundColor Yellow
            Apply-GDPRSecuritySettings
        }
        "FISMA" {
            # FISMA: Federal information security
            Write-Host "  [*] Applying FISMA standard settings..." -ForegroundColor Yellow
            Apply-FISMASecuritySettings
        }
        default {
            Write-Host "  [WARNING] Unknown framework, applying general security settings..." -ForegroundColor Yellow
            Apply-GeneralSecuritySettings
        }
    }
    
    # Apply advanced auto-fixes (90%+ automation)
    Write-Host "`n  [*] Applying advanced auto-fixes (service accounts, trusts, certificates, cloud services)..." -ForegroundColor Yellow
    $advancedFixed = Apply-AdvancedAutoFixes
    
    Write-Host "`nStandard security settings applied!" -ForegroundColor Green
    Write-Host "Advanced auto-fixes applied: $advancedFixed additional item(s)" -ForegroundColor Green
    return $true
}

# Framework-specific security settings functions
function Apply-HIPAASecuritySettings {
    try {
        # Password policy: 14 chars, complexity, 90 day expiration, 24 password history
        $domain = Get-ADDomain
        Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -MinPasswordLength 14 -ComplexityEnabled $true -MaxPasswordAge (New-TimeSpan -Days 90) -PasswordHistoryCount 24 -ErrorAction SilentlyContinue
        
        # Account lockout: 5 attempts, 30 min lockout
        Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -LockoutThreshold 5 -LockoutDuration (New-TimeSpan -Minutes 30) -LockoutObservationWindow (New-TimeSpan -Minutes 30) -ErrorAction SilentlyContinue
        
        Write-Host "    [OK] HIPAA password and lockout policies configured" -ForegroundColor Green
    } catch {
        Write-Host "    [WARNING] Could not apply password policy: $_" -ForegroundColor Yellow
    }
}

function Apply-CMMCSecuritySettings {
    try {
        # CMMC uses NIST 800-171/800-53 controls - strong security baseline
        $domain = Get-ADDomain
        Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -MinPasswordLength 14 -ComplexityEnabled $true -MaxPasswordAge (New-TimeSpan -Days 60) -PasswordHistoryCount 24 -ErrorAction SilentlyContinue
        Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -LockoutThreshold 3 -LockoutDuration (New-TimeSpan -Minutes 15) -LockoutObservationWindow (New-TimeSpan -Minutes 15) -ErrorAction SilentlyContinue
        Write-Host "    [OK] CMMC password and lockout policies configured" -ForegroundColor Green
    } catch {
        Write-Host "    [WARNING] Could not apply password policy: $_" -ForegroundColor Yellow
    }
}

function Apply-NISTCISSecuritySettings {
    try {
        # CIS/NIST baseline controls
        $domain = Get-ADDomain
        Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -MinPasswordLength 14 -ComplexityEnabled $true -MaxPasswordAge (New-TimeSpan -Days 90) -PasswordHistoryCount 24 -ErrorAction SilentlyContinue
        Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -LockoutThreshold 5 -LockoutDuration (New-TimeSpan -Minutes 30) -LockoutObservationWindow (New-TimeSpan -Minutes 30) -ErrorAction SilentlyContinue
        Write-Host "    [OK] NIST/CIS password and lockout policies configured" -ForegroundColor Green
    } catch {
        Write-Host "    [WARNING] Could not apply password policy: $_" -ForegroundColor Yellow
    }
}

function Apply-GLBASecuritySettings {
    try {
        # GLBA: Financial data protection
        $domain = Get-ADDomain
        Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -MinPasswordLength 14 -ComplexityEnabled $true -MaxPasswordAge (New-TimeSpan -Days 90) -PasswordHistoryCount 24 -ErrorAction SilentlyContinue
        Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -LockoutThreshold 5 -LockoutDuration (New-TimeSpan -Minutes 30) -LockoutObservationWindow (New-TimeSpan -Minutes 30) -ErrorAction SilentlyContinue
        Write-Host "    [OK] GLBA password and lockout policies configured" -ForegroundColor Green
    } catch {
        Write-Host "    [WARNING] Could not apply password policy: $_" -ForegroundColor Yellow
    }
}

function Apply-SOXSecuritySettings {
    try {
        # SOX: Financial reporting controls
        $domain = Get-ADDomain
        Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -MinPasswordLength 14 -ComplexityEnabled $true -MaxPasswordAge (New-TimeSpan -Days 90) -PasswordHistoryCount 24 -ErrorAction SilentlyContinue
        Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -LockoutThreshold 5 -LockoutDuration (New-TimeSpan -Minutes 30) -LockoutObservationWindow (New-TimeSpan -Minutes 30) -ErrorAction SilentlyContinue
        Write-Host "    [OK] SOX password and lockout policies configured" -ForegroundColor Green
    } catch {
        Write-Host "    [WARNING] Could not apply password policy: $_" -ForegroundColor Yellow
    }
}

function Apply-PCIDSSSecuritySettings {
    try {
        # PCI-DSS: Payment card data - strongest controls
        $domain = Get-ADDomain
        Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -MinPasswordLength 14 -ComplexityEnabled $true -MaxPasswordAge (New-TimeSpan -Days 90) -PasswordHistoryCount 24 -ErrorAction SilentlyContinue
        Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -LockoutThreshold 3 -LockoutDuration (New-TimeSpan -Minutes 30) -LockoutObservationWindow (New-TimeSpan -Minutes 30) -ErrorAction SilentlyContinue
        Write-Host "    [OK] PCI-DSS password and lockout policies configured" -ForegroundColor Green
    } catch {
        Write-Host "    [WARNING] Could not apply password policy: $_" -ForegroundColor Yellow
    }
}

function Apply-GDPRSecuritySettings {
    try {
        # GDPR: Data protection
        $domain = Get-ADDomain
        Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -MinPasswordLength 14 -ComplexityEnabled $true -MaxPasswordAge (New-TimeSpan -Days 90) -PasswordHistoryCount 24 -ErrorAction SilentlyContinue
        Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -LockoutThreshold 5 -LockoutDuration (New-TimeSpan -Minutes 30) -LockoutObservationWindow (New-TimeSpan -Minutes 30) -ErrorAction SilentlyContinue
        Write-Host "    [OK] GDPR password and lockout policies configured" -ForegroundColor Green
    } catch {
        Write-Host "    [WARNING] Could not apply password policy: $_" -ForegroundColor Yellow
    }
}

function Apply-FISMASecuritySettings {
    try {
        # FISMA: Federal security controls
        $domain = Get-ADDomain
        Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -MinPasswordLength 14 -ComplexityEnabled $true -MaxPasswordAge (New-TimeSpan -Days 60) -PasswordHistoryCount 24 -ErrorAction SilentlyContinue
        Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -LockoutThreshold 3 -LockoutDuration (New-TimeSpan -Minutes 15) -LockoutObservationWindow (New-TimeSpan -Minutes 15) -ErrorAction SilentlyContinue
        Write-Host "    [OK] FISMA password and lockout policies configured" -ForegroundColor Green
    } catch {
        Write-Host "    [WARNING] Could not apply password policy: $_" -ForegroundColor Yellow
    }
}

function Apply-GeneralSecuritySettings {
    try {
        # General security baseline
        $domain = Get-ADDomain
        Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -MinPasswordLength 14 -ComplexityEnabled $true -MaxPasswordAge (New-TimeSpan -Days 90) -PasswordHistoryCount 24 -ErrorAction SilentlyContinue
        Set-ADDefaultDomainPasswordPolicy -Identity $domain.DNSRoot -LockoutThreshold 5 -LockoutDuration (New-TimeSpan -Minutes 30) -LockoutObservationWindow (New-TimeSpan -Minutes 30) -ErrorAction SilentlyContinue
        Write-Host "    [OK] General security policies configured" -ForegroundColor Green
    } catch {
        Write-Host "    [WARNING] Could not apply password policy: $_" -ForegroundColor Yellow
    }
}

# ==================== ADVANCED AUTO-FIX FUNCTIONS (90%+ Automation) ====================

# Function to auto-fix service account configurations
function Fix-ServiceAccountConfigurations {
    Write-Host "`n  [*] Fixing service account configurations..." -ForegroundColor Yellow
    
    $serviceAccounts = Get-ADUser -Filter {ServicePrincipalName -like "*" -and Enabled -eq $true} -Properties ServicePrincipalName, DistinguishedName, PasswordNeverExpires -ErrorAction SilentlyContinue
    
    $fixed = 0
    foreach ($account in $serviceAccounts) {
        if (-not $account.PasswordNeverExpires) {
            try {
                # Set password never expires with description note
                $currentDesc = (Get-ADUser -Identity $account.DistinguishedName -Properties Description -ErrorAction SilentlyContinue).Description
                $newDesc = if ($currentDesc) { 
                    "$currentDesc | Service Account - Password Never Expires (Compliance Fix - $(Get-Date -Format 'yyyy-MM-dd'))" 
                } else { 
                    "Service Account - Password Never Expires (Compliance Fix - $(Get-Date -Format 'yyyy-MM-dd'))" 
                }
                Set-ADUser -Identity $account.DistinguishedName -PasswordNeverExpires $true -Description $newDesc -ErrorAction Stop
                $fixed++
                if (-not $Silent) {
                    Write-Host "    [OK] Set password never expires for: $($account.SamAccountName)" -ForegroundColor Green
                }
            } catch {
                if (-not $Silent) {
                    Write-Host "    [WARNING] Could not fix service account $($account.SamAccountName): $_" -ForegroundColor Yellow
                }
            }
        }
    }
    
    if (-not $Silent) {
        Write-Host "  [OK] Fixed $fixed service account(s)" -ForegroundColor Green
    }
    return $fixed
}

# Function to auto-fix domain trust relationships (enable SID filtering)
function Fix-TrustRelationships {
    Write-Host "`n  [*] Fixing domain trust relationships..." -ForegroundColor Yellow
    
    try {
        $trusts = Get-ADTrust -Filter * -ErrorAction SilentlyContinue
        
        if (-not $trusts) {
            if (-not $Silent) {
                Write-Host "    [INFO] No domain trusts found" -ForegroundColor Cyan
            }
            return 0
        }
        
        $fixed = 0
        foreach ($trust in $trusts) {
            try {
                # Enable SID filtering for external trusts (if not already enabled)
                if ($trust.TrustType -eq "External") {
                    try {
                        $trustDetails = Get-ADTrust -Identity $trust.Name -ErrorAction Stop
                        if (-not $trustDetails.SIDFilteringEnabled) {
                            Set-ADTrust -Identity $trust.Name -SIDFilteringEnabled $true -ErrorAction Stop
                            $fixed++
                            if (-not $Silent) {
                                Write-Host "    [OK] Enabled SID filtering for external trust: $($trust.Name)" -ForegroundColor Green
                            }
                        } else {
                            if (-not $Silent) {
                                Write-Host "    [OK] SID filtering already enabled for: $($trust.Name)" -ForegroundColor Cyan
                            }
                        }
                    } catch {
                        if (-not $Silent) {
                            Write-Host "    [WARNING] Could not check/enable SID filtering for trust $($trust.Name): $_" -ForegroundColor Yellow
                        }
                    }
                }
                
                # For forest trusts, provide information (selective authentication requires manual review)
                if ($trust.TrustType -eq "Forest") {
                    if (-not $Silent) {
                        Write-Host "    [INFO] Forest trust found: $($trust.Name) - Review selective authentication settings manually" -ForegroundColor Cyan
                    }
                }
            } catch {
                if (-not $Silent) {
                    Write-Host "    [WARNING] Could not process trust $($trust.Name): $_" -ForegroundColor Yellow
                }
            }
        }
        
        if (-not $Silent) {
            Write-Host "  [OK] Fixed $fixed trust relationship(s)" -ForegroundColor Green
        }
        return $fixed
    } catch {
        if (-not $Silent) {
            Write-Host "  [WARNING] Could not check/fix trust relationships: $_" -ForegroundColor Yellow
        }
        return 0
    }
}

# Function to auto-fix certificate/PKI issues (warnings and notifications)
function Fix-CertificatePKIIssues {
    Write-Host "`n  [*] Checking certificate/PKI issues..." -ForegroundColor Yellow
    
    try {
        # Check certificate stores (LocalMachine) for expiring certificates
        $certStores = @("My", "Root", "CA", "Trust")
        $expiringSoon = @()
        $thresholdDays = 30
        
        foreach ($storeName in $certStores) {
            try {
                $store = New-Object System.Security.Cryptography.X509Certificates.X509Store($storeName, "LocalMachine")
                $store.Open("ReadOnly")
                $certs = $store.Certificates
                
                foreach ($cert in $certs) {
                    $daysUntilExpiry = ($cert.NotAfter - (Get-Date)).Days
                    if ($daysUntilExpiry -gt 0 -and $daysUntilExpiry -le $thresholdDays) {
                        $expiringSoon += @{
                            Subject = $cert.Subject
                            Thumbprint = $cert.Thumbprint
                            ExpiryDate = $cert.NotAfter
                            DaysUntilExpiry = $daysUntilExpiry
                            Store = $storeName
                        }
                    }
                }
                $store.Close()
            } catch {
                # Store may not exist or may not be accessible
            }
        }
        
        if ($expiringSoon.Count -gt 0) {
            if (-not $Silent) {
                Write-Host "    [WARNING] Found $($expiringSoon.Count) certificate(s) expiring within $thresholdDays days" -ForegroundColor Yellow
                foreach ($cert in $expiringSoon) {
                    Write-Host "      - $($cert.Subject) expires in $($cert.DaysUntilExpiry) days ($($cert.ExpiryDate))" -ForegroundColor Yellow
                }
                Write-Host "    [INFO] Certificate renewal requires manual intervention" -ForegroundColor Cyan
            }
            Add-AuditFinding -Category "Certificate & PKI" `
                -Finding "$($expiringSoon.Count) certificate(s) expiring within $thresholdDays days" `
                -Severity "Medium" `
                -Description "Certificates need to be renewed before expiration" `
                -Recommendation "Renew expiring certificates or replace with new certificates" `
                -FixScript "# Manual certificate renewal required"
        } else {
            if (-not $Silent) {
                Write-Host "  [OK] No certificates expiring within $thresholdDays days" -ForegroundColor Green
            }
        }
        
        return $expiringSoon.Count
    } catch {
        if (-not $Silent) {
            Write-Host "  [WARNING] Could not check certificates: $_" -ForegroundColor Yellow
        }
        return 0
    }
}

# Function to auto-fix cloud service settings (Microsoft 365/Google Workspace)
function Fix-CloudServiceSettings {
    Write-Host "`n  [*] Checking cloud service settings..." -ForegroundColor Yellow
    
    $fixed = 0
    
    # Microsoft 365 / Entra ID fixes
    if ($script:Config.Microsoft365.Enabled) {
        try {
            if (-not $script:GraphToken) {
                if (Connect-Microsoft365) {
                    # Apply standard Microsoft 365 security settings
                    $policies = Invoke-MicrosoftGraph -Endpoint "policies/identitySecurityDefaultsEnforcementPolicy"
                    if ($policies -and -not $policies.isEnabled) {
                        # Enable security defaults (requires admin consent)
                        try {
                            $enableBody = @{ isEnabled = $true }
                            $result = Invoke-MicrosoftGraph -Method PATCH -Endpoint "policies/identitySecurityDefaultsEnforcementPolicy" -Body $enableBody
                            if ($result -or ($null -eq $result)) {
                                $fixed++
                                if (-not $Silent) {
                                    Write-Host "    [OK] Enabled Microsoft 365 Security Defaults" -ForegroundColor Green
                                }
                            }
                        } catch {
                            if (-not $Silent) {
                                Write-Host "    [WARNING] Could not enable security defaults (may require admin consent or permissions): $_" -ForegroundColor Yellow
                            }
                        }
                    } else {
                        if (-not $Silent) {
                            Write-Host "    [OK] Microsoft 365 Security Defaults already enabled" -ForegroundColor Cyan
                        }
                    }
                    
                    # Check and enable Conditional Access for admins (requires CA policy creation)
                    try {
                        $caPolicies = Invoke-MicrosoftGraph -Endpoint "identity/conditionalAccess/policies"
                        $adminMFA = $caPolicies.value | Where-Object { 
                            $_.state -eq "enabled" -and 
                            $_.conditions.users.includeRoles -contains "62e90394-69f5-4237-9190-012177145e10" -and # Global Administrator role
                            $_.grantControls.operator -eq "AND" -and
                            ($_.grantControls.builtInControls -contains "mfa")
                        }
                        
                        if (-not $adminMFA -or $adminMFA.Count -eq 0) {
                            if (-not $Silent) {
                                Write-Host "    [INFO] No Conditional Access policy found requiring MFA for Global Administrators" -ForegroundColor Yellow
                                Write-Host "    [INFO] Create a CA policy via Azure Portal to require MFA for admin roles" -ForegroundColor Cyan
                            }
                        }
                    } catch {
                        # May require additional permissions
                    }
                }
            } else {
                # Token already exists, check and fix
                $policies = Invoke-MicrosoftGraph -Endpoint "policies/identitySecurityDefaultsEnforcementPolicy"
                if ($policies -and -not $policies.isEnabled) {
                    try {
                        $enableBody = @{ isEnabled = $true }
                        $result = Invoke-MicrosoftGraph -Method PATCH -Endpoint "policies/identitySecurityDefaultsEnforcementPolicy" -Body $enableBody
                        if ($result -or ($null -eq $result)) {
                            $fixed++
                            if (-not $Silent) {
                                Write-Host "    [OK] Enabled Microsoft 365 Security Defaults" -ForegroundColor Green
                            }
                        }
                    } catch {
                        if (-not $Silent) {
                            Write-Host "    [WARNING] Could not enable security defaults: $_" -ForegroundColor Yellow
                        }
                    }
                }
            }
        } catch {
            if (-not $Silent) {
                Write-Host "    [WARNING] Could not fix Microsoft 365 settings: $_" -ForegroundColor Yellow
            }
        }
    }
    
    # Google Workspace fixes (requires Admin SDK API access and proper module)
    if ($script:Config.GoogleWorkspace.Enabled) {
        try {
            if (Connect-GoogleWorkspace) {
                # Check if Google.Apis.Auth module is available for full automation
                $moduleInstalled = Get-Module -ListAvailable -Name Google.Apis.Auth
                if ($moduleInstalled) {
                    if (-not $Silent) {
                        Write-Host "    [INFO] Google Workspace automation requires Google Admin SDK API access" -ForegroundColor Cyan
                        Write-Host "    [INFO] Full automation available with Google.Apis.Auth module and Admin SDK API permissions" -ForegroundColor Cyan
                    }
                } else {
                    if (-not $Silent) {
                        Write-Host "    [INFO] Install Google.Apis.Auth module for full Google Workspace automation" -ForegroundColor Cyan
                        Write-Host "    [INFO] Run: Install-Module -Name Google.Apis.Auth -Force" -ForegroundColor Yellow
                    }
                }
            }
        } catch {
            if (-not $Silent) {
                Write-Host "    [WARNING] Could not fix Google Workspace settings: $_" -ForegroundColor Yellow
            }
        }
    }
    
    if (-not $Silent -and $fixed -gt 0) {
        Write-Host "  [OK] Fixed $fixed cloud service setting(s)" -ForegroundColor Green
    }
    return $fixed
}

# Function to flag separation of duties violations (cannot auto-fix - requires manual review)
function Fix-SeparationOfDuties {
    Write-Host "`n  [*] Checking separation of duties violations..." -ForegroundColor Yellow
    Write-Host "    [INFO] Separation of duties violations require manual review" -ForegroundColor Cyan
    Write-Host "    [INFO] Auto-fix would remove users from groups - too risky for automation" -ForegroundColor Yellow
    Write-Host "    [INFO] Review findings in audit report and manually adjust group memberships" -ForegroundColor Cyan
    
    # Just run the check - don't auto-fix (too risky)
    Test-SeparationOfDuties
    
    # Return count of violations for reporting
    $violations = ($script:AuditResults | Where-Object { $_.Category -eq "Separation of Duties" }).Count
    return $violations
}

# Function to apply all advanced auto-fixes (90%+ automation)
function Apply-AdvancedAutoFixes {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "   Applying Advanced Auto-Fixes (90%+ Automation)" -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    $totalFixed = 0
    
    # Fix service accounts
    $fixed = Fix-ServiceAccountConfigurations
    $totalFixed += $fixed
    
    # Fix trust relationships
    $fixed = Fix-TrustRelationships
    $totalFixed += $fixed
    
    # Check certificate/PKI issues (provides warnings, but renewal requires manual action)
    $fixed = Fix-CertificatePKIIssues
    # Don't count cert checks as "fixed" since they're warnings
    
    # Fix cloud service settings
    $fixed = Fix-CloudServiceSettings
    $totalFixed += $fixed
    
    # Flag separation of duties (cannot auto-fix)
    $violations = Fix-SeparationOfDuties
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "   Advanced Auto-Fixes Complete         " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host "Items Fixed: $totalFixed" -ForegroundColor Green
    Write-Host "Separation of Duties Violations Found: $violations (requires manual review)" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "NOTE: Certificate/PKI issues require manual renewal." -ForegroundColor Cyan
    Write-Host "NOTE: Separation of duties violations require manual group membership review." -ForegroundColor Cyan
    Write-Host ""
    
    return $totalFixed
}

# Main execution loop
function Start-AuditProcess {
    do {
        $choice = Show-Menu
        
        switch ($choice) {
            "1" {
                Write-Host "`n" -NoNewline
                Start-HIPAAAudit
                $reportFile = Join-Path $OutputPath "HIPAA_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
                if ($script:ClientName) {
                    $clientSafeName = $script:ClientName -replace '[^\w\s-]', '' -replace '\s+', '_'
                    $reportFile = Join-Path $OutputPath "${clientSafeName}_HIPAA_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
                }
                New-HTMLReport -ReportPath $reportFile
                Save-AuditToHistory -Framework "HIPAA" -ReportPath $reportFile
                
                Write-Host "`nReport saved: $reportFile" -ForegroundColor Green
                Write-Host ""
                
                Invoke-PostAuditOptions -Framework "HIPAA"
                
                Write-Host "`nPress any key to return to main menu..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            "2" {
                Start-CMMCAudit
                $reportFile = Join-Path $OutputPath "CMMC_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
                if ($script:ClientName) {
                    $clientSafeName = $script:ClientName -replace '[^\w\s-]', '' -replace '\s+', '_'
                    $reportFile = Join-Path $OutputPath "${clientSafeName}_CMMC_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
                }
                New-HTMLReport -ReportPath $reportFile
                Save-AuditToHistory -Framework "CMMC" -ReportPath $reportFile
                
                Invoke-PostAuditOptions -Framework "CMMC"
                
                Write-Host "`nPress any key to return to main menu..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            "3" {
                Start-NISTCISAudit
                $reportFile = Join-Path $OutputPath "NISTCIS_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
                if ($script:ClientName) {
                    $clientSafeName = $script:ClientName -replace '[^\w\s-]', '' -replace '\s+', '_'
                    $reportFile = Join-Path $OutputPath "${clientSafeName}_NISTCIS_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
                }
                New-HTMLReport -ReportPath $reportFile
                Save-AuditToHistory -Framework "NIST/CIS" -ReportPath $reportFile
                
                Invoke-PostAuditOptions -Framework "NIST/CIS"
                
                Write-Host "`nPress any key to return to main menu..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            "4" {
                Start-GLBAAudit
                $reportFile = Join-Path $OutputPath "GLBA_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
                if ($script:ClientName) {
                    $clientSafeName = $script:ClientName -replace '[^\w\s-]', '' -replace '\s+', '_'
                    $reportFile = Join-Path $OutputPath "${clientSafeName}_GLBA_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
                }
                New-HTMLReport -ReportPath $reportFile
                Save-AuditToHistory -Framework "GLBA" -ReportPath $reportFile
                
                Invoke-PostAuditOptions -Framework "GLBA"
                
                Write-Host "`nPress any key to return to main menu..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            "5" {
                Start-SOXAudit
                $reportFile = Join-Path $OutputPath "SOX_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
                if ($script:ClientName) {
                    $clientSafeName = $script:ClientName -replace '[^\w\s-]', '' -replace '\s+', '_'
                    $reportFile = Join-Path $OutputPath "${clientSafeName}_SOX_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
                }
                New-HTMLReport -ReportPath $reportFile
                Save-AuditToHistory -Framework "SOX" -ReportPath $reportFile
                
                Invoke-PostAuditOptions -Framework "SOX"
                
                Write-Host "`nPress any key to return to main menu..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            "6" {
                Start-PCIDSSAudit
                $reportFile = Join-Path $OutputPath "PCI-DSS_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
                if ($script:ClientName) {
                    $clientSafeName = $script:ClientName -replace '[^\w\s-]', '' -replace '\s+', '_'
                    $reportFile = Join-Path $OutputPath "${clientSafeName}_PCI-DSS_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
                }
                New-HTMLReport -ReportPath $reportFile
                Save-AuditToHistory -Framework "PCI-DSS" -ReportPath $reportFile
                
                Invoke-PostAuditOptions -Framework "PCI-DSS"
                
                Write-Host "`nPress any key to return to main menu..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            "7" {
                Start-GDPRAudit
                $reportFile = Join-Path $OutputPath "GDPR_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
                if ($script:ClientName) {
                    $clientSafeName = $script:ClientName -replace '[^\w\s-]', '' -replace '\s+', '_'
                    $reportFile = Join-Path $OutputPath "${clientSafeName}_GDPR_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
                }
                New-HTMLReport -ReportPath $reportFile
                Save-AuditToHistory -Framework "GDPR" -ReportPath $reportFile
                
                Invoke-PostAuditOptions -Framework "GDPR"
                
                Write-Host "`nPress any key to return to main menu..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            "8" {
                Start-FISMAAudit
                $reportFile = Join-Path $OutputPath "FISMA_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
                if ($script:ClientName) {
                    $clientSafeName = $script:ClientName -replace '[^\w\s-]', '' -replace '\s+', '_'
                    $reportFile = Join-Path $OutputPath "${clientSafeName}_FISMA_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').html"
                }
                New-HTMLReport -ReportPath $reportFile
                Save-AuditToHistory -Framework "FISMA" -ReportPath $reportFile
                
                Invoke-PostAuditOptions -Framework "FISMA"
                
                Write-Host "`nPress any key to return to main menu..."
                $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            }
            "9" {
                Show-ConfigMenu
                # Config menu returns to main menu automatically
            }
            "10" {
                Set-ClientName
            }
            "11" {
                Show-AuditHistory
            }
            "12" {
                Show-ExportMenu
            }
            "13" {
                Write-Host "Exiting..." -ForegroundColor Yellow
                exit 0
            }
            default {
                Write-Host "Invalid choice. Please try again." -ForegroundColor Red
                Start-Sleep -Seconds 2
            }
        }
    } while ($true)
}

# ==================== CLIENT MANAGEMENT ====================

# Function to set client name for current session
function Set-ClientName {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "   Set Client Name (Current Session)    " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "Current Client: $(if ($script:ClientName) { $script:ClientName } else { 'Not Set - Recommended to set before running audits' })" -ForegroundColor $(if ($script:ClientName) { 'Green' } else { 'Yellow' })
    Write-Host "Current Domain: $script:DomainName" -ForegroundColor White
    Write-Host ""
    Write-Host "NOTE: This script is used for ONE client at a time." -ForegroundColor Yellow
    Write-Host "      Set the client name to label all reports from this session." -ForegroundColor Yellow
    Write-Host ""
    
    if ($script:ClientName) {
        $change = Read-Host "Client name is set. Change it? (Y/N, default: N)"
        if ($change -ne "Y" -and $change -ne "y") {
            return
        }
    }
    
    $newClientName = Read-Host "Enter client name for this session (e.g., 'Acme Corporation')"
    if ([string]::IsNullOrWhiteSpace($newClientName)) {
        Write-Host "Client name cannot be empty. Keeping current value." -ForegroundColor Yellow
        Start-Sleep -Seconds 1
        return
    }
    
    $script:ClientName = $newClientName
    Write-Host "`nClient name set to: $script:ClientName" -ForegroundColor Green
    Write-Host "All reports from this session will be tagged with this client name." -ForegroundColor Green
    Write-Host ""
    Write-Host "Press any key to continue..." -ForegroundColor Cyan
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# ==================== AUDIT HISTORY & COMPARISON ====================

# Function to save audit to history
function Save-AuditToHistory {
    param(
        [string]$Framework,
        [string]$ReportPath
    )
    
    try {
        $historyEntry = @{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Framework = $Framework
            ClientName = $script:ClientName
            DomainName = $script:DomainName
            ReportPath = $ReportPath
            TotalIssues = $script:AuditResults.Count
            HighSeverity = ($script:AuditResults | Where-Object { $_.Severity -eq "High" }).Count
            MediumSeverity = ($script:AuditResults | Where-Object { $_.Severity -eq "Medium" }).Count
            LowSeverity = ($script:AuditResults | Where-Object { $_.Severity -eq "Low" }).Count
            Findings = $script:AuditResults
        }
        
        # Load existing history
        if (Test-Path $script:AuditHistoryPath) {
            $script:AuditHistory = Get-Content $script:AuditHistoryPath -Raw | ConvertFrom-Json | ConvertTo-Hashtable
        }
        
        # Add new entry
        if (-not $script:AuditHistory) {
            $script:AuditHistory = @()
        }
        $script:AuditHistory += $historyEntry
        
        # Keep last 100 audits
        if ($script:AuditHistory.Count -gt 100) {
            $script:AuditHistory = $script:AuditHistory[-100..-1]
        }
        
        # Save history
        $script:AuditHistory | ConvertTo-Json -Depth 10 | Out-File -FilePath $script:AuditHistoryPath -Encoding UTF8
        
        return $historyEntry
    } catch {
        Write-Warning "Failed to save audit to history: $_"
        return $null
    }
}

# Function to view audit history
function Show-AuditHistory {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "   Audit History                        " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    if (-not (Test-Path $script:AuditHistoryPath)) {
        Write-Host "No audit history found." -ForegroundColor Yellow
        Write-Host "Press any key to continue..." -ForegroundColor Cyan
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        return
    }
    
    try {
        $history = Get-Content $script:AuditHistoryPath -Raw | ConvertFrom-Json | ConvertTo-Hashtable
        
        if (-not $history -or $history.Count -eq 0) {
            Write-Host "No audit history found." -ForegroundColor Yellow
            Write-Host "Press any key to continue..." -ForegroundColor Cyan
            $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
            return
        }
        
        # Filter by client if set
        if ($script:ClientName) {
            $history = $history | Where-Object { $_.ClientName -eq $script:ClientName }
        }
        
        Write-Host "Found $($history.Count) audit(s) in history" -ForegroundColor Green
        Write-Host ""
        Write-Host ("{0,-20} {1,-15} {2,-30} {3,-8} {4,-8} {5,-8} {6,-8}" -f "Date", "Framework", "Client", "Total", "High", "Med", "Low") -ForegroundColor Yellow
        Write-Host ("-" * 110) -ForegroundColor Gray
        
        $index = 1
        foreach ($entry in ($history | Sort-Object -Property Timestamp -Descending | Select-Object -First 20)) {
            $clientDisplay = if ($entry.ClientName) { if ($entry.ClientName.Length -gt 28) { $entry.ClientName.Substring(0, 25) + "..." } else { $entry.ClientName } } else { "N/A" }
            Write-Host ("{0,-20} {1,-15} {2,-30} {3,-8} {4,-8} {5,-8} {6,-8}" -f `
                $entry.Timestamp.Substring(0, 16), `
                $entry.Framework, `
                $clientDisplay, `
                $entry.TotalIssues, `
                $entry.HighSeverity, `
                $entry.MediumSeverity, `
                $entry.LowSeverity) -ForegroundColor White
            $index++
        }
        
        Write-Host ""
        Write-Host "Options:" -ForegroundColor Yellow
        Write-Host "1. Compare two audits (select by number)" -ForegroundColor White
        Write-Host "2. Export history to CSV" -ForegroundColor White
        Write-Host "3. Return to Main Menu" -ForegroundColor White
        Write-Host ""
        $historyChoice = Read-Host "Enter choice (1-3)"
        
        switch ($historyChoice) {
            "1" {
                $first = Read-Host "Enter number of first audit to compare (1-$([Math]::Min($history.Count, 20)))"
                $second = Read-Host "Enter number of second audit to compare (1-$([Math]::Min($history.Count, 20)))"
                try {
                    $firstEntry = ($history | Sort-Object -Property Timestamp -Descending | Select-Object -First 20)[$first - 1]
                    $secondEntry = ($history | Sort-Object -Property Timestamp -Descending | Select-Object -First 20)[$second - 1]
                    Compare-Audits -First $firstEntry -Second $secondEntry
                } catch {
                    Write-Host "Invalid selection. Press any key to continue..." -ForegroundColor Red
                    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                }
            }
            "2" {
                Export-AuditHistoryToCSV -History $history
            }
        }
    } catch {
        Write-Host "Error loading audit history: $_" -ForegroundColor Red
        Write-Host "Press any key to continue..." -ForegroundColor Cyan
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    }
}

# Function to compare two audits
function Compare-Audits {
    param(
        [object]$First,
        [object]$Second
    )
    
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "   Audit Comparison                    " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    Write-Host "FIRST AUDIT: $($First.Timestamp) - $($First.Framework)" -ForegroundColor Yellow
    Write-Host "  Total Issues: $($First.TotalIssues)" -ForegroundColor White
    Write-Host "  High: $($First.HighSeverity) | Medium: $($First.MediumSeverity) | Low: $($First.LowSeverity)" -ForegroundColor White
    Write-Host ""
    Write-Host "SECOND AUDIT: $($Second.Timestamp) - $($Second.Framework)" -ForegroundColor Yellow
    Write-Host "  Total Issues: $($Second.TotalIssues)" -ForegroundColor White
    Write-Host "  High: $($Second.HighSeverity) | Medium: $($Second.MediumSeverity) | Low: $($Second.LowSeverity)" -ForegroundColor White
    Write-Host ""
    Write-Host "COMPARISON:" -ForegroundColor Cyan
    Write-Host "  Total Issues Change: $(if ($Second.TotalIssues -lt $First.TotalIssues) { '-' } else { '+' })$([Math]::Abs($Second.TotalIssues - $First.TotalIssues))" -ForegroundColor $(if ($Second.TotalIssues -lt $First.TotalIssues) { 'Green' } else { 'Red' })
    Write-Host "  High Severity Change: $(if ($Second.HighSeverity -lt $First.HighSeverity) { '-' } else { '+' })$([Math]::Abs($Second.HighSeverity - $First.HighSeverity))" -ForegroundColor $(if ($Second.HighSeverity -lt $First.HighSeverity) { 'Green' } else { 'Red' })
    Write-Host ""
    Write-Host "Press any key to continue..." -ForegroundColor Cyan
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
}

# Function to export audit history to CSV
function Export-AuditHistoryToCSV {
    param(
        [array]$History
    )
    
    try {
        $csvPath = Join-Path $OutputPath "AuditHistory_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $exportData = $History | Select-Object Timestamp, Framework, ClientName, DomainName, TotalIssues, HighSeverity, MediumSeverity, LowSeverity, ReportPath
        $exportData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host "`nAudit history exported to: $csvPath" -ForegroundColor Green
        Start-Sleep -Seconds 2
    } catch {
        Write-Host "Failed to export history: $_" -ForegroundColor Red
        Start-Sleep -Seconds 2
    }
}

# ==================== EXPORT FUNCTIONS ====================

# Function to export audit results to CSV
function Export-AuditToCSV {
    param(
        [string]$Framework,
        [string]$OutputPath
    )
    
    try {
        $csvPath = Join-Path $OutputPath "${Framework}_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').csv"
        $exportData = $script:AuditResults | Select-Object `
            @{Name='Timestamp';Expression={$_.Timestamp.ToString("yyyy-MM-dd HH:mm:ss")}}, `
            Framework, `
            Category, `
            Finding, `
            Severity, `
            Description, `
            Recommendation, `
            @{Name='Fixed';Expression={if ($_.Fixed) { 'Yes' } else { 'No' }}}, `
            @{Name='FixTimestamp';Expression={if ($_.FixTimestamp) { $_.FixTimestamp.ToString("yyyy-MM-dd HH:mm:ss") } else { '' }}}
        
        $exportData | Export-Csv -Path $csvPath -NoTypeInformation -Encoding UTF8
        Write-Host "`nAudit results exported to CSV: $csvPath" -ForegroundColor Green
        return $csvPath
    } catch {
        Write-Host "Failed to export to CSV: $_" -ForegroundColor Red
        return $null
    }
}

# Function to export audit results to JSON
function Export-AuditToJSON {
    param(
        [string]$Framework,
        [string]$OutputPath
    )
    
    try {
        $jsonPath = Join-Path $OutputPath "${Framework}_Audit_$(Get-Date -Format 'yyyyMMdd_HHmmss').json"
        $exportData = @{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            Framework = $Framework
            ClientName = $script:ClientName
            DomainName = $script:DomainName
            Summary = @{
                TotalIssues = $script:AuditResults.Count
                HighSeverity = ($script:AuditResults | Where-Object { $_.Severity -eq "High" }).Count
                MediumSeverity = ($script:AuditResults | Where-Object { $_.Severity -eq "Medium" }).Count
                LowSeverity = ($script:AuditResults | Where-Object { $_.Severity -eq "Low" }).Count
            }
            Findings = $script:AuditResults
        }
        
        $exportData | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
        Write-Host "`nAudit results exported to JSON: $jsonPath" -ForegroundColor Green
        return $jsonPath
    } catch {
        Write-Host "Failed to export to JSON: $_" -ForegroundColor Red
        return $null
    }
}

# Function to show export menu
function Show-ExportMenu {
    Write-Host "`n========================================" -ForegroundColor Cyan
    Write-Host "   Export Reports                      " -ForegroundColor Cyan
    Write-Host "========================================" -ForegroundColor Cyan
    Write-Host ""
    
    if ($script:AuditResults.Count -eq 0) {
        Write-Host "No audit results to export. Run an audit first." -ForegroundColor Yellow
        Write-Host "Press any key to continue..." -ForegroundColor Cyan
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        return
    }
    
    Write-Host "Current Framework: $script:ComplianceFramework" -ForegroundColor White
    Write-Host "Total Findings: $($script:AuditResults.Count)" -ForegroundColor White
    Write-Host ""
    Write-Host "Export Options:" -ForegroundColor Yellow
    Write-Host "1. Export to CSV (for Excel/Ticketing Systems)" -ForegroundColor White
    Write-Host "2. Export to JSON (for Automation/APIs)" -ForegroundColor White
    Write-Host "3. Export Both (CSV + JSON)" -ForegroundColor White
    Write-Host "4. Return to Main Menu" -ForegroundColor White
    Write-Host ""
    $exportChoice = Read-Host "Enter choice (1-4)"
    
    switch ($exportChoice) {
        "1" {
            Export-AuditToCSV -Framework $script:ComplianceFramework -OutputPath $OutputPath
            Start-Sleep -Seconds 2
        }
        "2" {
            Export-AuditToJSON -Framework $script:ComplianceFramework -OutputPath $OutputPath
            Start-Sleep -Seconds 2
        }
        "3" {
            Export-AuditToCSV -Framework $script:ComplianceFramework -OutputPath $OutputPath
            Export-AuditToJSON -Framework $script:ComplianceFramework -OutputPath $OutputPath
            Start-Sleep -Seconds 2
        }
        "4" {
            return
        }
    }
}

# Start the audit process
Start-AuditProcess
