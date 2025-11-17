<#
.SYNOPSIS
    AWS Security Baseline Checker
.DESCRIPTION
    Scans AWS account for common S3 and IAM security misconfigurations
.AUTHOR
    Axel - Cloud Security Transition Project
.DATE
    November 16, 2025
.VERSION
    1.0 - Unified S3 and IAM Scanners
#>

# Import required modules
Import-Module AWS.Tools.Common
Import-Module AWS.Tools.S3
Import-Module AWS.Tools.IdentityManagement # <-- ADDED from IAM script

# Initialize results array (global scope)
$script:results = @()

#=======================================================================
# S3 SCANNER FUNCTION (Copied from v0.5)
#=======================================================================
function Get-S3SecurityFindings {
    Write-Host "=== Checking S3 Bucket Security ===" -ForegroundColor Cyan
    
    # Get all S3 buckets
    try {
        $buckets = Get-S3Bucket -ErrorAction Stop
    }
    catch {
        Write-Host "[ERROR] Could not list S3 buckets. Check permissions." -ForegroundColor Red
        Write-Host $_
        return
    }
    
    if ($buckets.Count -eq 0) {
        Write-Host "No S3 buckets found in this account." -ForegroundColor Yellow
        return
    }
    
    foreach ($bucket in $buckets) {
        Write-Host "Checking S3 Bucket: $($bucket.BucketName)" -ForegroundColor Yellow
        
        # Get bucket region
        try {
            $bucketLocation = Get-S3BucketLocation -BucketName $bucket.BucketName
            $bucketRegion = if ($bucketLocation.Value) { $bucketLocation.Value } else { "us-east-1" }
        }
        catch {
            $bucketRegion = "us-east-1"
        }
        
        # --- 1. GATHER ALL CHECK FLAGS ---
        
        # Check public access block
        try {
            $publicAccessBlock = Get-S3PublicAccessBlock -BucketName $bucket.BucketName -Region $bucketRegion
            $isPublic = -not ($publicAccessBlock.BlockPublicAcls -and 
                              $publicAccessBlock.BlockPublicPolicy -and 
                              $publicAccessBlock.IgnorePublicAcls -and 
                              $publicAccessBlock.RestrictPublicBuckets)
        }
        catch {
            $isPublic = $true
        }
        
        # Check encryption
        try {
            $encryption = Get-S3BucketEncryption -BucketName $bucket.BucketName -Region $bucketRegion
            $isEncrypted = $true
        }
        catch {
            $isEncrypted = $false
        }
        
        # Check versioning & MFA Delete
        $isVersioned = $false
        $mfaDeleteEnabled = $false 
        try {
            $versioning = Get-S3BucketVersioning -BucketName $bucket.BucketName -Region $bucketRegion
            $isVersioned = $versioning.Status -eq "Enabled"
            
            if ($isVersioned) {
                $mfaDeleteEnabled = $versioning.MFADelete -eq "Enabled"
            }
        }
        catch {
            Write-Host "  Warning: Could not check versioning for $($bucket.BucketName)" -ForegroundColor DarkYellow
            $isVersioned = $false
        }
        
        # Check server access logging
        try {
            $logging = Get-S3BucketLogging -BucketName $bucket.BucketName -Region $bucketRegion
            $hasLogging = $null -ne $logging.LoggingConfig.TargetBucketName
        }
        catch {
            $hasLogging = $false
        }
        
        # Check SSL Enforcement
        $hasSSLEnforcement = $false
        try {
            $policy = Get-S3BucketPolicy -BucketName $bucket.BucketName -Region $bucketRegion
            if (-not [string]::IsNullOrEmpty($policy.Policy)) {
                $policyJson = $policy.Policy | ConvertFrom-Json
                $statements = @($policyJson.Statement)
                $requiresSSL = $statements | Where-Object {
                    $_.Effect -eq "Deny" -and
                    $_.Condition.Bool.'aws:SecureTransport' -eq "false"
                }
                if ($null -ne $requiresSSL) {
                    $hasSSLEnforcement = $true
                }
            }
        }
        catch {
            # This is your SSL detection bug. We'll leave the debug message.
            Write-Host "  DEBUG: SSL Policy check failed with: $_" -ForegroundColor Magenta
            $hasSSLEnforcement = $false
        }

        
        # --- 2. DETERMINE ALL ISSUES AND SEVERITY ---
        $issues = @()

        if ($isPublic) { 
            $issues += @{Severity="HIGH"; Issue="Public access not blocked"} 
        }
        if ($isVersioned -and (-not $mfaDeleteEnabled)) { 
            $issues += @{Severity="HIGH"; Issue="MFA Delete disabled on versioned bucket"} 
        }
        if (-not $isEncrypted) { 
            $issues += @{Severity="MEDIUM"; Issue="No default encryption"} 
        }
        if (-not $hasSSLEnforcement) { 
            $issues += @{Severity="MEDIUM"; Issue="No SSL enforcement policy"} 
        }
        if (-not $isVersioned) { 
            $issues += @{Severity="LOW"; Issue="Versioning disabled"} 
        }
        if (-not $hasLogging) { 
            $issues += @{Severity="LOW"; Issue="No access logging"} 
        }

        # Determine overall severity
        $severity = if ($issues | Where-Object {$_.Severity -eq "HIGH"}) { "HIGH" }
                    elseif ($issues | Where-Object {$_.Severity -eq "MEDIUM"}) { "MEDIUM" }
                    elseif ($issues | Where-Object {$_.Severity -eq "LOW"}) { "LOW" }
                    else { "INFO" }

        # Combine all recommendations
        $recommendation = if ($issues.Count -gt 0) {
            ($issues | ForEach-Object { $_.Issue }) -join "; "
        } else {
            "No issues found"
        }
        
        # --- 3. CREATE FINDING OBJECT ---
        $finding = [PSCustomObject]@{
            ResourceType = "S3 Bucket"
            ResourceName = $bucket.BucketName
            Region = $bucketRegion
            Severity = $severity
            Recommendation = $recommendation
            CheckedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            # --- Individual checks kept for detail in CSV ---
            PublicAccess = if ($isPublic) { "YES" } else { "NO" }
            Encrypted = if ($isEncrypted) { "YES" } else { "NO" }
            Versioned = if ($isVersioned) { "YES" } else { "NO" }
            MFADelete = if ($mfaDeleteEnabled) { "YES" } else { "NO" }
            Logging = if ($hasLogging) { "YES" } else { "NO" }
            SSLEnforced = if ($hasSSLEnforcement) { "YES" } else { "NO" }
        }
        
        # Add to the *global* results array
        $script:results += $finding
    }
}


#=======================================================================
# IAM SCANNER FUNCTION (Refactored from v2.0)
#=======================================================================
function Get-IAMSecurityFindings {
    <#
    .SYNOPSIS
    Detects IAM users without MFA enabled and adds them to the global results.
    #>
    
    Write-Host "`n=== Checking IAM User Security ===" -ForegroundColor Cyan
    
    try {
        # Get all IAM users
        $users = Get-IAMUser -ErrorAction Stop
        
        if ($users.Count -eq 0) {
            Write-Host "No IAM users found in account." -ForegroundColor Yellow
            return
        }
        
        Write-Host "Checking $($users.Count) IAM users for MFA..." -ForegroundColor Yellow
                
        foreach ($user in $users) {
            $currentUserName = $user.UserName
            
            # Get this user's MFA devices
            $mfaDevices = Get-IAMMFADevice -UserName $currentUserName
            
            # If the user has no MFA devices, create a finding
            if (-not $mfaDevices) {
                Write-Host "  [!] Finding: $currentUserName - NO MFA ENABLED" -ForegroundColor Red
                
                # Create a finding object that matches the S3 object structure
                $finding = [PSCustomObject]@{
                    ResourceType = "IAM User"
                    ResourceName = $currentUserName
                    Region = "Global" # IAM is a global service
                    Severity = "HIGH"
                    Recommendation = "User does not have MFA enabled"
                    CheckedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    # --- Individual checks (for CSV consistency) ---
                    PublicAccess = "N/A"
                    Encrypted = "N/A"
                    Versioned = "N/A"
                    MFADelete = "N/A"
                    Logging = "N/A"
                    SSLEnforced = "N/A"
                }
                
                # Add to the *global* results array
                $script:results += $finding
            }
        }
        
    } catch {
        Write-Host "[ERROR] IAM Scanner failed: $_" -ForegroundColor Red
        Write-Host "Please check your AWS credentials and permissions (e.g., 'iam:ListUsers', 'iam:ListMFADevices')" -ForegroundColor Yellow
    }
}

#=======================================================================
# MAIN EXECUTION
#=======================================================================
Write-Host "`n╔════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║   AWS Security Baseline Checker v1.0      ║" -ForegroundColor Green
Write-Host "║   Author: Axel                            ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════╝`n" -ForegroundColor Green

# Create reports directory if it doesn't exist
$reportDir = "reports"
if (-not (Test-Path -Path $reportDir)) {
    New-Item -ItemType Directory -Path $reportDir
    Write-Host "Created '.\reports' directory for output." -ForegroundColor Yellow
}

# --- Run ALL scanners ---
Get-S3SecurityFindings
Get-IAMSecurityFindings # <-- ADDED

# --- Display unified results ---
if ($script:results.Count -gt 0) {
    Write-Host "`n=== ALL FINDINGS SUMMARY ===" -ForegroundColor Green
    
    # This Format-Table will now show S3 AND IAM findings
    $script:results | Format-Table -Property ResourceType, ResourceName, Region, Severity, Recommendation -AutoSize -Wrap
    
    # Count by severity (now includes all resource types)
    $highCount = ($script:results | Where-Object { $_.Severity -eq "HIGH" }).Count
    $mediumCount = ($script:results | Where-Object { $_.Severity -eq "MEDIUM" }).Count
    $lowCount = ($script:results | Where-Object { $_.Severity -eq "LOW" }).Count
    
    Write-Host "`n=== SEVERITY BREAKDOWN ===" -ForegroundColor Cyan
    if ($highCount -gt 0) { Write-Host "HIGH: $highCount" -ForegroundColor Red }
    if ($mediumCount -gt 0) { Write-Host "MEDIUM: $mediumCount" -ForegroundColor Yellow }
    if ($lowCount -gt 0) { Write-Host "LOW: $lowCount" -ForegroundColor Gray }
    
    # Export to CSV (now includes all resource types)
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $reportPath = "reports\aws-security-findings-$timestamp.csv"
    $script:results | Export-Csv -Path $reportPath -NoTypeInformation
    
    Write-Host "`n✓ Unified report saved to: $reportPath" -ForegroundColor Green
}
else {
    Write-Host "`nNo security issues found!" -ForegroundColor Green
}

Write-Host "`nScan complete!`n" -ForegroundColor Green