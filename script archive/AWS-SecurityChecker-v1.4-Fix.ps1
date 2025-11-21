<#
.SYNOPSIS
    AWS Security Baseline Checker
.DESCRIPTION
    Scans AWS account for common S3 and IAM security misconfigurations
.AUTHOR
    Axel - Cloud Security Transition Project
.DATE
    November 18, 2025
.VERSION
    1.4 - Improved AWS CLI Error Handling
#>

# Import required modules
Import-Module AWS.Tools.Common
Import-Module AWS.Tools.S3
Import-Module AWS.Tools.IdentityManagement

# Initialize results array (global scope)
$script:results = @()

#=======================================================================
# S3 SCANNER FUNCTION
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
            # --- START: AWS CLI LOGIC ---
            # We use the CLI because Get-S3BucketPolicy is unreliable.
            # 2>&1 captures errors stream, ensuring we don't crash if the command fails.
            $cliOutput = aws s3api get-bucket-policy --bucket $bucket.BucketName --region $bucketRegion --query Policy --output text 2>&1
            
            # Check if the command succeeded ($LASTEXITCODE is 0) AND output is a string
            if ($LASTEXITCODE -eq 0 -and $cliOutput -is [string] -and $cliOutput.StartsWith("{")) {
                
                $policyJson = $cliOutput | ConvertFrom-Json
                $statements = @($policyJson.Statement)

                $requiresSSL = $statements | Where-Object {
                    $_.Effect -eq "Deny" -and
                    $_.Condition.Bool.'aws:SecureTransport' -eq "false"
                }
                if ($null -ne $requiresSSL) {
                    $hasSSLEnforcement = $true
                }
            } elseif ($cliOutput -is [System.Management.Automation.ErrorRecord]) {
                 # Use the exception message if available, otherwise convert to string
                 $errorMsg = if ($cliOutput.Exception.Message) { $cliOutput.Exception.Message } else { $cliOutput.ToString() }
                 # Only print debug if it's NOT the expected "NoSuchBucketPolicy" error
                 if ($errorMsg -notmatch "NoSuchBucketPolicy") {
                    Write-Host "  DEBUG: CLI command failed: $errorMsg" -ForegroundColor DarkGray
                 }
            }
            # --- END: AWS CLI LOGIC ---
        }
        catch {
            Write-Host "  DEBUG (PS): SSL Policy check logic error: $_" -ForegroundColor Magenta
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
        
        $script:results += $finding
    }
}


#=======================================================================
# IAM SCANNER FUNCTION
#=======================================================================
function Get-IAMSecurityFindings {
    Write-Host "`n=== Checking IAM User Security ===" -ForegroundColor Cyan
    
    try {
        $users = Get-IAMUser -ErrorAction Stop
        
        if ($users.Count -eq 0) {
            Write-Host "No IAM users found in this account." -ForegroundColor Yellow
            return
        }
        
        Write-Host "Checking $($users.Count) IAM users for MFA..." -ForegroundColor Yellow
                
        foreach ($user in $users) {
            $currentUserName = $user.UserName
            $mfaDevices = Get-IAMMFADevice -UserName $currentUserName
            
            if (-not $mfaDevices) {
                Write-Host "  [!] Finding: $currentUserName - NO MFA ENABLED" -ForegroundColor Red
                
                $finding = [PSCustomObject]@{
                    ResourceType = "IAM User"
                    ResourceName = $currentUserName
                    Region = "Global"
                    Severity = "HIGH"
                    Recommendation = "User does not have MFA enabled"
                    CheckedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
                    # --- Individual checks ---
                    PublicAccess = "N/A"
                    Encrypted = "N/A"
                    Versioned = "N/A"
                    MFADelete = "N/A"
                    Logging = "N/A"
                    SSLEnforced = "N/A"
                }
                
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
Write-Host "║   AWS Security Baseline Checker v1.4      ║" -ForegroundColor Green
Write-Host "║   (CLI Error Handling Fix)                ║" -ForegroundColor Green
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
Get-IAMSecurityFindings

# --- Display unified results ---
if ($script:results.Count -gt 0) {
    Write-Host "`n=== ALL FINDINGS SUMMARY ===" -ForegroundColor Green
    
    $script:results | Format-Table -Property ResourceType, ResourceName, Region, Severity, Recommendation -AutoSize -Wrap
    
    # Count by severity
    $highCount = ($script:results | Where-Object { $_.Severity -eq "HIGH" }).Count
    $mediumCount = ($script:results | Where-Object { $_.Severity -eq "MEDIUM" }).Count
    $lowCount = ($script:results | Where-Object { $_.Severity -eq "LOW" }).Count
    
    Write-Host "`n=== SEVERITY BREAKDOWN ===" -ForegroundColor Cyan
    if ($highCount -gt 0) { Write-Host "HIGH: $highCount" -ForegroundColor Red }
    if ($mediumCount -gt 0) { Write-Host "MEDIUM: $mediumCount" -ForegroundColor Yellow }
    if ($lowCount -gt 0) { Write-Host "LOW: $lowCount" -ForegroundColor Gray }
    
    # Export to CSV
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $reportPath = "reports\aws-security-findings-$timestamp.csv"
    $script:results | Export-Csv -Path $reportPath -NoTypeInformation
    
    Write-Host "`n✓ Unified report saved to: $reportPath" -ForegroundColor Green
}
else {
    Write-Host "`nNo security issues found!" -ForegroundColor Green
}

Write-Host "`nScan complete!`n" -ForegroundColor Green