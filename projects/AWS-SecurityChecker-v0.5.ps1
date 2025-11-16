<#
.SYNOPSIS
    AWS Security Baseline Checker
.DESCRIPTION
    Scans AWS account for common security misconfigurations
.AUTHOR
    Axel - Cloud Security Transition Project
.DATE
    November 2025
.VERSION
    0.5 - Refactored logic to report ALL findings per bucket
#>

# Import required modules
Import-Module AWS.Tools.Common
Import-Module AWS.Tools.S3

# Initialize results array
$script:results = @()

function Get-S3SecurityFindings {
    Write-Host "=== Checking S3 Bucket Security ===" -ForegroundColor Cyan
    
    # Get all S3 buckets
    $buckets = Get-S3Bucket
    
    if ($buckets.Count -eq 0) {
        Write-Host "No S3 buckets found in this account." -ForegroundColor Yellow
        return
    }
    
    foreach ($bucket in $buckets) {
        Write-Host "Checking bucket: $($bucket.BucketName)" -ForegroundColor Yellow
        
        # Get bucket region first to handle regional buckets properly
        try {
            $bucketLocation = Get-S3BucketLocation -BucketName $bucket.BucketName
            $bucketRegion = if ($bucketLocation.Value) { $bucketLocation.Value } else { "us-east-1" }
        }
        catch {
            # Default to us-east-1 if location lookup fails (common for new buckets)
            $bucketRegion = "us-east-1"
        }
        
        # --- 1. GATHER ALL CHECK FLAGS ---
        
        # Check public access block configuration
        try {
            $publicAccessBlock = Get-S3PublicAccessBlock -BucketName $bucket.BucketName -Region $bucketRegion
            $isPublic = -not ($publicAccessBlock.BlockPublicAcls -and 
                              $publicAccessBlock.BlockPublicPolicy -and 
                              $publicAccessBlock.IgnorePublicAcls -and 
                              $publicAccessBlock.RestrictPublicBuckets)
        }
        catch {
            $isPublic = $true  # If no block exists, assume potentially public
        }
        
        # Check encryption
        try {
            $encryption = Get-S3BucketEncryption -BucketName $bucket.BucketName -Region $bucketRegion
            $isEncrypted = $true
        }
        catch {
            $isEncrypted = $false # No encryption rules are configured
        }
        
        # Check versioning (with proper error handling)
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
            Write-Host "  Warning: Could not check logging for $($bucket.BucketName)" -ForegroundColor DarkYellow
            $hasLogging = $false
        }
        
        # Check SSL Enforcement (via bucket policy)
        $hasSSLEnforcement = $false # Default to false
        try {
            # Get the policy text
            $policy = Get-S3BucketPolicy -BucketName $bucket.BucketName -Region $bucketRegion
            
            # Check if the returned policy string is not null or empty
            if (-not [string]::IsNullOrEmpty($policy.Policy)) {
                # Convert the JSON string into a PowerShell object
                $policyJson = $policy.Policy | ConvertFrom-Json
                
                # Force the 'Statement' property to be an array
                $statements = @($policyJson.Statement)
            
                # Search for a statement that DENIES access if 'aws:SecureTransport' is false.
                $requiresSSL = $statements | Where-Object {
                    $_.Effect -eq "Deny" -and
                    $_.Condition.Bool.'aws:SecureTransport' -eq "false"
                }
                
                # If we found one or more such statements, set our flag to true.
                if ($null -ne $requiresSSL) {
                    $hasSSLEnforcement = $true
                }
            }
            # If $policy.Policy was null, $hasSSLEnforcement remains $false (correct)
        }
        catch {
            # This catch block is hit if Get-S3BucketPolicy fails (e.g., no policy exists)
            $hasSSLEnforcement = $false  # No policy = no enforcement
        }

        
        # --- 2. NEW LOGIC: DETERMINE ALL ISSUES AND SEVERITY ---
        # Instead of elseif cascade, build an issues list
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
            # This check is separate from the MFA Delete check
            $issues += @{Severity="LOW"; Issue="Versioning disabled"} 
        }
        if (-not $hasLogging) { 
            $issues += @{Severity="LOW"; Issue="No access logging"} 
        }

        # Determine overall severity (worst one)
        $severity = if ($issues | Where-Object {$_.Severity -eq "HIGH"}) { "HIGH" }
                    elseif ($issues | Where-Object {$_.Severity -eq "MEDIUM"}) { "MEDIUM" }
                    elseif ($issues | Where-Object {$_.Severity -eq "LOW"}) { "LOW" }
                    else { "INFO" }

        # Combine all recommendations
        $recommendation = if ($issues.Count -gt 0) {
            ($issues | ForEach-Object { $_.Issue }) -join "; "
        } else {
            "No issues found" # Changed from "No critical issues found"
        }
        # --- END OF NEW LOGIC ---

        
        # --- 3. CREATE FINDING OBJECT ---
        $finding = [PSCustomObject]@{
            ResourceType = "S3 Bucket"
            ResourceName = $bucket.BucketName
            Region = $bucketRegion
            # Individual check results
            PublicAccess = if ($isPublic) { "YES" } else { "NO" }
            Encrypted = if ($isEncrypted) { "YES" } else { "NO" }
            Versioned = if ($isVersioned) { "YES" } else { "NO" }
            MFADelete = if ($mfaDeleteEnabled) { "YES" } else { "NO" }
            Logging = if ($hasLogging) { "YES" } else { "NO" }
            SSLEnforced = if ($hasSSLEnforcement) { "YES" } else { "NO" }
            # Summary fields
            Severity = $severity
            Recommendation = $recommendation # This is now the combined list
            CheckedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        
        $script:results += $finding
    }
}

# Main execution
Write-Host "`n╔════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║   AWS Security Baseline Checker v0.5      ║" -ForegroundColor Green
Write-Host "║   Author: Axel                            ║" -ForegroundColor Green
Write-Host "╚════════════════════════════════════════════╝`n" -ForegroundColor Green

# Create reports directory if it doesn't exist
$reportDir = "reports"
if (-not (Test-Path -Path $reportDir)) {
    New-Item -ItemType Directory -Path $reportDir
    Write-Host "Created '.\reports' directory for output." -ForegroundColor Yellow
}

# Run S3 checks
Get-S3SecurityFindings

# Display results
if ($script:results.Count -gt 0) {
    Write-Host "`n=== FINDINGS SUMMARY ===" -ForegroundColor Green
    
    # COMMENT: Added -Wrap to Format-Table to handle the new
    # multi-issue Recommendation field without breaking the console.
    $script:results | Format-Table -AutoSize -Wrap
    
    # Count by severity
    $criticalCount = ($script:results | Where-Object { $_.Severity -eq "CRITICAL" }).Count
    $highCount = ($script:results | Where-Object { $_.Severity -eq "HIGH" }).Count
    $mediumCount = ($script:results | Where-Object { $_.Severity -eq "MEDIUM" }).Count
    $lowCount = ($script:results | Where-Object { $_.Severity -eq "LOW" }).Count
    
    Write-Host "`n=== SEVERITY BREAKDOWN ===" -ForegroundColor Cyan
    if ($criticalCount -gt 0) { Write-Host "CRITICAL: $criticalCount" -ForegroundColor Red }
    if ($highCount -gt 0) { Write-Host "HIGH: $highCount" -ForegroundColor Red }
    if ($mediumCount -gt 0) { Write-Host "MEDIUM: $mediumCount" -ForegroundColor Yellow }
    if ($lowCount -gt 0) { Write-Host "LOW: $lowCount" -ForegroundColor Gray }
    
    # Export to CSV
    $timestamp = Get-Date -Format "yyyyMMdd-HHmmss"
    $reportPath = "reports\aws-security-findings-$timestamp.csv"
    $script:results | Export-Csv -Path $reportPath -NoTypeInformation
    
    Write-Host "`n✓ Report saved to: $reportPath" -ForegroundColor Green
}
else {
    Write-Host "`nNo findings to report!" -ForegroundColor Yellow
}

Write-Host "`nScan complete!`n" -ForegroundColor Green