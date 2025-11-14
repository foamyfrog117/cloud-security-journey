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
    0.3 - Added S3 MFA Delete check (per our discussion)
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
        # COMMENT: This is the new variable for the check you asked about.
        $mfaDeleteEnabled = $false 
        try {
            $versioning = Get-S3BucketVersioning -BucketName $bucket.BucketName -Region $bucketRegion
            $isVersioned = $versioning.Status -eq "Enabled"
            
            # COMMENT: Here is the check for MFA Delete.
            # We only check it IF versioning is enabled, otherwise the property is irrelevant.
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
        
        # Determine severity and recommendation
        # COMMENT: Updated this logic to include the new MFA Delete check.
        # This is the risk we discussed: Versioning is on, but MFA Delete is off.
        if ($isPublic) {
            $severity = "HIGH"
            $recommendation = "Enable public access block settings"
        } 
        elseif ($isVersioned -and (-not $mfaDeleteEnabled)) {
            $severity = "HIGH" # This is a high finding!
            $recommendation = "Enable MFA Delete on this versioned bucket to protect from object deletion"
        }
        elseif (-not $isEncrypted) { 
            $severity = "MEDIUM"
            $recommendation = "Enable default encryption (AES-256 or KMS)"
        } 
        elseif (-not $isVersioned) { 
            $severity = "LOW"
            $recommendation = "Enable versioning for data protection"
        }
        elseif (-not $hasLogging) {
            $severity = "LOW" # Changed from INFO to LOW
            $recommendation = "Enable server access logging for audit trail"
        }
        else { 
            $severity = "INFO"
            $recommendation = "No critical issues found"
        }
        
        # Create finding object
        # COMMENT: Added '.MFADelete' to the finding object for reporting.
        $finding = [PSCustomObject]@{
            ResourceType = "S3 Bucket"
            ResourceName = $bucket.BucketName
            Region = $bucketRegion
            PublicAccess = if ($isPublic) { "YES" } else { "NO" }
            Encrypted = if ($isEncrypted) { "YES" } else { "NO" }
            Versioned = if ($isVersioned) { "YES" } else { "NO" }
            MFADelete = if ($mfaDeleteEnabled) { "YES" } else { "NO" }
            Logging = if ($hasLogging) { "YES" } else { "NO" }
            Severity = $severity
            Recommendation = $recommendation
            CheckedDate = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
        }
        
        $script:results += $finding
    }
}

# Main execution
Write-Host "`n╔════════════════════════════════════════════╗" -ForegroundColor Green
Write-Host "║   AWS Security Baseline Checker v0.3      ║" -ForegroundColor Green
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
    $script:results | Format-Table -AutoSize
    
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