#!/usr/bin/env pwsh
# AWS IAM Security Scanner
# Purpose: Detect IAM users without MFA enabled
# Created: November 8, 2025

function Test-IAMUserMFA {
    <#
    .SYNOPSIS
    Detects IAM users without MFA enabled
    
    .DESCRIPTION
    Scans all IAM users in the AWS account and identifies
    users without Multi-Factor Authentication configured.
    #>
    
    Write-Host "`n[*] AWS IAM Security Scanner v0.1" -ForegroundColor Green
    Write-Host "================================`n" -ForegroundColor Green
    
    Write-Host "[*] Checking for users without MFA..." -ForegroundColor Cyan
    
    try {
        # Get all IAM users
        $usersJson = aws iam list-users --query 'Users[*].UserName' --output json
        
        if ($LASTEXITCODE -ne 0) {
            Write-Host "[ERROR] Failed to list IAM users. Check AWS CLI configuration." -ForegroundColor Red
            exit 1
        }
        
        $users = $usersJson | ConvertFrom-Json
        
        if ($users.Count -eq 0) {
            Write-Host "[*] No IAM users found in account" -ForegroundColor Yellow
            return
        }
        
        Write-Host "[*] Found $($users.Count) IAM users to scan`n" -ForegroundColor Yellow
        
        $usersWithoutMFA = 0
        
        foreach ($user in $users) {
            # Check MFA devices for each user
            $mfaJson = aws iam list-mfa-devices --user-name $user --query 'MFADevices' --output json
            $mfaDevices = $mfaJson | ConvertFrom-Json
            
            if ($mfaDevices.Count -eq 0) {
                Write-Host "  [!] $user - NO MFA ENABLED" -ForegroundColor Red
                $usersWithoutMFA++
            } else {
                Write-Host "  [✓] $user - MFA enabled" -ForegroundColor Green
            }
        }
        
        # Summary
        Write-Host "`n================================" -ForegroundColor Green
        Write-Host "SCAN SUMMARY" -ForegroundColor Green
        Write-Host "================================" -ForegroundColor Green
        Write-Host "Total users scanned: $($users.Count)" -ForegroundColor Yellow
        Write-Host "Users without MFA: $usersWithoutMFA" -ForegroundColor $(if ($usersWithoutMFA -gt 0) { "Red" } else { "Green" })
        Write-Host "================================`n" -ForegroundColor Green
        
        if ($usersWithoutMFA -gt 0) {
            Write-Host "[!] ACTION REQUIRED: Enable MFA for users listed above" -ForegroundColor Red
        } else {
            Write-Host "[✓] All users have MFA enabled!" -ForegroundColor Green
        }
        
    } catch {
        Write-Host "[ERROR] Scanner failed: $_" -ForegroundColor Red
        exit 1
    }
}

# Run the scanner.
Test-IAMUserMFA