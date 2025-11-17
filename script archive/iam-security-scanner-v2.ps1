#!/usr/bin/env pwsh
# AWS IAM Security Scanner
# Purpose: Detect IAM users without MFA enabled
# Created: November 8, 2025
#
# -------------------------------------------------------------------
# v2.0 - Refactored by Gemini
# REASON FOR CHANGE: Converted script from using external 'aws cli'
# executable to using the native AWS.Tools.IdentityManagement module.
# This makes the script faster, more reliable, and allows us to
# work with real objects instead of parsing JSON strings.
# -------------------------------------------------------------------

# COMMENT: Import the specific PowerShell module for IAM.
# This is better practice than importing everything.
# You must run 'Install-Module AWS.Tools.IdentityManagement' one time first.
Import-Module AWS.Tools.IdentityManagement

function Test-IAMUserMFA {
    <#
    .SYNOPSIS
    Detects IAM users without MFA enabled
    
    .DESCRIPTION
    Scans all IAM users in the AWS account and identifies
    users without Multi-Factor Authentication configured.
    #>
    
    Write-Host "`n[*] AWS IAM Security Scanner v2.0 (PowerShell Native)" -ForegroundColor Green
    Write-Host "===================================================`n" -ForegroundColor Green
    
    Write-Host "[*] Checking for users without MFA..." -ForegroundColor Cyan
    
    try {
        # COMMENT: This is the old 'aws cli' command. We are replacing it.
        # $usersJson = aws iam list-users --query 'Users[*].UserName' --output json
        # $users = $usersJson | ConvertFrom-Json
        
        # COMMENT: This is the NEW PowerShell equivalent.
        # It returns a collection of full 'User' objects, not just text.
        # We also add '-ErrorAction Stop' to jump to the 'catch' block on an error.
        $users = Get-IAMUser -ErrorAction Stop
        
        if ($users.Count -eq 0) {
            Write-Host "[*] No IAM users found in account" -ForegroundColor Yellow
            return
        }
        
        Write-Host "[*] Found $($users.Count) IAM users to scan`n" -ForegroundColor Yellow
        
        # COMMENT: This is a best practice. Instead of just printing to the
        # console, we will create a list of "finding" objects.
        $findings = @()
        
        foreach ($user in $users) {
            
            # COMMENT: We must now access the .UserName property of the $user object.
            $currentUserName = $user.UserName
            
            # COMMENT: This is the old 'aws cli' command.
            # $mfaJson = aws iam list-mfa-devices --user-name $user --query 'MFADevices' --output json
            # $mfaDevices = $mfaJson | ConvertFrom-Json
            
            # COMMENT: This is the NEW PowerShell equivalent.
            # It returns a list of 'MFADevice' objects, or $null if none are found.
            # It does NOT error if no devices are found, which is perfect for our check.
            $mfaDevices = Get-IAMMFADevice -UserName $currentUserName
            
            # COMMENT: The logic for checking if MFA is enabled is now simpler.
            # We just check if the $mfaDevices variable actually contains anything.
            if ($mfaDevices) {
                # This means $mfaDevices is not $null and has one or more items.
                Write-Host "  [✓] $currentUserName - MFA enabled" -ForegroundColor Green
                $mfaEnabled = $true
            } else {
                # This means $mfaDevices was $null or an empty list.
                Write-Host "  [!] $currentUserName - NO MFA ENABLED" -ForegroundColor Red
                $mfaEnabled = $false
            }
            
            # COMMENT: Add our result to the structured findings array.
            # This is much more powerful than just writing to the screen.
            $findings += [PSCustomObject]@{
                UserName = $currentUserName
                MFAEnabled = $mfaEnabled
                PasswordLastUsed = $user.PasswordLastUsed
                CreateDate = $user.CreateDate
            }
        }
        
        # COMMENT: Now we create the summary based on our findings array,
        # not just a simple counter variable ($usersWithoutMFA).
        $usersWithoutMFA = ($findings | Where-Object { $_.MFAEnabled -eq $false }).Count
        
        # Summary
        Write-Host "`n================================" -ForegroundColor Green
        Write-Host "SCAN SUMMARY" -ForegroundColor Green
        Write-Host "================================" -ForegroundColor Green
        Write-Host "Total users scanned: $($users.Count)" -ForegroundColor Yellow
        Write-Host "Users without MFA: $usersWithoutMFA" -ForegroundColor $(if ($usersWithoutMFA -gt 0) { "Red" } else { "Green" })
        Write-Host "================================`n" -ForegroundColor Green
        
        if ($usersWithoutMFA -gt 0) {
            Write-Host "[!] ACTION REQUIRED: Enable MFA for users listed above" -ForegroundColor Red
            
            # COMMENT: Because we have the $findings array, we can do
            # powerful things like show a clean list of non-compliant users.
            Write-Host "`nUsers without MFA:"
            $findings | Where-Object { $_.MFAEnabled -eq $false } | Format-Table UserName, PasswordLastUsed
            
        } else {
            Write-Host "[✓] All users have MFA enabled!" -ForegroundColor Green
        }
        
    } catch {
        # COMMENT: This will catch errors from Get-IAMUser if auth fails.
        Write-Host "[ERROR] Scanner failed: $_" -ForegroundColor Red
        Write-Host "Please check your AWS credentials and permissions (e.g., 'iam:ListUsers', 'iam:ListMFADevices')" -ForegroundColor Yellow
    }
}

# Run the scanner.
Test-IAMUserMFA