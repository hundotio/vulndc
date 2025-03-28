# Write the flags:
    Set-Content -Path "C:\GUEST\flag.txt" -Value "DSU{0p3n_t0_3v3ry0n3}"                                # Guest share flag
    Set-Content -Path "C:\Users\Menu\Desktop\flag.txt" -Value "DSU{wh3n_l1f3_g1v3s_y0u_l3m0ns}"         # Menu user flag
    Set-Content -Path "C:\Users\Waiter\Desktop\flag.txt" -Value "DSU{4n_4bs0lut3_cl4ss1c}"              # Waiter user flag
    Set-Content -Path "C:\Users\Cook\Desktop\flag.txt" -Value "DSU{j3ss3_w3_n33d_t0_c00k}"              # Cook user flag
    Set-Content -Path "C:\Users\Manager\Desktop\flag.txt" -Value "DSU{k3rb3r04st_g0_brrrr}"             # Manager user flag
    Set-Content -Path "C:\Users\Administrator\Desktop\flag.txt" -Value "DSU{d3l3g4t10n_f0r_th3_w1n}"    # Admin user flag

# Add Users:
    Set-ADUser -Identity "Guest" -Enabled $true
    New-ADUser -Username "Menu" -Password "pink_lemonade"
    New-ADUser -Username "Waiter" -Password "ilike2eatfood"
    New-ADUser -Username "Cook" -Password "cookies4life"
    New-ADUser -Username "Manager" -Password "iamthebossofthehouse"
    New-ADUser -Username "BigBoss" -Password "tooPowerful"
    New-ADUser -Username "Administrator" -Password "superLongAdminPassword123!"

# Disable User expiration
    Get-LocalUser | ForEach-Object { Set-LocalUser -Name $_.Name -PasswordNeverExpires $true }

# Challenge 1 - Configure Guest SMB
    New-SmbShare -Name "GUEST" -Path "C:\GUEST" -FullAccess "Everyone"

# Challenge 2 - RPC LDAP
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RestrictAnonymous -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RestrictAnonymousSAM -Value 0
    net localgroup "Pre-Windows 2000 Compatible Access" "ANONYMOUS LOGON" /add

    Set-ADUser -Identity "Menu" -Description "Password: pink_lemonade"

# Challenge 3 - LLMNR
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" -Name "EnableMulticast" -Value 1

    $task = '/c powershell New-PSDrive -Name "Public" -PSProvider "FileSystem" -Root "\\whosorderisit"'
    $repeat = (New-TimeSpan -Minutes 5)
    $taskName = "responder-bot"
    $user = "Waiter"
    $password = "ilike2eatfood"

    $action = New-ScheduledTaskAction -Execute "cmd.exe" -Argument "$task"
    $trigger = New-ScheduledTaskTrigger -Once -At (Get-Date) -RepetitionInterval $repeat
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable -RunOnlyIfNetworkAvailable -DontStopOnIdleEnd

    $taskExists = Get-ScheduledTask | Where-Object {$_.TaskName -like $taskName }
    if($taskExists) {
        Unregister-ScheduledTask -TaskName $taskName -Confirm:$false
    }

    Register-ScheduledTask -TaskName $taskName -Action $action -Trigger $trigger -User $user -Password $password -Settings $settings

# Challenge 4 - Preauthentication
    Get-ADUser -Identity "Cook" | Set-ADAccountControl -DoesNotRequirePreAuth:$true

# Challenge 5 - User SPNs
    Set-ADUser -Identity "Manager" -ServicePrincipalNames @{Add='CIFS/DC01.secure.local'}

# Challenge 6 - Constrained Delegation
    # Set-ADUser -Identity "Manager" -ServicePrincipalNames @{Add='CIFS/DC01.secure.local'}
    Get-ADUser -Identity "Manager" | Set-ADAccountControl -TrustedToAuthForDelegation $true
    Set-ADUser -Identity "Manager" -Add @{'msDS-AllowedToDelegateTo'=@('CIFS/DC01')}

# Challenge 7 - Unconstrained Delegation
    Get-ADUser -Identity "Cook" | Set-ADAccountControl -TrustedForDelegation $true

# Update Group Policy
    gpupdate /force

# References
# https://github.com/hundotio/bluewin/blob/main/users.ps1
# https://github.com/Orange-Cyberdefense/GOAD/tree/main/ad/GOAD/scripts
# https://github.com/hundotio/bluewin/blob/main/lockdown.ps1
