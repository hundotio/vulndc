# Weaken password policy:
    $Domain = (Get-ADDomain).DNSRoot
    Set-ADDefaultDomainPasswordPolicy -Identity $Domain `
        -LockoutDuration 00:00:01 `
        -LockoutObservationWindow 00:00:01 `
        -ComplexityEnabled $False `
        -ReversibleEncryptionEnabled $True `
        -MaxPasswordAge 999.00:00:00 `
        -MinPasswordLength 2

# Add Users:
    Set-ADUser -Identity "Guest" -Enabled $true
    net user Menu pink_lemonade /add
    net user Waiter ilike2eatfood /add
    net localgroup "performance log users" waiter /add
    net user Cook cookies4life /add
    net user Manager iamthebossofthehouse /add

# Write the flags:
    New-Item -ItemType Directory -Path C:\Secrets -Force

    # Challenge 1 - Guest SMB - Guest Flag
        New-Item -ItemType Directory -Path C:\Secrets\Guest -Force
        Set-Content -Path "C:\Secrets\Guest\flag.txt" -Value "DSU{0p3n_t0_3v3ry0n3}"  
        icacls "C:\Secrets\Guest" /inheritance:r /grant "Guest:(OI)(CI)F" /grant "Administrator:(OI)(CI)F"
    
    # Challenge 2 - Anon RPC - Menu Flag + Credentials
        New-Item -ItemType Directory -Path C:\Secrets\Menu -Force
        Set-Content -Path "C:\Secrets\Menu\flag.txt" -Value "DSU{wh3n_l1f3_g1v3s_y0u_l3m0ns}"
        icacls "C:\Secrets\Menu" /inheritance:r /grant "Menu:(OI)(CI)F" /grant "Administrator:(OI)(CI)F"
    
    # Challenge 3 - LLMNR - Waiter Flag + Credentials
        New-Item -ItemType Directory -Path C:\Secrets\Waiter -Force
        Set-Content -Path "C:\Secrets\Waiter\flag.txt" -Value "DSU{4n_4bs0lut3_cl4ss1c}"
            icacls "C:\Secrets\Waiter" /inheritance:r /grant "Waiter:(OI)(CI)F" /grant "Administrator:(OI)(CI)F"
    
    # Challenge 4 - Preauthentication - Cook Flag + Credentials
        New-Item -ItemType Directory -Path C:\Secrets\Cook -Force
        Set-Content -Path "C:\Secrets\Cook\flag.txt" -Value "DSU{j3ss3_w3_n33d_t0_c00k}"
        icacls "C:\Secrets\Cook" /inheritance:r /grant "Cook:(OI)(CI)F" /grant "Administrator:(OI)(CI)F"
    
    # Challenge 5 - Kerberoastable User SPNs - Manager Flag + Credentials
        New-Item -ItemType Directory -Path C:\Secrets\Manager -Force
        Set-Content -Path "C:\Secrets\Manager\flag.txt" -Value "DSU{k3rb3r04st_g0_brrrr}"
        icacls "C:\Secrets\Manager" /inheritance:r /grant "Manager:(OI)(CI)F" /grant "Administrator:(OI)(CI)F"
    
    # Challenge 6 - Constrained Delegation - Administrator Flag + Pass-the-hash
        New-Item -ItemType Directory -Path C:\Secrets\Administrator -Force
        Set-Content -Path "C:\Secrets\Administrator\flag.txt" -Value "DSU{d3l3g4t10n_f0r_th3_w1n}"
        icacls "C:\Secrets\Administrator" /inheritance:r /grant "Administrator:(OI)(CI)F" /grant "Administrator:(OI)(CI)F"

# Challenge 1 - Configure Guest SMB
    icacls "C:\Secrets" /grant "Guest:(OI)(CI)F"
    New-SmbShare -Name "Secrets" -Path "C:\Secrets" -FullAccess "Everyone"

# Challenge 2 - RPC LDAP
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RestrictAnonymous -Value 0
    Set-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\Lsa" -Name RestrictAnonymousSAM -Value 0
    net localgroup "Pre-Windows 2000 Compatible Access" "ANONYMOUS LOGON" /add

    Set-ADUser -Identity "Menu" -Description "Password: pink_lemonade"

# Challenge 3 - LLMNR
    REG ADD "HKLM\Software\policies\Microsoft\Windows NT\DNSClient"
    REG ADD "HKLM\Software\policies\Microsoft\Windows NT\DNSClient" /v "EnableMulticast" /t REG_DWORD /d "1" /f

    $task = '/c powershell New-PSDrive -Name "Public" -PSProvider "FileSystem" -Root "\\orderup\whosisit"'
    $repeat = (New-TimeSpan -Minutes 2)
    $taskName = "responder"
    $user = "secure.local\Waiter"
    $password = "ilike2eatfood"

    # Create scheduled task
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
    Set-ADUser -Identity "Manager" -ServicePrincipalNames @{Add="CIFS/DC01.$Domain"}

# Challenge 6 - Constrained Delegation
    Get-ADUser -Identity "Manager" | Set-ADAccountControl -TrustedToAuthForDelegation $true
    Set-ADUser -Identity "Manager" -Add @{'msDS-AllowedToDelegateTo'=@('host/DC01')}

# Challenge 7 - Unconstrained Delegation
    Get-ADUser -Identity "Cook" | Set-ADAccountControl -TrustedForDelegation $true

# Update Group Policy
    gpupdate /force

# References
# https://github.com/hundotio/bluewin/blob/main/users.ps1
# https://github.com/Orange-Cyberdefense/GOAD/tree/main/ad/GOAD/scripts
# https://github.com/hundotio/bluewin/blob/main/lockdown.ps1
