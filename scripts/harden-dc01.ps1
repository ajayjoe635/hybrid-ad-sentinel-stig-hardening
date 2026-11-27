# ==============================================================================
# Windows Server 2025 Domain Controller (DC01) CIS / DISA STIG Hardening Script
# Consolidates Batches 1-4 (Score Progression: 3.27 [93] -> 3.94 [174 Passed])
# ==============================================================================

# --- BATCH 1: VISIBILITY & AUDIT TELEMETRY ---
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v SCENoApplyLegacyAuditPolicy /t REG_DWORD /d 1 /f

$Subcategories = @(
    "Credential Validation", "Kerberos Authentication Service", "Kerberos Service Ticket Operations",
    "Application Group Management", "Computer Account Management", "Distribution Group Management",
    "Other Account Management Events", "Security Group Management", "User Account Management",
    "Process Creation", "Audit Policy Change", "Authentication Policy Change",
    "Sensitive Privilege Use", "Logoff", "Logon", "Special Logon", "System Integrity",
    "DPAPI Activity", "Plug and Play Events", "Account Lockout", "Group Membership",
    "Other Logon/Logoff Events", "Detailed File Share", "File Share", "Kernel Object",
    "Other Object Access Events", "Removable Storage", "SAM",
    "MPSSVC Rule-Level Policy Change", "Other Policy Change Events", "Security System Extension"
)
foreach ($Sub in $Subcategories) {
    auditpol /set /subcategory:"$Sub" /success:enable /failure:enable | Out-Null
}

# Process CLI Auditing (Event ID 4688), PowerShell Logging (Event ID 4104) & Event Log Sizing
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Audit" /v ProcessCreationIncludeCmdLine_Enabled /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\PowerShell\ScriptBlockLogging" /v EnableScriptBlockLogging /t REG_DWORD /d 1 /f
wevtutil sl Security /ms:201326592
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\Application" /v MaxSize /t REG_DWORD /d 32768 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\EventLog\System" /v MaxSize /t REG_DWORD /d 32768 /f

# --- BATCH 2: CREDENTIAL THEFT & LATERAL MOVEMENT DEFENSE ---
# LSASS Protected Process Light (RunAsPPL) & Custom SSP/AP Block
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RunAsPPL /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v DisableCustomSSPsAndAPs /t REG_DWORD /d 1 /f

# Disable Print Spooler (PrintNightmare) & WebClient
Stop-Service Spooler -Force -ErrorAction SilentlyContinue
Set-Service Spooler -StartupType Disabled
Stop-Service WebClient -Force -ErrorAction SilentlyContinue
Set-Service WebClient -StartupType Disabled -ErrorAction SilentlyContinue
reg add "HKLM\SYSTEM\CurrentControlSet\Services\WebClient" /v Start /t REG_DWORD /d 4 /f

# Disable LLMNR & NetBIOS over TCP/IP
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableMulticast /t REG_DWORD /d 0 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\DNSClient" /v EnableNetbios /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\NetBT\Parameters" /v NoNameReleaseOnDemand /t REG_DWORD /d 1 /f
Get-CimInstance Win32_NetworkAdapterConfiguration -Filter "IPEnabled=True" |
    Invoke-CimMethod -MethodName SetTcpipNetbios -Arguments @{TcpipNetbiosOptions = 2} | Out-Null

# Block Anonymous SAM Enumeration, Restrict Remote SAM & Admin Approval Mode
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymousSAM /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictAnonymous /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa" /v RestrictRemoteSAM /t REG_SZ /d "O:BAG:BAD:(A;;RC;;;BA)" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v FilterAdministratorToken /t REG_DWORD /d 1 /f

# Disable SMBv1 & Enforce Mandatory SMB Signing
Set-SmbServerConfiguration -EnableSMB1Protocol $false -RequireSecuritySignature $true -Force
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v SMB1 /t REG_DWORD /d 0 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\mrxsmb10" /v Start /t REG_DWORD /d 4 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\LanmanWorkstation" /v AllowInsecureGuestAuth /t REG_DWORD /d 0 /f

# --- BATCH 3: NTLM AUDITING & DEFENDER ASR BLOCK ENFORCEMENT ---
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v AuditReceivingNTLMTraffic /t REG_DWORD /d 2 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" /v AuditNTLMInDomain /t REG_DWORD /d 7 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v NTLMMinClientSec /t REG_DWORD /d 537395200 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Control\Lsa\MSV1_0" /v NTLMMinServerSec /t REG_DWORD /d 537395200 /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender" /v PUAProtection /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SpynetReporting /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\Spynet" /v SubmitSamplesConsent /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows Defender\MpEngine" /v MpCloudBlockLevel /t REG_DWORD /d 2 /f

$AsrBlockRules = @(
    "56a863a9-875e-4185-98a7-b882c64b5ce5", "7674ba52-37eb-4a4f-a9a1-f0f9a1619a2c",
    "d4f940ab-401b-4efc-aadc-ad5f3c50688a", "9e6c4e1f-7d60-472f-ba1a-a39ef669e4b2",
    "be9ba2d9-53ea-4cdc-84e5-9b1eeee46550", "01443614-cd74-433a-b99e-2ecdc07bfc25",
    "5beb7efe-fd9a-4556-801d-275e5ffc04cc", "d3e037e1-3eb8-44c8-a917-57927947596d",
    "3b576869-a4ec-4529-8536-b80a7769e899", "75668c1f-73b5-4cf0-bb93-3ecf5cb7cc84",
    "26190899-1602-49e8-8b27-eb1d0a1ce869", "e6db77e5-3df2-4cf1-b95a-636979351e5b",
    "d1e49aac-8f56-4280-b9ba-993a6d77406c", "b2b3f03d-6a65-4f7b-a9c7-1c7ef74a9ba4",
    "92e97fa1-2edf-4476-bdd6-9dd0b4dddc7b"
)
Set-MpPreference -AttackSurfaceReductionRules_Ids $AsrBlockRules -AttackSurfaceReductionRules_Actions (@("Enabled") * $AsrBlockRules.Count) -ErrorAction SilentlyContinue

# --- BATCH 4: RPC, SMB AUDIT, RDP/WINRM & FIREWALL HARDENING ---
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v AuditClientDoesNotSupportEncryption /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanWorkstation\Parameters" /v AuditClientDoesNotSupportSigning /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AuditClientDoesNotSupportEncryption /t REG_DWORD /d 1 /f
reg add "HKLM\SYSTEM\CurrentControlSet\Services\LanmanServer\Parameters" /v AuditClientDoesNotSupportSigning /t REG_DWORD /d 1 /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" /v EnableAuthEpResolution /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Rpc" /v RestrictRemoteClients /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\W32Time\TimeProviders\NtpClient" /v Enabled /t REG_DWORD /d 1 /f

foreach ($Profile in @("DomainProfile", "PrivateProfile", "PublicProfile")) {
    $Base = "HKLM\SOFTWARE\Policies\Microsoft\WindowsFirewall\$Profile"
    reg add $Base /v EnableFirewall /t REG_DWORD /d 1 /f
    reg add "$Base\Logging" /v LogFileSize /t REG_DWORD /d 16384 /f
    reg add "$Base\Logging" /v LogDroppedPackets /t REG_DWORD /d 1 /f
}

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v EnableSmartScreen /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\System" /v ShellSmartScreenLevel /t REG_SZ /d "Block" /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorAdmin /t REG_DWORD /d 2 /f
reg add "HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System" /v ConsentPromptBehaviorUser /t REG_DWORD /d 1 /f

reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows\WinRM\Service" /v DisableRunAs /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fEncryptRPCTraffic /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fPromptForPassword /t REG_DWORD /d 1 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v MinEncryptionLevel /t REG_DWORD /d 3 /f
reg add "HKLM\SOFTWARE\Policies\Microsoft\Windows NT\Terminal Services" /v fDisableCdm /t REG_DWORD /d 1 /f
