# requires -RunAsAdministrator
###############################################################################
# Minimal Windows 11 Pro - Vagrant Box
# http://www.hurryupandwait.io/blog/in-search-of-a-light-weight-windows-vagrant-box
###############################################################################

###############################################################################
# ensure vagrant box runs powershell scripts without friction
###############################################################################
Set-ExecutionPolicy -ExecutionPolicy Unrestricted -Force

###############################################################################
# registry settings
###############################################################################
# separate window processes: prevent explorer.exe crash when one window crashes
New-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" `
  -Name "SeparateProcess" `
  -PropertyType DWORD `
  -Value 1 `
  -Force

# enable long file paths
New-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Control\FileSystem" `
  -Name "LongPathsEnabled" `
  -PropertyType DWORD `
  -Value 1 `
  -Force

###############################################################################
# ensure no password complexity requirements for next step
###############################################################################
# export current security configuration as a temporary file
secedit /export /cfg C:\SECURITYPOLICY.cfg

# change password complexity from 1 to 0
(Get-Content C:\SECURITYPOLICY.cfg).replace("PasswordComplexity = 1", "PasswordComplexity = 0") | Out-File C:\SECURITYPOLICY.cfg

# overwrite security configuration with temporary file
secedit /configure /db C:\Windows\security\local.sdb /cfg C:\SECURITYPOLICY.cfg /areas SECURITYPOLICY

# remove temporary security configuration file
Remove-Item C:\SECURITYPOLICY.cfg -Force

###############################################################################
# vagrant requires admin username and password to be "vagrant"
###############################################################################
# get the WinNT Active Directory Service Interface (ADSI) Administrator user object
$admin = [ADSI]"WinNT://./Administrator,user"

try {
  $admin.psbase.Rename("vagrant")
}
catch [System.Management.Automation.MethodInvocationException] {
  if ($_.FullyQualifiedErrorId -eq "DotNetMethodException") {
    Write-Host "Administrator account already renamed to vagrant"
  }
}

$admin.SetPassword("vagrant")
$admin.UserFlags.value = $admin.UserFlags.value -BOR 0x10000
$admin.CommitChanges()

###############################################################################
# tweak winrm for vagrant's ruby-based winrm implementation
###############################################################################
# set up default configuration for remote management
winrm quickconfig

# enable basic authentication for client and service
winrm set winrm/config/client/auth '@{Basic="true"}'
winrm set winrm/config/service/auth '@{Basic="true"}'

# set all network connection profiles from public to private
Get-NetConnectionProfile | Set-NetConnectionProfile -NetworkCategory Private

# allow transfer of unencrypted data on the WinRM service
winrm set winrm/config/service '@{AllowUnencrypted="true"}'

###############################################################################
# allow vagrant RDP
###############################################################################
$wmiObject = Get-WmiObject -Class "Win32_TerminalServiceSetting" -Namespace root\cimv2\terminalservices
$wmiObject.SetAllowTsConnections(1, 1)

###############################################################################
# enable firewall for RDP and winrm outside of subnet
# https://learn.microsoft.com/en-us/powershell/module/microsoft.powershell.core/enable-psremoting?view=powershell-7.2
###############################################################################
Enable-PSRemoting -SkipNetworkProfileCheck -Force

# get WINRM firewall rules:
# Get-NetFirewallRule -Name 'WINRM*' | Select-Object Name

# WINRM-HTTP-In-TCP-Public does not seem to exist in Windows 11 Pro
Set-NetFirewallRule -Name WINRM-HTTP-In-TCP -RemoteAddress Any
# Set-NetFirewallRule -Name WINRM-HTTP-In-TCP-NoScope -RemoteAddress Any
# Set-NetFirewallRule -Name WINRM-HTTP-Compat-In-TCP -RemoteAddress Any
# Set-NetFirewallRule -Name WINRM-HTTP-Compat-In-TCP-NoScope -RemoteAddress Any

# user mode = when a non-admin opens remotes into client computers
Set-NetFirewallRule -Name RemoteDesktop-UserMode-In-TCP -Enabled True

###############################################################################
# shrink pagefile
###############################################################################
$System = Get-WmiObject Win32_ComputerSystem -EnableAllPrivileges
$System.AutomaticManagedPagefile = $False
$System.Put()

$CurrentPageFile = Get-WmiObject -query "select * from Win32_PageFileSetting where name='C:\\pagefile.sys'"
$CurrentPageFile.InitialSize = 512
$CurrentPageFile.MaximumSize = 512
$CurrentPageFile.Put()

###############################################################################
# debloat - uninstall all possible apps
###############################################################################
Get-AppxPackage * -AllUsers | Remove-AppxPackage -ErrorAction SilentlyContinue -WarningAction SilentlyContinue

###############################################################################
# clean up
###############################################################################
$paths = @(

  # registry key for recent files
  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3134ef9c-6b18-4996-ad04-ed5912e00eb5}"

  # registry key for recent folders
  "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\HomeFolderDesktop\NameSpace\DelegateFolders\{3936E9E4-D92C-4EEE-A85A-BC16D5EA0819}"

  # swap file
  "C:\swapfile.sys"

  # update files
  "C:\Windows\SoftwareDistribution\Download"

  # update backups
  "C:\Windows\SoftwareDistribution\Backup"

  # Windows.old folder
  "C:\Windows.old"

  # temporary files
  "C:\Windows\Temp"
  "%LOCALAPPDATA%\Temp"
  "%APPDATA%\Temp"
)

foreach ($path in $paths) {
  if (Test-Path $path) {
    Remove-Item $path -Recurse -Force
  }
}

# empty recycle bin
Clear-RecycleBin -DriveLetter C -Force

# clean WinSxS folder
(Start-Process DISM.exe `
  -ArgumentList "/Online /Cleanup-Image /StartComponentCleanup /ResetBase" `
  -NoNewWindow `
  -Wait `
  -PassThru
).WaitForExit()

###############################################################################
# disable system restore - restore points are deleted after reboot
###############################################################################
Disable-ComputerRestore -Drive "C:\"

###############################################################################
# disable hibernation - C:\hiberfil.sys is deleted after reboot.
###############################################################################
powercfg.exe /hibernate off

###############################################################################
# Clear unnecessary files from hard disk.
###############################################################################
$strKeyPath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\VolumeCaches"
$strValueName = "StateFlags0065"
$subkeys = Get-ChildItem -Path $strKeyPath -Name

foreach ($subkey in $subkeys) {
  $null = New-ItemProperty `
    -Path $strKeyPath\$subkey `
    -Name $strValueName `
    -PropertyType DWord `
    -Value 2 `
    -ErrorAction SilentlyContinue `
    -WarningAction SilentlyContinue
}

(Start-Process cleanmgr `
  -ArgumentList "/sagerun:65 /verylowdisk" `
  -Wait `
  -PassThru `
  -NoNewWindow `
  -ErrorAction SilentlyContinue `
  -WarningAction SilentlyContinue `
).WaitForExit()

foreach ($subkey in $subkeys) {
  $null = Remove-ItemProperty `
    -Path $strKeyPath\$subkey `
    -Name $strValueName `
    -ErrorAction SilentlyContinue `
    -WarningAction SilentlyContinue
}

###############################################################################
# defrag disk
###############################################################################
Optimize-Volume -DriveLetter C -Verbose

###############################################################################
# purge hidden data with SDelete (Secure Delete)
###############################################################################
# TODO: download file for offline install
# download SDelete
Invoke-WebRequest `
  http://download.sysinternals.com/files/SDelete.zip `
  -OutFile SDelete.zip `
  -ErrorAction SilentlyContinue `
  -WarningAction SilentlyContinue

# extract SDelete.zip
Add-Type -AssemblyName System.IO.Compression.FileSystem
[System.IO.Compression.ZipFile]::ExtractToDirectory("SDelete.zip", "C:\Windows\System32")

# run SDelete on C: and (-z)eroize free space
./sdelete.exe /accepteula -z C:

# remove SDelete
$sdeleteFiles = @(
  "C:\Windows\System32\SDelete.zip"
  "C:\Windows\System32\Eula.txt"
  "C:\Windows\System32\sdelete.exe"
  "C:\Windows\System32\sdelete64.exe"
  "C:\Windows\System32\sdelete64a.exe"
)

foreach ($sdeleteFile in $sdeleteFiles) {
  if (Test-Path $sdeleteFile) {
    Remove-Item $sdeleteFile -Recurse -Force
  }
}

###############################################################################
# clear event logs
###############################################################################
wevtutil enum-logs | Foreach-Object {
  # these two logs return an "access is denied" error
  if ($_.contains("Microsoft-Windows-LiveId/Analytic") -OR $_.contains("Microsoft-Windows-LiveId/Operational")) {
    return
  }
  wevtutil clear-log "$_"
}

###############################################################################
# reboot to delete files
###############################################################################
Restart-Computer
