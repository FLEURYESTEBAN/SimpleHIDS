# =====================================
#       PowerShell HIDS (Office 365)
# Host-based Intrusion Detection System
# Monitors file integrity (SHA256) and network reachability (Ping)
# Sends alerts via Office 365 email
# =====================================

# --- GLOBAL VARIABLES ---
# Hash table to store the baseline hashes of monitored files:
# Key = full file path, Value = SHA256 hash
$global:dico_de_hash = @{}     
# List of IP addresses to periodically check reachability (ping)
$global:ips_to_watch = @()     
# Flag to control the main monitoring loop state
$global:surveillanceActive = $false

# --- MAIL CONFIGURATION ---
Write-Host "=== Mail Alert Configuration ===" -ForegroundColor Cyan
# Prompt for the recipient email address for alerts
$destinataire = Read-Host "Enter the recipient email (alert)"
# Prompt for the sender email address (Office 365 account)
$expediteur = Read-Host "Enter your Office 365 email (sender)"
Write-Host "[INFO] Please enter the Office 365 credentials for the sender account" -ForegroundColor Yellow
# Securely obtain credentials for the sender's Office 365 account
$cred = Get-Credential -Message "Office 365 Login (use sender address)"

# --- UTILITY FUNCTIONS ---

function Get-Hash {
    param([string]$path)
    # Calculates the SHA256 hash of a file
    try {
        Write-Host "[INFO] Computing hash for: $path" -ForegroundColor Cyan
        # Use Get-FileHash cmdlet to compute the SHA256 hash
        return (Get-FileHash -Path $path -Algorithm SHA256).Hash
    } catch {
        # Handle cases where the file cannot be read (e.g., permissions, non-existent)
        Write-Host "[ERROR] Cannot compute hash for $path : $($_.Exception.Message)" -ForegroundColor Red
        return $null
    }
}


function Send-Alert {
    param([string]$message)
    # Sends an email alert via Office 365 SMTP
    $smtp = "smtp.office365.com"
    $port = 587
    Write-Host "[ALERT] Sending email alert..." -ForegroundColor Yellow
    try {
        Send-MailMessage -To $destinataire `
                             -From $expediteur `
                             -Subject "HIDS Alert" `
                             -Body $message `
                             -SmtpServer $smtp `
                             -Port $port `
                             -UseSsl `
                             -Credential $cred # Use stored credentials
        Write-Host "[OK] Email sent to $destinataire" -ForegroundColor Green
    } catch {
        Write-Host "[ERROR] Failed to send email: $($_.Exception.Message)" -ForegroundColor Red
    }
}

# --- CHECK ONESHOT FUNCTIONS (no internal loops) ---

function CheckFilesOnce {
    # Iterates over all monitored files and checks for changes or deletions
    # Iterate over a copy of the keys to avoid "collection modified" errors 
    # when removing an entry inside the loop.
    foreach ($path in @($global:dico_de_hash.Keys)) {
        if (Test-Path $path) {
            # File exists, compute current hash
            $currentHash = Get-Hash -path $path
            # Compare current hash with baseline hash
            if ($currentHash -ne $null -and $currentHash -ne $global:dico_de_hash[$path]) {
                Write-Host "File changed: $path" -ForegroundColor Red
                Send-Alert "The file $path has been modified."
                # Update baseline to the new hash. This ensures continuous 
                # monitoring and alerts only on new changes.
                $global:dico_de_hash[$path] = $currentHash
            }
        } else {
            # File does not exist (deleted)
            Write-Host "File deleted: $path" -ForegroundColor Yellow
            Send-Alert "The file $path has been deleted."
            # Remove the file from monitoring
            $global:dico_de_hash.Remove($path)
        }
    }
}

function CheckIPsOnce {
    # Iterates over all monitored IPs and checks reachability via ping
    foreach ($ip in @($global:ips_to_watch)) {
        try {
            # Use Test-Connection to send one ping packet (-Count 1 -Quiet returns boolean)
            $alive = Test-Connection -ComputerName $ip -Count 1 -Quiet
        } catch {
            # Treat connection errors as unreachable
            $alive = $false
        }
        if (-not $alive) {
            Write-Host "Host unreachable: $ip" -ForegroundColor Red
            Send-Alert "The host $ip is not responding to ping."
        } else {
            Write-Host "Host reachable: $ip" -ForegroundColor Green
        }
    }
}

# --- MASTER MONITORING LOOP (interleaved checks, ESC to stop) ---

function Start-Monitoring {
    param(
        # Interval for file integrity checks (in seconds)
        [int]$FileIntervalSec = 1,
        # Interval for IP reachability checks (in seconds)
        [int]$IpIntervalSec = 5
    )

    Write-Host "[INFO] Monitoring started. Press ESC to stop." -ForegroundColor Cyan
    $global:surveillanceActive = $true

    # Initialize next check timestamps
    $nextFileCheck = Get-Date
    $nextIpCheck = Get-Date

    # Main monitoring loop runs as long as the flag is true
    while ($global:surveillanceActive) {
        $now = Get-Date

        # Check file integrity if time has elapsed and files are monitored
        if ($global:dico_de_hash.Count -gt 0 -and $now -ge $nextFileCheck) {
            try {
                CheckFilesOnce
            } catch {
                Write-Host "[ERROR] CheckFilesOnce failed: $($_.Exception.Message)" -ForegroundColor Red
            }
            # Set time for the next file check
            $nextFileCheck = $now.AddSeconds($FileIntervalSec)
        }

        # Check IP reachability if time has elapsed and IPs are monitored
        if ($global:ips_to_watch.Count -gt 0 -and $now -ge $nextIpCheck) {
            try {
                CheckIPsOnce
            } catch {
                Write-Host "[ERROR] CheckIPsOnce failed: $($_.Exception.Message)" -ForegroundColor Red
            }
            # Set time for the next IP check
            $nextIpCheck = $now.AddSeconds($IpIntervalSec)
        }

        # Non-blocking ESC detection to allow stopping the script gracefully
        try {
            if ($Host.UI.RawUI.KeyAvailable) {
                # Read key press without echoing to console
                $key = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
                if ($key.VirtualKeyCode -eq 27) { # Check for ESC key (VirtualKeyCode 27)
                    Write-Host "[INFO] Stopping monitoring..." -ForegroundColor Yellow
                    $global:surveillanceActive = $false
                    break # Exit the while loop
                }
            }
        } catch {
            # Ignore keyboard read errors
        }

        # Wait for a short period to prevent excessive CPU usage and allow key input checks
        Start-Sleep -Milliseconds 200
    }

    Write-Host "[INFO] Monitoring stopped." -ForegroundColor Cyan
}

# --- MAIN MENU ---

# Loop to display the main menu until the user chooses to Quit (option 4)
do {
    Write-Host "`n==============================" -ForegroundColor Cyan
    Write-Host "        PowerShell HIDS" -ForegroundColor Cyan
    Write-Host "==============================" -ForegroundColor Cyan
    Write-Host "1. Add a file or folder to monitor"
    Write-Host "2. Add an IP address to monitor"
    Write-Host "3. Start monitoring"
    Write-Host "4. Quit"
    $choice = Read-Host "Choice"

    switch ($choice) {
        1 {
            $path = Read-Host "Enter the full path of the file or folder"
            # Check if path is a single file
            if (Test-Path $path -PathType Leaf) {
                $hash = Get-Hash -path $path
                if ($hash -ne $null) {
                    # Add file path and its baseline hash to the dictionary
                    $global:dico_de_hash[$path] = $hash
                    Write-Host "File added: $path" -ForegroundColor Green
                } else {
                    Write-Host "[ERROR] Failed to read file hash, not added." -ForegroundColor Red
                }
            # Check if path is a folder (container)
            } elseif (Test-Path $path -PathType Container) {
                # Get all files recursively within the folder
                $files = Get-ChildItem -Path $path -Recurse -File -ErrorAction SilentlyContinue
                foreach ($f in $files) {
                    $hash = Get-Hash -path $f.FullName
                    # Add each file and its hash to the dictionary
                    if ($hash -ne $null) { $global:dico_de_hash[$f.FullName] = $hash }
                }
                Write-Host "Folder added: $path" -ForegroundColor Green
            } else {
                Write-Host "[ERROR] Invalid path." -ForegroundColor Red
            }
        }
        2 {
            $ip = Read-Host "Enter an IP address to monitor"
            if ($ip) {
                # Add IP address to the watch list
                $global:ips_to_watch += $ip
                Write-Host "IP added: $ip" -ForegroundColor Green
            }
        }
        3 {
            Write-Host "Starting monitoring... (Press ESC to stop)" -ForegroundColor Yellow
            # Call the master monitoring loop with default or specified intervals
            Start-Monitoring -FileIntervalSec 1 -IpIntervalSec 5
        }
        4 {
            Write-Host "Exiting program." -ForegroundColor Cyan
            break # Exit the do-while loop
        }
        default {
            Write-Host "[ERROR] Invalid choice, please try again." -ForegroundColor Red
        }
    }
} while ($choice -ne 4)
