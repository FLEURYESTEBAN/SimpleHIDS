# === Mail Alert Configuration ===
$global:CredFile = "$env:ProgramData\SimpleHIDS\m365_creds.sec"
$global:alertTimestamps = @{}
$MinAlertIntervalSec = 60  # pas plus d’une alerte/minute par fichier

Write-Host "=== Configuration de l'alerte mail ===" -ForegroundColor Cyan
$global:destinataire = Read-Host "Entrez l'adresse de réception (alertes)"
$global:expediteur = Read-Host "Entrez votre adresse Microsoft 365 (expéditeur)"

# Charger ou créer les identifiants chiffrés
if (Test-Path $global:CredFile) {
    Write-Host "[INFO] Chargement des identifiants chiffrés..." -ForegroundColor Yellow
    $secure = Get-Content $global:CredFile | ConvertTo-SecureString
    $global:cred = New-Object System.Management.Automation.PSCredential($global:expediteur, $secure)
} else {
    Write-Host "[INFO] Veuillez entrer votre mot de passe Microsoft 365 (sera stocké de manière chiffrée)" -ForegroundColor Yellow
    $global:cred = Get-Credential -Message "Connexion Office 365 ($global:expediteur)"
    $global:cred.Password | ConvertFrom-SecureString | Set-Content -Path $global:CredFile
    Write-Host "[OK] Identifiants enregistrés en sécurité pour les prochaines sessions." -ForegroundColor Green
}

# === Fonction d'envoi d'alerte (avec limitation) ===
function Send-Alert {
    param(
        [string]$Target,
        [string]$Message
    )

    $smtp = "smtp.office365.com"
    $port = 587

    # Anti-spam : une seule alerte/minute pour la même cible
    $now = Get-Date
    $last = $global:alertTimestamps[$Target]
    if ($last -and ($now - $last).TotalSeconds -lt $MinAlertIntervalSec) {
        Write-Host "[INFO] Alerte ignorée pour $Target (limitation de fréquence)" -ForegroundColor Yellow
        return
    }
    $global:alertTimestamps[$Target] = $now

    try {
        Send-MailMessage `
            -To $global:destinataire `
            -From $global:expediteur `
            -Subject "HIDS : Changement détecté sur $Target" `
            -Body $Message `
            -SmtpServer $smtp `
            -Port $port `
            -UseSsl `
            -Credential $global:cred

        Write-Host "[OK] Alerte envoyée à $($global:destinataire)" -ForegroundColor Green
    } catch {
        Write-Host "[ERREUR] Impossible d'envoyer l'alerte : $($_.Exception.Message)" -ForegroundColor Red
    }
}


Send-Alert -Target "Test-Mail" -Message "Ceci est un test de l'alerte HIDS depuis PowerShell."
