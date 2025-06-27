#ERABLE-BS
#V1.0
# Script to create or modify your salt and delete cache file with the keepass password encrypt
function Show-Menu {
    Clear-Host
    Write-Host "=== Menu ==="
    Write-Host ""
    Write-Host "1. Générer un salt (Base64, 32 octets) et l'enregistrer dans %APPDATA%"
    Write-Host "2. Supprimer les fichiers sshor_keepass_* dans le dossier Temp"
    Write-Host "0. Quitter"
    Write-Host ""
    $choice = Read-Host "Choisissez une option"
    Write-Host ""

    switch ($choice) {
        "1" { Generate-And-Save-Salt }
        "2" { Delete-TempFiles }
        "0" { Write-Host "Au revoir !" ; return }
        default { Write-Host "Option invalide." }
    }

    Write-Host ""
    Pause
    Show-Menu
}

function Delete-TempFiles {
    $tempPath = "$env:USERPROFILE\AppData\Local\Temp"
    $files = Get-ChildItem -Path $tempPath -Filter "sshor_keepass_*" -File -ErrorAction SilentlyContinue

    if ($files.Count -eq 0) {
        Write-Host "Aucun fichier correspondant trouvé dans $tempPath"
    } else {
        foreach ($file in $files) {
            try {
                Remove-Item $file.FullName -Force
                Write-Host "Supprimé : $($file.Name)"
            } catch {
                Write-Host "Erreur lors de la suppression de $($file.Name) : $_"
            }
        }
    }
}

function Generate-And-Save-Salt {
    $bytes = New-Object byte[] 32
    [System.Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($bytes)
    $base64 = [Convert]::ToBase64String($bytes)

    $filePath = Join-Path $env:APPDATA "sshor_keepass_salt.txt"
    $base64 | Out-File -FilePath $filePath -Encoding ASCII -NoNewline

    Write-Host "Chaîne Base64 enregistrée dans : $filePath"
}

Show-Menu
