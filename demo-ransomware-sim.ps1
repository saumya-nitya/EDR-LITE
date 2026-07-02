# EDR-Lite Safe Demo Script
# Simulates ransomware-like rapid file create + rename behavior.
# This script does NOT encrypt, delete, or harm any files.
# It only creates dummy test files and renames their extensions.

$targetFolder = "test-folder"
$fileCount = 25

Write-Host "Starting EDR-Lite ransomware simulation..." -ForegroundColor Yellow
Write-Host "Target folder: $targetFolder"
Write-Host "Files to create: $fileCount"
Write-Host ""

if (-not (Test-Path $targetFolder)) {
    New-Item -ItemType Directory -Path $targetFolder | Out-Null
}

for ($i = 1; $i -le $fileCount; $i++) {
    $fileName = "$targetFolder\sim_file_$i.txt"
    "This is dummy content for simulation file $i" | Out-File -FilePath $fileName

    Start-Sleep -Milliseconds 50

    $renamedName = "$targetFolder\sim_file_$i.locked"
    Rename-Item -Path $fileName -NewName "sim_file_$i.locked"

    Write-Host "Created and renamed: sim_file_$i.txt -> sim_file_$i.locked"
}

Write-Host ""
Write-Host "Simulation complete. Check EDR-Lite's output/log for detection and response." -ForegroundColor Green