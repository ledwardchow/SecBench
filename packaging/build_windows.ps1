$ErrorActionPreference = "Stop"
Set-Location (Split-Path $PSScriptRoot -Parent)
python -m pip install -e ".[dev]"
pyinstaller packaging/pyinstaller-secbench.spec --noconfirm --clean
Write-Host "Built dist\SecBench"
