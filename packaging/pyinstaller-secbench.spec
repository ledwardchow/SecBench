# PyInstaller spec for Sec-Benchmarks (cross-platform).
# Build: pyinstaller packaging/pyinstaller-secbench.spec --noconfirm

# -*- mode: python ; coding: utf-8 -*-

import sys
from pathlib import Path
from PyInstaller.utils.hooks import collect_data_files, collect_submodules

block_cipher = None
project_root = Path.cwd()

datas = []
datas += collect_data_files("secbench", includes=["**/*.yaml", "**/*.j2", "**/*.qss", "**/*.css", "**/*.svg"])

hiddenimports = []
hiddenimports += collect_submodules("secbench.benchmarks")
hiddenimports += collect_submodules("azure")
hiddenimports += [
    "azure.mgmt.resource",
    "azure.mgmt.subscription",
    "azure.mgmt.compute",
    "azure.mgmt.storage",
    "azure.mgmt.sql",
    "azure.mgmt.network",
    "azure.mgmt.keyvault",
    "azure.mgmt.monitor",
    "azure.mgmt.security",
    "azure.mgmt.policyinsights",
    "azure.mgmt.authorization",
    "azure.mgmt.web",
    "azure.mgmt.containerservice",
    "azure.mgmt.containerregistry",
    "azure.mgmt.cosmosdb",
    "azure.mgmt.rdbms.postgresql_flexibleservers",
    "azure.mgmt.rdbms.mysql_flexibleservers",
    "azure.identity",
    "msal",
    "msgraph",
    "weasyprint",
    "reportlab",
]

a = Analysis(
    ["src/secbench/__main__.py"],
    pathex=[str(project_root / "src")],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=["tkinter"],
    win_no_prefer_redirects=False,
    win_private_assemblies=False,
    cipher=block_cipher,
    noarchive=False,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="SecBench",
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    console=False,
    icon=str(project_root / "packaging" / "icons" / ("icon.icns" if sys.platform == "darwin" else "icon.ico")) if (project_root / "packaging" / "icons").exists() else None,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=False,
    upx_exclude=[],
    name="SecBench",
)

if sys.platform == "darwin":
    app = BUNDLE(
        coll,
        name="SecBench.app",
        icon=str(project_root / "packaging" / "icons" / "icon.icns") if (project_root / "packaging" / "icons" / "icon.icns").exists() else None,
        bundle_identifier="ai.factory.secbench",
        info_plist={"NSHighResolutionCapable": "True"},
    )
