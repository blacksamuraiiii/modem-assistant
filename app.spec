# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['app_ctk.py'],
    pathex=[],
    binaries=[('C:\\Users\\black_samurai\\AppData\\Local\\ms-playwright\\chromium-1187', 'chromium')],
    datas=[('version_info.txt', '.'), ('screenshots', 'screenshots')],
    hiddenimports=['customtkinter', 'playwright', 'pandas', 'openpyxl', 'tkinter', 'ttk'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='光猫助手',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    version='version_info.txt',
)