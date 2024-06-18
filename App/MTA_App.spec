# -*- mode: python ; coding: utf-8 -*-

block_cipher = None

a = Analysis(
    ['MTA_App.py'],
    pathex=['.'],
    binaries=[],
    datas=[('D:\\Python_NETWORKING_CODE\\BTLon\\CD1\\App\\Logo_MTA_new.png', '.')],
    hiddenimports=['requests', 'tkinter', 'pyshark', 'matplotlib', 'psutil'],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='MTA_App',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,  # Đặt console=False để không mở terminal
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
    icon=r'D:\Python_NETWORKING_CODE\BTLon\CD1\App\Logo_MTA_new.png'
)

coll = COLLECT(
    exe,
    a.binaries,
    a.zipfiles,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='MTA_App'
)
