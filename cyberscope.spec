# PyInstaller spec (optional): pyinstaller cyberscope.spec
a = Analysis(['main.py'], pathex=['.'], hiddenimports=['core.checks', 'gui.main_window'])
pyz = PYZ(a.pure)
exe = EXE(pyz, a.scripts, [], exclude_binaries=True, name='CyberScope', console=False)
coll = COLLECT(exe, a.binaries, a.datas, name='CyberScope')
