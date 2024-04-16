# -*- mode: python ; coding: utf-8 -*-

block_cipher = None
options = [ ('u', None, 'OPTION')]

# MacOS option. By default, current running architecture is targeted.
# See scripts/ci/build_binary.py
target_arch = None

a = Analysis(['./kubemarine/__main__.py'],
             hiddenimports=[
                # Dynamically imported `python` procedures for plugins in defaults.yaml
                'kubemarine.plugins.builtin',
                'kubemarine.plugins.calico',
                'kubemarine.plugins.nginx_ingress',
                'kubemarine.plugins.kubernetes_dashboard',
             ],
             pathex=[],
             binaries=[],
             datas=[
                ('./kubemarine/patches',        './kubemarine/patches'),
                ('./kubemarine/plugins',        './kubemarine/plugins'),
                ('./kubemarine/version',        './kubemarine/'),
                ('./kubemarine/resources',      './kubemarine/resources'),
                ('./kubemarine/templates',      './kubemarine/templates')
             ],
             hookspath=['scripts/ci/custom-hooks'],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          options,
          exclude_binaries=False,
          name='kubemarine',
          icon='kubemarine.ico',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          console=True,
          target_arch=target_arch,
          )
