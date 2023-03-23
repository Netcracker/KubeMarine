# -*- mode: python ; coding: utf-8 -*-

block_cipher = None
options = [ ('u', None, 'OPTION')]

# MacOS option. By default, current running architecture is targeted.
# See scripts/ci/build_binary.py
target_arch = None

a = Analysis(['./kubemarine/__main__.py'],
             hiddenimports=[
                'kubemarine.procedures.add_node',
                'kubemarine.procedures.check_iaas',
                'kubemarine.procedures.check_paas',
                'kubemarine.procedures.do',
                'kubemarine.procedures.install',
                'kubemarine.procedures.migrate_kubemarine',
                'kubemarine.procedures.migrate_cri',
                'kubemarine.procedures.manage_psp',
                'kubemarine.procedures.manage_pss',
                'kubemarine.procedures.remove_node',
                'kubemarine.procedures.upgrade',
                'kubemarine.procedures.cert_renew',
                'kubemarine.procedures.backup',
                'kubemarine.procedures.restore',
                'kubemarine.procedures.reboot',
                'kubemarine.plugins.builtin',
                'kubemarine.plugins.calico',
                'kubemarine.plugins.nginx_ingress',
                'kubemarine.plugins.kubernetes_dashboard',
                'kubemarine.core.schema'
             ],
             pathex=[],
             binaries=[],
             datas=[
                ('./kubemarine/plugins',        './kubemarine/plugins'),
                ('./kubemarine/version',        './kubemarine/'),
                ('./kubemarine/resources',      './kubemarine/resources'),
                ('./kubemarine/templates',      './kubemarine/templates')
             ],
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
