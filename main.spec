# -*- mode: python ; coding: utf-8 -*-

block_cipher = None
options = [ ('u', None, 'OPTION')]


a = Analysis(['./kubetool/__main__.py'],
             hiddenimports=[
                'kubetool.procedures.add_node',
                'kubetool.procedures.check_iaas',
                'kubetool.procedures.check_paas',
                'kubetool.procedures.do',
                'kubetool.procedures.install',
                'kubetool.procedures.manage_psp',
                'kubetool.procedures.remove_node',
                'kubetool.procedures.upgrade',
                'kubetool.procedures.cert_renew',
                'kubetool.procedures.backup',
                'kubetool.procedures.restore',
                'kubetool.procedures.reboot'
             ],
             pathex=['./'],
             binaries=[],
             datas=[
                ('./kubetool/resources/configurations/*', './kubetool/resources/configurations'),
                ('./kubetool/resources/psp/*', './kubetool/resources/psp'),
                ('./kubetool/resources/reports/*', './kubetool/resources/reports'),
                ('./kubetool/resources/scripts/*', './kubetool/resources/scripts'),
                ('./kubetool/resources/drop_ins/*', './kubetool/resources/drop_ins'),
                ('./kubetool/templates/*', './kubetool/templates'),
                ('./kubetool/templates/plugins/*', './kubetool/templates/plugins'),
                ('./kubetool/plugins/*', './kubetool/plugins')
             ],
             runtime_hooks=[],
             excludes=[],
             win_no_prefer_redirects=False,
             win_private_assemblies=False,
             cipher=block_cipher,
             noarchive=False)

pyz = PYZ(a.pure, a.zipped_data,
             cipher=block_cipher)

exe = EXE(pyz,
          a.scripts,
          a.binaries,
          a.zipfiles,
          a.datas,
          options,
          exclude_binaries=False,
          name='kubetools',
          debug=False,
          bootloader_ignore_signals=False,
          strip=False,
          upx=True,
          console=False)

coll = COLLECT(exe,
               a.scripts,
               a.binaries,
               a.zipfiles,
               a.datas,
               debug=False,
               strip=False,
               upx=True,
               upx_exclude=[],
               name='main')
