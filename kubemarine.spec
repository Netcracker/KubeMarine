# -*- mode: python ; coding: utf-8 -*-

block_cipher = None
options = [ ('u', None, 'OPTION')]


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
                'kubemarine.plugins.calico',
                'kubemarine.plugins.nginx_ingress',
                'kubemarine.plugins.haproxy_ingress'
             ],
             pathex=['./'],
             binaries=[],
             datas=[
                ('./kubemarine/resources/configurations/*', './kubemarine/resources/configurations'),
                ('./kubemarine/resources/psp/*',            './kubemarine/resources/psp'),
                ('./kubemarine/resources/reports/*',        './kubemarine/resources/reports'),
                ('./kubemarine/resources/scripts/*',        './kubemarine/resources/scripts'),
                ('./kubemarine/resources/drop_ins/*',       './kubemarine/resources/drop_ins'),
                ('./kubemarine/templates/*',                './kubemarine/templates'),
                ('./kubemarine/plugins/*',                  './kubemarine/plugins'),
                ('./kubemarine/plugins/yaml/*',             './kubemarine/plugins/yaml'),
                ('./kubemarine/templates/plugins/*',        './kubemarine/templates/plugins'),
                ('./kubemarine/version',                    './kubemarine/')
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
          console=True)

app = BUNDLE(name='kubemarine',
             icon='kubemarine.ico',
             bundle_identifier=None)