import json
import os
import platform
import subprocess
import sys
import tempfile
import requests
import yaml

KubemarineVersions:list = ["0.17.0","0.18.0","0.18.1","0.18.2","0.19.0","0.20.0","0.21.0","0.21.1","0.22.0","v0.23.0","v0.24.1","v0.25.0","v0.25.1","v0.26.0","v0.27.0"] #TODO to  get from github/gitlab/git/custom/file?

Envs: list = ["src", "pip", "bin", "docker"]

MigrationProcedure: dict = {
#    "v0.25.1":{"procedure":{},
#               "patches":[]},
#    "v0.26.0":{"procedure":{},
#               "patches":[
#                   {"patch0":
#                    f"Description0"}}
}


def migrate_kubemarine(toVersion, env, procedureyaml, patches ,clusteryaml):
    print(locals())
    pass


def distant_migrate():
    clusteryaml = ""
    for plan in MigrationProcedure:
        toVersion, env = next(iter(plan.items()))
        env = get_patches_info(toVersion, env)
        clusteryaml = migrate_kubemarine(toVersion,
                                         env,
                                         MigrationProcedure[toVersion]["procedure"],
                                         MigrationProcedure[toVersion]["patches"],
                                         clusteryaml)

def get_patches_info(version, env):
    patches_info = {"patches":[]}

    if env in "bin":
        #TODO kubemarine-win64.exe support
        filename = f"kubemarine-{'macos11' if platform.system().lower() == 'darwin' else 'linux'}-{platform.machine().lower()}"
        filepath = os.path.join(tempfile.gettempdir(),filename)
        
        try:
            # Download the file
            response = requests.get(f"https://github.com/Netcracker/KubeMarine/releases/download/{version}/{filename}")
            response.raise_for_status()  
            
            with open(filepath, "wb") as file:
                file.write(response.content)
            
            os.chmod(filepath, os.stat(filepath).st_mode | 0o111) # set executable
            
            # Assuming subprocess.run returns the patches list
            patches_list = subprocess.run([filepath, "migrate_kubemarine", "--list"], capture_output=True, text=True).stdout.splitlines()
            if "No patches available." in patches_list:
                patches_list = []
            else:
                patches_list.remove("Available patches list:") 
            
            for patch in patches_list:
                description = subprocess.run([filepath, "migrate_kubemarine", "--describe", patch], capture_output=True, text=True).stdout.strip()
                patches_info["patches"].append({patch.strip(): description})
        
        except Exception as e:
            print(f"Error: {e}")

        finally:
            os.unlink(filepath)

    return patches_info
 


def list(old_version='', new_version=''):
    ## get the patch list and  migration procedure
    index_from = KubemarineVersions.index(old_version) if old_version in KubemarineVersions else 0
    index_to =  KubemarineVersions.index(new_version)+1 if new_version in KubemarineVersions else -1

    for version in KubemarineVersions[index_from:index_to]:
        print(version,file=sys.stderr)
        MigrationProcedure[version] = get_patches_info(version,"bin")

    return MigrationProcedure


# function name, parameters ...
print(json.dumps(globals()[sys.argv[1]](*sys.argv[2:]),indent=3))
