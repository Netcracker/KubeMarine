import os
import platform
import subprocess
import sys
import tempfile
import requests

KubemarineVersions:list = ["v0.25.0","v0.25.1","v0.26.0"]
Envs: list = ["src", "pip", "bin", "docker"]

MigrationProcedure: dict = {
    "v0.25.0":{"procedure":{},
               "patches":[]},
    "v0.25.1":{"procedure":{},
               "patches":[]},
    "v0.26.0":{"procedure":{},
               "patches":[
                   {"patch0":
                    f"Description0"},
                   {"patch1":
                    "description1"}]
                           }}

MigrationPlan: list = [
    {"v0.25.1":"src"},
    {"v0.26.0":"src"},]


def migrate_kubemarine(toVersion, env, procedureyaml, patches ,clusteryaml) :
    print(locals())
    pass
 
def get_set_env(version, deployment):
    pass

def distant_migrate():
    clusteryaml = ""
    for plan in MigrationPlan:
        toVersion, env = next(iter(plan.items()))
        env = get_set_env(toVersion, env)
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
            patches_list.remove("Available patches list:")
            
            for patch in patches_list:
                description = subprocess.run([filepath, "migrate_kubemarine", "--describe", patch], capture_output=True, text=True).stdout.strip()
                patches_info["patches"].append({patch.strip(): description})
        
        except Exception as e:
            print(f"Error: {e}")

        finally:
            os.unlink(filepath)
        
    return patches_info
 



print(globals()[sys.argv[1]](*sys.argv[2:]))

