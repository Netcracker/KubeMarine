import json
import logging
import os
import platform
import subprocess
import sys
import tempfile
import requests
import yaml

# TODO
# update /etc/kubemarine/procedures/latest_dump/version every migrate even when no patches ?
# software upgrade patches --describe doesn't print exact 3rd party version, only patched k8s
# to use kubemarine config feature to avoid migration to not supported k8s in migrated kubemarine



MigrationProcedure: dict = {
    #    "v0.26.0":{"procedure":"",
    #               "patches":[
    #                   {"patch0":
    #                    f"Description0"},
    #               "env":"docker"}
}

def patches_to_versions() -> list:
    return

class Filepath:
    """manages environment {type} and a {path} to kubemarine executable"""

    SUPPORTED_ENVS: list = ["git", "pip", "bin", "docker", "brew"]

    def __init__(self, env:str = "bin", path:str = "") -> None:
        if env not in self.SUPPORTED_ENVS:
            raise ValueError(f"Env {env} is not supported. Supperted envs {self.SUPPORTED_ENVS}")
        self.type = env
        self.path = path

def distant_migrate(MigrationProcedure:dict) -> int:
    """ run migrate_kubemarine according to {MigrationProcedure} """
    for version,details in MigrationProcedure.items():
        patches = details.get("patches", [])
        if patches:
            procedure_yaml  = details.get("procedure","")

            env_type = details.get("env", "bin")  # bin is default
            
            env = get_kubemarine_env(version, Filepath(env_type))
            logging.debug(f"{version}, {env.path}, {get_patches_info(env)}, {procedure_yaml or ''} ")
            #input()  
            
            if procedure_yaml:
                with open("procedure.yaml", "w") as file:
                    file.write(procedure_yaml)
            
            try:
                patch_names = []
                for patch in patches: 
                    patch_names.extend(patch.keys())

                process = subprocess.Popen([env.path, "migrate_kubemarine","--force-apply", ",".join(patch_names), "procedure.yaml" if procedure_yaml else ""],
                                        stdout=subprocess.PIPE, text=True) # TODO --force-apply 
                
                if process.stdout is not None:
                    for line in process.stdout:
                        logging.info(line.strip())
                
                exit_status = process.wait()
            finally:
                os.remove("procedure.yaml") if os.path.exists("procedure.yaml") else None

            return exit_status
        else:
            logging.warning(f"No patches. Skipping migration for {version}")    
    
    return True


def get_kubemarine_env(version:str, env:Filepath) -> Filepath:
    """ Get apropriate version env and set path to it in {env} """

    if env.type == "bin":

        filename = f"kubemarine-{'macos11' if platform.system().lower() == 'darwin' else 'linux'}-{platform.machine().lower()}"
        path = os.path.join(tempfile.gettempdir(), filename + f"-{version}") #TODO caching 

        if os.path.exists(path) and os.stat(path).st_mode | 0o111: # Сaching TODO to rework to use existing downloaded versions
            env.path = path
            return env

        try:
            # Download the file
            response = requests.get(f"https://github.com/Netcracker/KubeMarine/releases/download/{version}/{filename}")
            response.raise_for_status()

            with open(path, "wb") as file:
                file.write(response.content)

            os.chmod(path, os.stat(path).st_mode | 0o111)  # Set executable
            env.path = path
            return env
        except Exception as e:
            logging.error(f"Error: {e}")
    elif env.type == "git":
        
        process = subprocess.run(['git', "checkout", version],stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
      
        if process.returncode == os.EX_OK:
            env.path = "bin/kubemarine"
            return env
    
    return env


def get_patches_info(env:Filepath) -> dict:
    patches_info:dict = {"patches": []}
    
    if not env or not env.path:
        logging.error("Environment or path is not provided ")
        return patches_info

    try:
        # Assuming subprocess.run returns the patches list
        patches_list = subprocess.run([env.path, "migrate_kubemarine", "--list"],capture_output=True, text=True
                                        ).stdout.splitlines()
        if "No patches available." in patches_list:
            patches_list = []
        elif "Available patches list:" in patches_list:
            patches_list.remove("Available patches list:")

        logging.debug(patches_list)
        for patch in patches_list:
            description = subprocess.run([env.path, "migrate_kubemarine", "--describe", patch],capture_output=True, text=True
                                            ).stdout.strip()
            patches_info["patches"].append({patch.strip(): description})
    except Exception as e:
        logging.error(f"Error: {e}")
        return {}

    return patches_info


def list_versions( old_version: str = "", new_version: str = "", patches_path:str = "patches.json") -> dict:
    """@returns: MigrationProcedure dict"""

    MigrationProcedure: dict = {}

    patches = dict(json.load(open(patches_path,'r'))) # initialization from patch list
    KubemarineVersions = list(patches.keys())

    if not old_version:
        old_version = KubemarineVersions[0]

    if not new_version:
        new_version = KubemarineVersions[-1]
    
    index_from = KubemarineVersions.index(old_version) if old_version in KubemarineVersions else None
    index_to = KubemarineVersions.index(new_version) if new_version in KubemarineVersions else None

    # error handling
    if ( index_from is None or index_to is None ) or  index_from > index_to:
        logging.warning(f"Not supported combination of versions {old_version}, {new_version} or outdated version list {KubemarineVersions}")
        return {}

    ## get the patch list
    for version in KubemarineVersions[index_from:index_to + 1]:
        logging.info(f"Iterating {version}")
        MigrationProcedure[version] = patches[version]
        MigrationProcedure[version]["procedure"] = "" #TODO to have it generated in patches.json already
        MigrationProcedure[version]["env"] = "bin"    #TODO to have it generated in patches.json already

    return MigrationProcedure

def generate_patches_list(old_version: str, new_version: str, env:str = "bin") -> dict:   # TODO temporary
    """@returns: MigrationProcedure dict"""
    KubemarineVersions: list = [ "0.3.0", "0.4.0", "0.5.0", "0.6.0", "0.7.0", "0.7.1", "0.8.0", "0.9.0", "0.10.0", "0.11.0",
                            "0.11.1", "0.12.0", "0.12.1", "0.13.0", "0.13.1", "0.14.0", "0.15.0", "0.15.1", "0.16.0", "0.17.0",
                            "0.18.0", "0.18.1", "0.18.2", "0.19.0", "0.20.0", "0.21.0", "0.21.1", "0.22.0", "v0.23.0",
                            "v0.24.1", "v0.25.0", "v0.25.1", "v0.26.0", "v0.27.0", "v0.28.0", "v0.28.1"
]  # TODO to  get from github/gitlab/git/custom/file?
    
    index_from = KubemarineVersions.index(old_version) if old_version in KubemarineVersions else None
    index_to = KubemarineVersions.index(new_version) if new_version in KubemarineVersions else None

    ## get the patch list and  migration procedure
    for version in KubemarineVersions[index_from:index_to + 1]:
        logging.info(f"Iterating {version}")
        filepath = get_kubemarine_env(version, Filepath(env))
        logging.debug(filepath.path)
        if filepath:
            MigrationProcedure[version] = get_patches_info(filepath)
            MigrationProcedure[version]["procedure"] = ""


    return MigrationProcedure

if __name__ == "__main__": #temporary TODO to rework 
    # format: yaml/json, function name, parameters ...
    logging.root.setLevel(logging.DEBUG)

    if 'json' in sys.argv[1]:
        if sys.argv[2] in 'distant_migrate':
            sys.argv[3] = json.load(open(sys.argv[3],'r'))
        print(json.dumps(globals()[sys.argv[2]](*sys.argv[3:])))
    elif 'yaml' in sys.argv[1]:
        if sys.argv[2] in 'distant_migrate':
            sys.argv[3] = yaml.safe_load(open(sys.argv[3],"r"))
        print(yaml.safe_dump(globals()[sys.argv[2]](*sys.argv[3:]),sort_keys=False))
    else:
        print(f"Error: incorrect {sys.argv[1]}", file=sys.stderr)
