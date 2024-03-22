import json
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

KubemarineVersions: list = [ "0.3.0", "0.4.0", "0.5.0", "0.6.0", "0.7.0", "0.7.1", "0.8.0", "0.9.0", "0.10.0", "0.11.0",
                            "0.11.1", "0.12.0", "0.12.1", "0.13.0", "0.13.1", "0.14.0", "0.15.0", "0.15.1", "0.16.0", "0.17.0",
                            "0.18.0", "0.18.1", "0.18.2", "0.19.0", "0.20.0", "0.21.0", "0.21.1", "0.22.0", "v0.23.0",
                            "v0.24.1", "v0.25.0", "v0.25.1", "v0.26.0", "v0.27.0", "v0.28.0"
]  # TODO to  get from github/gitlab/git/custom/file?

MigrationProcedure: dict = {
    #    "v0.25.1":{"procedure":"",
    #               "patches":[],
    #               "env":"bin"}
    #    "v0.26.0":{"procedure":"",
    #               "patches":[
    #                   {"patch0":
    #                    f"Description0"},
    #               "env":"docker"}
}

class Filepath:
    Envs: list = ["git", "pip", "bin", "docker", "brew"]

    def __init__(self,env="bin",path=""):
        if env not in self.Envs:
            raise f"Env {self.Envs} is not supported."
        self.type = env
        self.path = path


def distant_migrate(MigrationProcedure:dict):

    for version in MigrationProcedure:
        if MigrationProcedure[version]["patches"]:
                procedure_yaml  = False
                if MigrationProcedure[version].get("procedure") and MigrationProcedure[version]["procedure"]:
                    procedure_yaml  = True

                if not MigrationProcedure[version].get("env") or MigrationProcedure[version]["env"] in "bin": #TODO default is bin only
                    path = get_kubemarine_env(version, "bin")
                    print(version, path, get_patches_info(path), MigrationProcedure[version]["procedure"] if procedure_yaml else "" )  #
                    input()
                    if procedure_yaml:
                        with open("procedure.yaml", "w") as file:
                            file.write(MigrationProcedure[version]["procedure"])

                    process = subprocess.Popen([path, "migrate_kubemarine", "procedure.yaml" if procedure_yaml else ""],stdout=subprocess.PIPE, text=True,)
                    for line in process.stdout:
                        print(line.strip())
                    exit_status = process.wait()
                    os.remove("procedure.yaml") if os.path.exists("procedure.yaml") else None
                    return exit_status
        else:
            print(f"No patches. Skipping migration for {version}")


def get_kubemarine_env(version, env:Filepath):

    if env.type == "bin":

        filename = f"kubemarine-{'macos11' if platform.system().lower() == 'darwin' else 'linux'}-{platform.machine().lower()}"
        env.path = os.path.join(tempfile.gettempdir(), filename + f"-{version}") #TODO caching 

        if os.path.exists(env.path) and os.stat(env.path).st_mode | 0o111: # Сaching TODO to rework to use existing downloaded versions
            return env

        try:
            # Download the file
            response = requests.get(f"https://github.com/Netcracker/KubeMarine/releases/download/{version}/{filename}")
            response.raise_for_status()

            with open(env.path, "wb") as file:
                file.write(response.content)

            os.chmod(env.path, os.stat(env.path).st_mode | 0o111)  # Set executable
            return env
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            return None
    elif env.type == "git":
        process = subprocess.Popen(['git', "checkout", version],stdout=subprocess.PIPE, text=True,)
        for line in process.stdout:
            print(line.strip())
        
        if process.wait():
            env.path = "kubemarine"
        
    return None


def get_patches_info(env:Filepath):
    patches_info = {"patches": []}

    try:
        if env and env.path:
            # Assuming subprocess.run returns the patches list
            patches_list = subprocess.run([env.path, "migrate_kubemarine", "--list"],capture_output=True, text=True,
                                          ).stdout.splitlines()
            if "No patches available." in patches_list:
                patches_list = []
            elif "Available patches list:" in patches_list:
                patches_list.remove("Available patches list:")

            for patch in patches_list:
                description = subprocess.run([env.path, "migrate_kubemarine", "--describe", patch],capture_output=True, text=True,
                                             ).stdout.strip()
                patches_info["patches"].append({patch.strip(): description})
    except Exception as e:
        print(f"Error: {e}")
        return {}

    return patches_info


def list_versions(old_version: str =  KubemarineVersions[0], new_version: str = KubemarineVersions[-1], env="bin") -> dict:
    index_from = KubemarineVersions.index(old_version) if old_version in KubemarineVersions else None
    index_to = KubemarineVersions.index(new_version) if new_version in KubemarineVersions else None

    # error handling
    if ( index_from is None or index_to is None ) or  index_from > index_to:
        print(f"Not supported combination of versions {old_version}, {new_version} or outdated version list {KubemarineVersions}", file=sys.stderr)
        return {}

    ## get the patch list and  migration procedure
    for version in KubemarineVersions[index_from:index_to + 1]:
        filepath = get_kubemarine_env(version, Filepath(env))
        if filepath:
            MigrationProcedure[version] = get_patches_info(filepath)

    return MigrationProcedure

if __name__ == "__main__":
    # format: yaml/json, function name, parameters ...
    
    if 'json' in sys.argv[1]:
        if sys.argv[2] in 'distant_migrate':
            sys.argv[3] = json.load(open(sys.argv[3],'r'))
        print(json.dumps(globals()[sys.argv[2]](*sys.argv[3:])))
    elif 'yaml' in sys.argv[1]:
        if sys.argv[2] in 'distant_migrate':
            sys.argv[3] = yaml.safe_load(open(sys.argv[3],"r"))
        print(yaml.dump(globals()[sys.argv[2]](*sys.argv[3:])))
    else:
        print(f"Error: incorrect {sys.argv[1]}", file=sys.stderr)
