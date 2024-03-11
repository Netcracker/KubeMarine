import json
import os
import platform
import subprocess
import sys
import tempfile
import requests
import yaml

# TODO
# update /etc/kubemarine/procedures/latest_dump/version every migrate even when no patches
# software upgrade patches --describe doesn't print exact 3rd party version, only patched k8s
# to use kubemarine config feature to avoid migration to not supported k8s in migrated kubemarine

KubemarineVersions: list = [
    "0.17.0",
    "0.18.0",
    "0.18.1",
    "0.18.2",
    "0.19.0",
    "0.20.0",
    "0.21.0",
    "0.21.1",
    "0.22.0",
    "v0.23.0",
    "v0.24.1",
    "v0.25.0",
    "v0.25.1",
    "v0.26.0",
    "v0.27.0",
]  # TODO to  get from github/gitlab/git/custom/file?

Envs: list = ["src", "pip", "bin", "docker", "brew"]

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


def distant_migrate(MigrationProcedure:dict):

    MigrationProcedure = json.loads(MigrationProcedure)
    for version in MigrationProcedure:
        if MigrationProcedure[version]["patches"]:
            procedure_yaml  = False
            if MigrationProcedure[version].get("procedure") and MigrationProcedure[version]["procedure"]:
                procedure_yaml  = True
            path = get_kubemarine_env(version, "bin")
            print(version, path, get_patches_info(path), MigrationProcedure[version]["procedure"] if procedure_yaml else "" )  #
            input()
            if procedure_yaml:
                with open("procedure.yaml", "w") as file:
                    file.write(MigrationProcedure[version]["procedure"])

            process = subprocess.Popen([path, "migrate_kubemarine", "procedure.yaml" if procedure_yaml else ""],stdout=subprocess.PIPE, text=True,)
            for line in process.stdout:
                print(line.strip())
            process.wait()
            os.remove("procedure.yaml") if os.path.exists("procedure.yaml") else None
        else:
            print(f"No patches. Skipping migration for {version}")


def get_kubemarine_env(version, env):

    if env in "bin":

        filename = f"kubemarine-{'macos11' if platform.system().lower() == 'darwin' else 'linux'}-{platform.machine().lower()}"
        filepath = os.path.join(tempfile.gettempdir(), filename + f"-{version}")

        if os.path.exists(filepath) and os.stat(filepath).st_mode | 0o111: # Сaching 
            return filepath

        try:
            # Download the file
            response = requests.get(f"https://github.com/Netcracker/KubeMarine/releases/download/{version}/{filename}")
            response.raise_for_status()

            with open(filepath, "wb") as file:
                file.write(response.content)

            os.chmod(filepath, os.stat(filepath).st_mode | 0o111)  # Set executable
            return filepath
        except Exception as e:
            print(f"Error: {e}", file=sys.stderr)
            return None
    return None


def get_patches_info(filepath):
    patches_info = {"patches": []}

    try:
        if filepath:
            # Assuming subprocess.run returns the patches list
            patches_list = subprocess.run([filepath, "migrate_kubemarine", "--list"],capture_output=True, text=True,
                                          ).stdout.splitlines()
            if "No patches available." in patches_list:
                patches_list = []
            else:
                patches_list.remove("Available patches list:")

            for patch in patches_list:
                description = subprocess.run([filepath, "migrate_kubemarine", "--describe", patch],capture_output=True, text=True,
                                             ).stdout.strip()
                patches_info["patches"].append({patch.strip(): description})
    except Exception as e:
        print(f"Error: {e}")

    return patches_info


def list_versions(old_version: str =  KubemarineVersions[0], new_version: str = KubemarineVersions[-1]) -> dict:
    index_from = KubemarineVersions.index(old_version) if old_version in KubemarineVersions else None
    index_to = KubemarineVersions.index(new_version) if new_version in KubemarineVersions else None

    # error handling
    if ( index_from is None or index_to is None ) or  index_from > index_to:
        print(f"Not supported combination of versions {old_version}, {new_version} or outdated version list {KubemarineVersions}", file=sys.stderr)
        return {}

    ## get the patch list and  migration procedure
    for version in KubemarineVersions[index_from:index_to + 1]:
        filepath = get_kubemarine_env(version, "bin")
        MigrationProcedure[version] = get_patches_info(filepath)

    return MigrationProcedure

if __name__ == "__main__":
    # function name, parameters ...
    print(json.dumps(globals()[sys.argv[1]](*sys.argv[2:])))
