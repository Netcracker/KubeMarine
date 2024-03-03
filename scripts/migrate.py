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


def distant_migrate(MigrationProcedure):
    MigrationProcedure = json.loads(MigrationProcedure)
    for version in MigrationProcedure:
        if MigrationProcedure[version]["patches"]:
            path = download_kubemarine(version, "bin")  # TODO check cache
            print(version, path, get_patches_info(path))  #
            if MigrationProcedure[version]["procedure"]:
                with open("procedure.yaml", "w") as file:
                    file.write(MigrationProcedure[version]["procedure"])
            process = subprocess.Popen(
                [path, "migrate_kubemarine", "procedure.yaml"],
                stdout=subprocess.PIPE, text=True,
            )
            for line in process.stdout:
                print(line.strip())
            process.wait()
            os.remove("procedure.yaml") if os.path.exists("procedure.yaml") else None
        else:
            print(f"No patches. Skipping migration for {version}")

    #    clusteryaml = migrate_kubemarine(toVersion,
    #                                     env,
    #                                     MigrationProcedure[toVersion]["procedure"],
    #                                     MigrationProcedure[toVersion]["patches"],
    #                                     clusteryaml)


def download_kubemarine(version, env):
    filename = f"kubemarine-{'macos11' if platform.system().lower() == 'darwin' else 'linux'}-{platform.machine().lower()}"
    filepath = os.path.join(tempfile.gettempdir(), filename + f"-{version}")

    if env in "bin":
        try:
            # Download the file
            response = requests.get(
                f"https://github.com/Netcracker/KubeMarine/releases/download/{version}/{filename}"
            )
            response.raise_for_status()

            with open(filepath, "wb") as file:
                file.write(response.content)

            os.chmod(filepath, os.stat(filepath).st_mode | 0o111)  # Set executable
            return filepath
        except Exception as e:
            print(f"Error: {e}")
            return None
    return None


def get_patches_info(filepath):
    patches_info = {"patches": []}

    try:
        if filepath:
            # Assuming subprocess.run returns the patches list
            patches_list = subprocess.run(
                [filepath, "migrate_kubemarine", "--list"],
                capture_output=True, text=True,
            ).stdout.splitlines()
            if "No patches available." in patches_list:
                patches_list = []
            else:
                patches_list.remove("Available patches list:")

            for patch in patches_list:
                description = subprocess.run(
                    [filepath, "migrate_kubemarine", "--describe", patch],
                    capture_output=True, text=True,
                ).stdout.strip()
                patches_info["patches"].append({patch.strip(): description})
    except Exception as e:
        print(f"Error: {e}")

    return patches_info


def list(old_version: str = "", new_version: str = "") -> dict:
    index_from = (
        KubemarineVersions.index(old_version)
        if old_version in KubemarineVersions
        else 0
    )
    index_to = (
        KubemarineVersions.index(new_version) + 1
        if new_version in KubemarineVersions
        else -1
    )

    ## get the patch list and  migration procedure
    for version in KubemarineVersions[index_from:index_to]:
        filepath = download_kubemarine(version, "bin")
        MigrationProcedure[version] = get_patches_info(filepath)

    return MigrationProcedure


# function name, parameters ...
print(json.dumps(globals()[sys.argv[1]](*sys.argv[2:])))
