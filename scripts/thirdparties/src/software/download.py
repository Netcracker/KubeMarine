import os
from kubemarine import thirdparties
from ..shell import curl, TEMP_FILE, SYNC_CACHE

# pylint: disable=bad-builtin

def resolve_local_path(destination: str, version: str) -> str:
    filename = f"{destination.split('/')[-1]}-{version}"
    target_file = os.path.join(SYNC_CACHE, filename)
    if os.path.exists(target_file):
        return target_file

    source = thirdparties.get_default_thirdparty_source(destination, version, in_public=True)

    print(f"Downloading thirdparty {destination} of version {version} from {source}")
    curl(source, TEMP_FILE)
    os.rename(TEMP_FILE, target_file)

    return target_file