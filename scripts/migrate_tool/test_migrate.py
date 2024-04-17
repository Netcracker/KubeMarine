# mypy: ignore-errors
from migrate import *
import pytest


logging.root.setLevel(logging.DEBUG)
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.DEBUG) 
logging.root.addHandler(console_handler)

def test_list_version():
    assert list_versions("v0.25.1","v0.26.0")
    assert list_versions("v0.25.1")
    assert list_versions()
    assert not list_versions("0.17.0","not exist version")
    assert not list_versions("not exist version")
    assert not list_versions("0.18.0","0.17.0")
    assert not list_versions(1,"")
    assert not list_versions(1,2)
    assert not list_versions("1","2")

def test_get_kubemarine_env():
    assert get_kubemarine_env("v0.28.0",Filepath("bin")).path != ""
    assert get_kubemarine_env("none",Filepath("bin")).path == ""
    with pytest.raises(BaseException):
        get_kubemarine_env("v0.28.0",Filepath("None"))

def test_get_patches_info():
    get_kubemarine_env("v0.28.0",Filepath("bin")) 
    get_kubemarine_env("v0.27.0",Filepath("bin"))
    
    assert (get_patches_info(Filepath("bin",
        f"{tempfile.gettempdir()}/kubemarine-"
        f"{'macos11' if platform.system().lower() == 'darwin' else 'linux'}-"
        f"{platform.machine().lower()}-v0.28.0")).get("patches")) #some patches
    
    assert not get_patches_info(Filepath("bin",
        f"{tempfile.gettempdir()}/kubemarine-"
        f"{'macos11' if platform.system().lower() == 'darwin' else 'linux'}-"
        f"{platform.machine().lower()}-v0.27.0")).get("patches") # no patches

    assert not get_patches_info(Filepath("bin","none")) 
    assert not get_patches_info(Filepath("bin","/bin/ls")).get("patches")
    

