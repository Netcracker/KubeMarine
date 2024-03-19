from migrate import *

def test_list_version():
    assert list_versions("v0.25.1","v0.26.0")
    assert list_versions()
    assert list_versions("v0.25.1")
    assert list_versions(KubemarineVersions[-1])
    assert not list_versions("0.17.0","not exist version")
    assert not list_versions("not exist version")
    assert not list_versions("0.18.0","0.17.0")
    assert not list_versions(1,"")
    assert not list_versions(1,2)
    assert not list_versions("1","2")

def test_get_patches_info():
    assert get_patches_info("/tmp/kubemarine-linux-x86_64-v0.28.0").get("patches") # some patches
    assert not get_patches_info("/tmp/kubemarine-linux-x86_64-v0.27.0").get("patches") # no patches
    assert not get_patches_info("no file") 
    assert not get_patches_info("/bin/ls").get("patches")
    

def test_get_kubemarine_env():
    assert get_kubemarine_env("v0.28.0","bin")
    assert not get_kubemarine_env("none","bin")
    assert not get_kubemarine_env("v0.28.0","None")

    
