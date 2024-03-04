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
    
