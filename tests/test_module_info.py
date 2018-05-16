import pytest
from routersploit.core.exploit.utils import iter_modules


@pytest.mark.parametrize("exploit", iter_modules("./routersploit/modules/exploit"))
def test_exploit_info(exploit):
    info = exploit._Exploit__info__

    assert isinstance(info, dict)

    assert "name" in info
    assert isinstance(info["name"], str)

    assert "description" in info 
    assert isinstance(info["description"], str)

    assert "authors" in info
    assert isinstance(info["authors"], tuple)

    assert "references" in info
    assert isinstance(info["references"], tuple)

    assert "devices" in info
    assert isinstance(info["devices"], tuple)


@pytest.mark.parametrize("creds", iter_modules("./routersploit/modules/creds"))
def test_exploit_info(creds):
    info = creds._Exploit__info__

    assert isinstance(info, dict)

    assert "name" in info
    assert isinstance(info["name"], str)

    assert "description" in info 
    assert isinstance(info["description"], str)

    assert "authors" in info
    assert isinstance(info["authors"], tuple)

    assert "devices" in info
    assert isinstance(info["devices"], tuple)


@pytest.mark.parametrize("scanner", iter_modules("./routersploit/modules/scanners"))
def test_exploit_info(scanner):
    info = scanner._Exploit__info__

    assert isinstance(info, dict)

    assert "name" in info
    assert isinstance(info["name"], str)

    assert "description" in info 
    assert isinstance(info["description"], str)

    assert "authors" in info
    assert isinstance(info["authors"], tuple)

    assert "devices" in info
    assert isinstance(info["devices"], tuple)
