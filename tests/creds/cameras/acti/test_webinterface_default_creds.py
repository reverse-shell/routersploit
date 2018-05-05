from flask import request
from routersploit.modules.creds.cameras.acti.webinterface_http_form_default_creds import Exploit


def apply_response(*args, **kwargs):
    if request.method == "GET":
        return "<TEST>Password</TEST>", 200
    elif request.method == "POST":
        return "TEST", 200


def test_check_success(target):
    """ Test scenario - successful check """

    cgi_mock = target.get_route_mock("/video.htm", methods=["GET", "POST"])
    cgi_mock.side_effect = apply_response

    exploit = Exploit()
    exploit.target = target.host
    exploit.port = target.port
