from __future__ import print_function

import atexit
import itertools
import pkgutil
import os
import sys
import getopt
import traceback
from collections import Counter

from future.builtins import input

from routersploit.core.exploit.exceptions import RoutersploitException
from routersploit.core.exploit.utils import (
    index_modules,
    pythonize_path,
    humanize_path,
    import_exploit,
    stop_after,
    module_required,
    MODULES_DIR,
    WORDLISTS_DIR,
)
from routersploit.core.exploit.printer import (
    print_info,
    print_success,
    print_error,
    print_status,
    print_table,
    pprint_dict_in_order,
    PrinterThread,
    printer_queue
)
from routersploit.core.exploit.exploit import GLOBAL_OPTS
from routersploit.core.exploit.payloads import BasePayload

import readline
if sys.platform == "win32":
    import colorama
    colorama.init(autoreset = True)

def is_libedit():
    return "libedit" in (readline.__doc__ or "")


class BaseInterpreter(object):
    history_file = os.path.expanduser("~/.history")
    history_length = 100
    global_help = ""

    def __init__(self):
        self.setup()
        self.banner = ""

    def setup(self):
        """ Initialization of third-party libraries

        Setting interpreter history.
        Setting appropriate completer function.

        :return:
        """
        if not os.path.exists(self.history_file):
            with open(self.history_file, "a+") as history:
                if is_libedit():
                    history.write("_HiStOrY_V2_\n\n")

        readline.read_history_file(self.history_file)
        readline.set_history_length(self.history_length)
        atexit.register(readline.write_history_file, self.history_file)

        readline.parse_and_bind("set enable-keypad on")

        readline.set_completer(self.complete)
        readline.set_completer_delims(" \t\n;")
        if is_libedit():
            readline.parse_and_bind("bind ^I rl_complete")
        else:
            readline.parse_and_bind("tab: complete")

    def parse_line(self, line):
        """ Split line into command and argument.

        :param line: line to parse
        :return: (command, argument, named_arguments)
        """
        kwargs = dict()
        command, _, arg = line.strip().partition(" ")
        args = arg.strip().split()
        for word in args:
            if '=' in word:
                (key, value) = word.split('=', 1)
                kwargs[key.lower()] = value
                arg = arg.replace(word, '')
        return command, ' '.join(arg.split()), kwargs

    @property
    def prompt(self):
        """ Returns prompt string """
        return ">>>"

    def get_command_handler(self, command):
        """ Parsing command and returning appropriate handler.

        :param command: command
        :return: command_handler
        """
        try:
            command_handler = getattr(self, "command_{}".format(command))
        except AttributeError:
            raise RoutersploitException("Unknown command: '{}'".format(command))

        return command_handler

    def start(self):
        """ Routersploit main entry point. Starting interpreter loop. """

        print_info(self.banner)
        printer_queue.join()
        while True:
            try:
                command, args, kwargs = self.parse_line(input(self.prompt))
                if not command:
                    continue
                command_handler = self.get_command_handler(command)
                command_handler(args, **kwargs)
            except RoutersploitException as err:
                print_error(err)
            except (EOFError, KeyboardInterrupt, SystemExit):
                print_info()
                print_error("RouterSploit stopped")
                break
            finally:
                printer_queue.join()

    def complete(self, text, state):
        """Return the next possible completion for 'text'.

        If a command has not been entered, then complete against command list.
        Otherwise try to call complete_<command> to get list of completions.
        """
        if state == 0:
            original_line = readline.get_line_buffer()
            line = original_line.lstrip()
            stripped = len(original_line) - len(line)
            start_index = readline.get_begidx() - stripped
            end_index = readline.get_endidx() - stripped

            if start_index > 0:
                cmd, args, _ = self.parse_line(line)
                if cmd == "":
                    complete_function = self.default_completer
                else:
                    try:
                        complete_function = getattr(self, "complete_" + cmd)
                    except AttributeError:
                        complete_function = self.default_completer
            else:
                complete_function = self.raw_command_completer

            self.completion_matches = complete_function(text, line, start_index, end_index)

        try:
            return self.completion_matches[state]
        except IndexError:
            return None

    def commands(self, *ignored):
        """ Returns full list of interpreter commands.

        :param ignored:
        :return: full list of interpreter commands
        """
        return [command.rsplit("_").pop() for command in dir(self) if command.startswith("command_")]

    def raw_command_completer(self, text, line, start_index, end_index):
        """ Complete command w/o any argument """
        return [command for command in self.suggested_commands() if command.startswith(text)]

    def default_completer(self, *ignored):
        return []

    def suggested_commands(self):
        """ Entry point for intelligent tab completion.

        Overwrite this method to suggest suitable commands.

        :return: list of suitable commands
        """
        return self.commands()


class RoutersploitInterpreter(BaseInterpreter):
    history_file = os.path.expanduser("~/.rsf_history")
    global_help = """Global commands:
    help                        Print this help menu
    use <module>                Select a module for usage
    exec <shell command> <args> Execute a command in a shell
    search <search term>        Search for appropriate module
    exit                        Exit RouterSploit"""

    module_help = """Module commands:
    run                                 Run the selected module with the given options
    back                                De-select the current module
    set <option name> <option value>    Set an option for the selected module
    setg <option name> <option value>   Set an option for all of the modules
    unsetg <option name>                Unset option that was set globally
    show [info|options|devices]         Print information, options, or target devices for a module
    check                               Check if a given target is vulnerable to a selected module's exploit"""

    def __init__(self):
        super(RoutersploitInterpreter, self).__init__()
        PrinterThread().start()

        self.current_module = None
        self.raw_prompt_template = None
        self.module_prompt_template = None
        self.prompt_hostname = "rsf"
        self.show_sub_commands = ("info", "options", "advanced", "devices", "all", "encoders", "creds", "exploits", "scanners", "wordlists")
        self.search_sub_commands = ("type", "device", "language", "payload", "vendor")

        self.global_commands = sorted(["use ", "exec ", "help", "exit", "show ", "search "])
        self.module_commands = ["run", "back", "set ", "setg ", "check"]
        self.module_commands.extend(self.global_commands)
        self.module_commands.sort()

        self.modules = index_modules()
        self.modules_count = Counter()
        self.modules_count.update([module.split('.')[0] for module in self.modules])
        self.main_modules_dirs = [module for module in os.listdir(MODULES_DIR) if not module.startswith("__")]

        self.__parse_prompt()

        self.banner = """ ______            _            _____       _       _ _
 | ___ \\          | |          /  ___|     | |     (_) |
 | |_/ /___  _   _| |_ ___ _ __\\ `--. _ __ | | ___  _| |_
 |    // _ \\| | | | __/ _ \\ '__|`--. \\ '_ \\| |/ _ \\| | __|
 | |\\ \\ (_) | |_| | ||  __/ |  /\\__/ / |_) | | (_) | | |_
 \\_| \\_\\___/ \\__,_|\\__\\___|_|  \\____/| .__/|_|\\___/|_|\\__|
                                     | |
       Exploitation Framework for    |_|    by Threat9
            Embedded Devices

 Codename   : I Knew You Were Trouble
 Version    : 3.4.1
 Homepage   : https://www.threat9.com - @threatnine
 Join Slack : https://www.threat9.com/slack

 Join Threat9 Beta Program - https://www.threat9.com

 Exploits: {exploits_count} Scanners: {scanners_count} Creds: {creds_count} Generic: {generic_count} Payloads: {payloads_count} Encoders: {encoders_count}
""".format(exploits_count=self.modules_count["exploits"],
           scanners_count=self.modules_count["scanners"],
           creds_count=self.modules_count["creds"],
           generic_count=self.modules_count["generic"],
           payloads_count=self.modules_count["payloads"],
           encoders_count=self.modules_count["encoders"])

    def __parse_prompt(self):
        raw_prompt_default_template = "\001\033[4m\002{host}\001\033[0m\002 > "
        raw_prompt_template = os.getenv("RSF_RAW_PROMPT", raw_prompt_default_template).replace('\\033', '\033')
        self.raw_prompt_template = raw_prompt_template if '{host}' in raw_prompt_template else raw_prompt_default_template

        module_prompt_default_template = "\001\033[4m\002{host}\001\033[0m\002 (\001\033[91m\002{module}\001\033[0m\002) > "
        module_prompt_template = os.getenv("RSF_MODULE_PROMPT", module_prompt_default_template).replace('\\033', '\033')
        self.module_prompt_template = module_prompt_template if all(map(lambda x: x in module_prompt_template, ['{host}', "{module}"])) else module_prompt_default_template

    def __handle_if_noninteractive(self, argv):
        """ Keep old method for backward compat only """
        self.nonInteractive(argv)

    def nonInteractive(self, argv):
        """ Execute specific command and return result without launching the interactive CLI

        :return:

        """
        module = ""
        set_opts = []

        try:
            opts, args = getopt.getopt(argv[1:], "hm:s:", ["help=", "module=", "set="])
        except getopt.GetoptError:
            print_info("{} -m <module> -s \"<option> <value>\"".format(argv[0]))
            printer_queue.join()
            return

        for opt, arg in opts:
            if opt in ("-h", "--help"):
                print_info("{} -m <module> -s \"<option> <value>\"".format(argv[0]))
                printer_queue.join()
                return
            elif opt in ("-m", "--module"):
                module = arg
            elif opt in ("-s", "--set"):
                set_opts.append(arg)

        if not len(module):
            print_error('A module is required when running non-interactively')
            printer_queue.join()
            return

        self.command_use(module)

        for opt in set_opts:
            self.command_set(opt)

        self.command_exploit()

        # Wait for results if needed
        printer_queue.join()

        return

    @property
    def module_metadata(self):
        return getattr(self.current_module, "_{}__info__".format(self.current_module.__class__.__name__))

    @property
    def prompt(self):
        """ Returns prompt string based on current_module attribute.

        Adding module prefix (module.name) if current_module attribute is set.

        :return: prompt string with appropriate module prefix.
        """
        if self.current_module:
            try:
                return self.module_prompt_template.format(host=self.prompt_hostname, module=self.module_metadata['name'])
            except (AttributeError, KeyError):
                return self.module_prompt_template.format(host=self.prompt_hostname, module="UnnamedModule")
        else:
            return self.raw_prompt_template.format(host=self.prompt_hostname)

    def available_modules_completion(self, text):
        """ Looking for tab completion hints using setup.py entry_points.

        May need optimization in the future!

        :param text: argument of 'use' command
        :return: list of tab completion hints
        """
        text = pythonize_path(text)
        all_possible_matches = filter(lambda x: x.startswith(text), self.modules)
        matches = set()
        for match in all_possible_matches:
            head, sep, tail = match[len(text):].partition('.')
            if not tail:
                sep = ""
            matches.add("".join((text, head, sep)))
        return list(map(humanize_path, matches))  # humanize output, replace dots to forward slashes

    def suggested_commands(self):
        """ Entry point for intelligent tab completion.

        Based on state of interpreter this method will return intelligent suggestions.

        :return: list of most accurate command suggestions
        """
        if self.current_module and GLOBAL_OPTS:
            return sorted(itertools.chain(self.module_commands, ("unsetg ",)))
        elif self.current_module:
            return self.module_commands
        else:
            return self.global_commands

    def command_back(self, *args, **kwargs):
        self.current_module = None

    def command_use(self, module_path, *args, **kwargs):
        module_path = pythonize_path(module_path)
        module_path = ".".join(("routersploit", "modules", module_path))
        # module_path, _, exploit_name = module_path.rpartition('.')
        try:
            self.current_module = import_exploit(module_path)()
        except RoutersploitException as err:
            print_error(str(err))

    @stop_after(2)
    def complete_use(self, text, *args, **kwargs):
        if text:
            return self.available_modules_completion(text)
        else:
            return self.main_modules_dirs

    @module_required
    def command_run(self, *args, **kwargs):
        print_status("Running module {}...".format(self.current_module))
        try:
            self.current_module.run()
        except KeyboardInterrupt:
            print_info()
            print_error("Operation cancelled by user")
        except Exception:
            print_error(traceback.format_exc(sys.exc_info()))

    def command_exploit(self, *args, **kwargs):
        self.command_run()

    @module_required
    def command_set(self, *args, **kwargs):
        key, _, value = args[0].partition(" ")
        if key in self.current_module.options:
            setattr(self.current_module, key, value)
            self.current_module.exploit_attributes[key][0] = value

            if kwargs.get("glob", False):
                GLOBAL_OPTS[key] = value
            print_success("{} => {}".format(key, value))
        else:
            print_error("You can't set option '{}'.\n"
                        "Available options: {}".format(key, self.current_module.options))

    @stop_after(2)
    def complete_set(self, text, *args, **kwargs):
        if text:
            return [" ".join((attr, "")) for attr in self.current_module.options if attr.startswith(text)]
        else:
            return self.current_module.options

    @module_required
    def command_setg(self, *args, **kwargs):
        kwargs['glob'] = True
        self.command_set(*args, **kwargs)

    @stop_after(2)
    def complete_setg(self, text, *args, **kwargs):
        return self.complete_set(text, *args, **kwargs)

    @module_required
    def command_unsetg(self, *args, **kwargs):
        key, _, value = args[0].partition(' ')
        try:
            del GLOBAL_OPTS[key]
        except KeyError:
            print_error("You can't unset global option '{}'.\n"
                        "Available global options: {}".format(key, list(GLOBAL_OPTS.keys())))
        else:
            print_success({key: value})

    @stop_after(2)
    def complete_unsetg(self, text, *args, **kwargs):
        if text:
            return [' '.join((attr, "")) for attr in GLOBAL_OPTS.keys() if attr.startswith(text)]
        else:
            return list(GLOBAL_OPTS.keys())

    @module_required
    def get_opts(self, *args):
        """ Generator returning module's Option attributes (option_name, option_value, option_description)

        :param args: Option names
        :return:
        """
        for opt_key in args:
            try:
                opt_description = self.current_module.exploit_attributes[opt_key][1]
                opt_display_value = self.current_module.exploit_attributes[opt_key][0]
                if self.current_module.exploit_attributes[opt_key][2]:
                    continue
            except (KeyError, IndexError, AttributeError):
                pass
            else:
                yield opt_key, opt_display_value, opt_description

    @module_required
    def get_opts_adv(self, *args):
        """ Generator returning module's advanced Option attributes (option_name, option_value, option_description)

        :param args: Option names
        :return:
        """
        for opt_key in args:
            try:
                opt_description = self.current_module.exploit_attributes[opt_key][1]
                opt_display_value = self.current_module.exploit_attributes[opt_key][0]
            except (KeyError, AttributeError):
                pass
            else:
                yield opt_key, opt_display_value, opt_description

    @module_required
    def _show_info(self, *args, **kwargs):
        pprint_dict_in_order(
            self.module_metadata,
            ("name", "description", "devices", "authors", "references"),
        )
        print_info()

    @module_required
    def _show_options(self, *args, **kwargs):
        target_names = ["target", "port", "ssl", "rhost", "rport", "lhost", "lport"]
        target_opts = [opt for opt in self.current_module.options if opt in target_names]
        module_opts = [opt for opt in self.current_module.options if opt not in target_opts]
        headers = ("Name", "Current settings", "Description")

        print_info("\nTarget options:")
        print_table(headers, *self.get_opts(*target_opts))

        if module_opts:
            print_info("\nModule options:")
            print_table(headers, *self.get_opts(*module_opts))

        print_info()

    @module_required
    def _show_advanced(self, *args, **kwargs):
        target_names = ["target", "port", "ssl", "rhost", "rport", "lhost", "lport"]
        target_opts = [opt for opt in self.current_module.options if opt in target_names]
        module_opts = [opt for opt in self.current_module.options if opt not in target_opts]
        headers = ("Name", "Current settings", "Description")

        print_info("\nTarget options:")
        print_table(headers, *self.get_opts(*target_opts))

        if module_opts:
            print_info("\nModule options:")
            print_table(headers, *self.get_opts_adv(*module_opts))

        print_info()

    @module_required
    def _show_devices(self, *args, **kwargs):  # TODO: cover with tests
        try:
            devices = self.current_module._Exploit__info__['devices']

            print_info("\nTarget devices:")
            i = 0
            for device in devices:
                if isinstance(device, dict):
                    print_info("   {} - {}".format(i, device['name']))
                else:
                    print_info("   {} - {}".format(i, device))
                i += 1
            print_info()
        except KeyError:
            print_info("\nTarget devices are not defined")

    @module_required
    def _show_wordlists(self, *args, **kwargs):
        headers = ("Wordlist", "Path")
        wordlists = [(f, "file://{}/{}".format(WORDLISTS_DIR, f)) for f in os.listdir(WORDLISTS_DIR) if f.endswith(".txt")]

        print_table(headers, *wordlists, max_column_length=100)

    @module_required
    def _show_encoders(self, *args, **kwargs):
        if issubclass(self.current_module.__class__, BasePayload):
            encoders = self.current_module.get_encoders()
            if encoders:
                headers = ("Encoder", "Name", "Description")
                print_table(headers, *encoders, max_column_length=100)
                return

        print_error("No encoders available")

    def __show_modules(self, root=''):
        for module in [module for module in self.modules if module.startswith(root)]:
            print_info(module.replace('.', os.sep))

    def _show_all(self, *args, **kwargs):
        self.__show_modules()

    def _show_scanners(self, *args, **kwargs):
        self.__show_modules('scanners')

    def _show_exploits(self, *args, **kwargs):
        self.__show_modules('exploits')

    def _show_creds(self, *args, **kwargs):
        self.__show_modules('creds')

    def command_show(self, *args, **kwargs):
        sub_command = args[0]
        try:
            getattr(self, "_show_{}".format(sub_command))(*args, **kwargs)
        except AttributeError:
            print_error("Unknown 'show' sub-command '{}'. "
                        "What do you want to show?\n"
                        "Possible choices are: {}".format(sub_command, self.show_sub_commands))

    @stop_after(2)
    def complete_show(self, text, *args, **kwargs):
        if text:
            return [command for command in self.show_sub_commands if command.startswith(text)]
        else:
            return self.show_sub_commands

    @module_required
    def command_check(self, *args, **kwargs):
        try:
            result = self.current_module.check()
        except Exception as error:
            print_error(error)
        else:
            if result is True:
                print_success("Target is vulnerable")
            elif result is False:
                print_error("Target is not vulnerable")
            else:
                print_status("Target could not be verified")

    def command_help(self, *args, **kwargs):
        print_info(self.global_help)
        if self.current_module:
            print_info("\n", self.module_help)

    def command_exec(self, *args, **kwargs):
        os.system(args[0])

    def command_search(self, *args, **kwargs):
        mod_type = ''
        mod_detail = ''
        mod_vendor = ''
        existing_modules = [name for _, name, _ in pkgutil.iter_modules([MODULES_DIR])]
        devices = [name for _, name, _ in pkgutil.iter_modules([os.path.join(MODULES_DIR, 'exploits')])]
        languages = [name for _, name, _ in pkgutil.iter_modules([os.path.join(MODULES_DIR, 'encoders')])]
        payloads = [name for _, name, _ in pkgutil.iter_modules([os.path.join(MODULES_DIR, 'payloads')])]

        try:
            keyword = args[0].strip("'\"").lower()
        except IndexError:
            keyword = ''

        if not (len(keyword) or len(kwargs.keys())):
            print_error("Please specify at least search keyword. e.g. 'search cisco'")
            print_error("You can specify options. e.g. 'search type=exploits device=routers vendor=linksys WRT100 rce'")
            return

        for (key, value) in kwargs.items():
            if key == 'type':
                if value not in existing_modules:
                    print_error("Unknown module type.")
                    return
                # print_info(' - Type  :\t{}'.format(value))
                mod_type = "{}.".format(value)
            elif key in ['device', 'language', 'payload']:
                if key == 'device' and (value not in devices):
                    print_error("Unknown exploit type.")
                    return
                elif key == 'language' and (value not in languages):
                    print_error("Unknown encoder language.")
                    return
                elif key == 'payload' and (value not in payloads):
                    print_error("Unknown payload type.")
                    return
                # print_info(' - {}:\t{}'.format(key.capitalize(), value))
                mod_detail = ".{}.".format(value)
            elif key == 'vendor':
                # print_info(' - Vendor:\t{}'.format(value))
                mod_vendor = ".{}.".format(value)

        for module in self.modules:
            if mod_type not in str(module):
                continue
            if mod_detail not in str(module):
                continue
            if mod_vendor not in str(module):
                continue
            if not all(word in str(module) for word in keyword.split()):
                continue

            found = humanize_path(module)

            if len(keyword):
                for word in keyword.split():
                    found = found.replace(word, "\033[31m{}\033[0m".format(word))

            print_info(found)

    @stop_after(2)
    def complete_search(self, text, *args, **kwargs):
        if text:
            return [command for command in self.search_sub_commands if command.startswith(text)]
        else:
            return self.search_sub_commands

    def command_exit(self, *args, **kwargs):
        raise EOFError
