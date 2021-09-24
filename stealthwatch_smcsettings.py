# System Requirements: Stealthwatch Version: 7.3.0 or higher
#
# Copyright (c) 2021, Cisco Systems, Inc. All rights reserved.
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
# The above copyright notice and this permission notice shall be included in all
# copies or substantial portions of the Software.
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.

import json
import logging
import os
import pathlib
import platform
import re
from typing import Dict

from utils.get_dns_dhcp import local_dns_servers, get_internal_dns, \
    get_external_dns, get_internal_dhcp
from utils.get_internal_network import capture_company_info
from utils.get_ip_details import get_public_ips, get_ip_info, get_dhcp_details, get_public_cidr
from utils.misc import print_settings_info, write_file, \
    confirm_captured_results, print_settings_return, print_settings_first, Style

IP_REGX = re.compile("^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
smc_path = str(pathlib.Path.home())


def run_all(result: Dict):
    """
    Runs the full set of functions to collect the network parameters
    Args:
        result(dict): The result dictionary which holds the keys and values for all the relevant network params
    """
    run_func = [get_public_ips, get_public_cidr, write_file, local_dns_servers, get_dhcp_details, get_internal_dns,
                get_external_dns, get_internal_dhcp, write_file, capture_company_info, write_file, get_ip_info,
                write_file, confirm_captured_results]
    for func in run_func:
        if func.__name__ == 'write_file':
            func(result, smc_path)
        else:
            func(result)


def main():
    """
    The main function which is driving the whole script.
    """
    if os.path.isfile('.result'):
        with open(".result") as f:
            os.environ["stealth_watch_post"] = f.read()
    logging.basicConfig(filename='smc.log', filemode='w', format='%(levelname)s - %(message)s', level=logging.INFO)

    print_settings_info()  # Print header information
    result = dict()  # Dictionary to store all the network details

    smc_file = os.path.join(smc_path, 'smc.settings')

    if os.path.isfile(smc_file):
        with open(smc_file) as f:
            result = json.load(f)
        print_settings_return()  # Print welcome message for returning user
        confirm_captured_results(result)
    else:
        print_settings_first()  # Print welcome message for first time user
        run_all(result)


if __name__ == '__main__':
    if platform.system() == 'Windows' or platform.system() == 'win32':
        os.system("")
    main()
