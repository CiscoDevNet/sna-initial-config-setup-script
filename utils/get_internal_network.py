# System Requirements: Stealthwatch Version: 7.3.2 or higher
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

import datetime
import logging
from .misc import case_check, ip_validation, cidr_ip_validation


def capture_company_info(result):
    """
    Function to extract and validate the Domain Controller, Email Servers, Critical Range
    Args:
        result(dict): Input result dictionary with all network parameters and boolean flags
    Returns:
        result(dict): The updated result dictionary with network parameter
    Raises:
        Exception on Invalid IP addresses
    """
    logging.info('[%s] - Get the Domain controller, Mail server and other secure information.',
                 datetime.datetime.today())
    is_internal = False
    while not is_internal:
        domain_control = \
            case_check(input("Please enter your companies DOMAIN CONTROLLER server IPs comma separated or "
                             "'s' to skip \n"))
        if domain_control.lower() != 's':
            result, is_internal = ip_validation('DOMAIN_CONTROLLER', domain_control, result, is_internal)
        else:
            result["domain_control_flag"] = 's'
            logging.info("DOMAIN_CONTROLLER option skipped by user")
            is_internal = True

    is_internal = False
    while not is_internal:
        mail_server = \
            case_check(input("Please enter your company MAIL SERVER IP address(s) comma separated or 's' to skip. \n"))
        if mail_server.lower() != 's':
            result, is_internal = ip_validation('EMAIL_SERVERS', mail_server, result, is_internal)
        else:
            result["mail_server_flag"] = 's'
            logging.info("EMAIL_SERVERS option skipped by user")
            is_internal = True

    is_internal = False
    while not is_internal:
        critical_subnet\
            = case_check(input(
             "To help segment and monitor critical assets, please enter a subnet IP range comma separated that hosts\n"
             "sensitive or CRITICAL SERVERS that if compromised would impact business operations\n"
             "(e.g. PCI servers or source code servers ) 's' to skip.\n"))
        if critical_subnet.lower() != 's':
            result, is_internal = cidr_ip_validation('CRITICAL_RANGE', critical_subnet, result, is_internal)
        else:
            result["critical_subnet_flag"] = 's'
            logging.info("CRITICAL_RANGE option skipped by user")
            is_internal = True
    return result
