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

import datetime
import logging
import dns.resolver

from .misc import case_check, ip_validation, yn_check, Style


def get_windows_dhcp(result, output):
    """
    Function to validate the ip address. Used to extract DHCP_SERVER
    Args:
        result(dict): Input result dictionary with all network parameters and boolean flags
        output(str): The output generated from the Operating System Command
    Returns:
        result(dict): The updated result dictionary with network parameters
    Raises:
        Exception on Invalid IP addresses
    """
    logging.info('[%s] - Started the extraction of IP related data.', datetime.datetime.today())
    dhcp_server = list()
    result["DHCP_SERVER"] = list()

    if output is not None and len(output) > 0:
        try:
            for tokens in output.strip().split('\r\n\r\n'):
                if "IPv4 Address" in tokens:
                    tokens = tokens.strip().split("\r\n")

                    for index in range(len(tokens)):

                        if "DHCP Server" in tokens[index]:
                            dhcp_server.append(tokens[index].split(":", 1)[1].strip())
                            result["DHCP_SERVER"] = dhcp_server

            logging.info('[%s] - Completed the Windows DHCP data extraction to the file.', datetime.datetime.today())
            return result
        except Exception as error:
            logging.error(error)


def local_dns_servers(result):
    """
    Function to validate the ip address. Used to collect INTERNAL_DNS
    Args:
        result(dict): Input result dictionary with all network parameters and boolean flags
    Returns:
        result(dict): The updated result dictionary with network parameters
    Raises:
            Exception on Invalid IP addresses
     """
    try:
        if "dns_servers" not in result.keys():
            result["INTERNAL_DNS"] = list()
        logging.info("[%s] - Utilize the DNS resolver to get all internal nameservers.", datetime.datetime.now())
        dns_resolver = dns.resolver.Resolver()
        dns_list = result["INTERNAL_DNS"]
        for dns_items in dns_resolver.nameservers:
            dns_list.append(dns_items)
        return result
    except Exception as error:
        logging.error(error)


def get_internal_dns(result):
    """
    Function to validate the ip address. Used to extract INTERNAL_DNS server information
    Args:
        result(dict): Input result dictionary with all network parameters and boolean flags
    Returns:
        result(dict): The updated result dictionary with network parameters
    Raises:
        Exception on Invalid IP addresses
    """
    logging.info('[%s] - Started updating the collected dns information.', datetime.datetime.today())
    try:
        print(f'{Style.GREEN}INTERNAL DNS Servers: {Style.CYAN}{", ".join(result["INTERNAL_DNS"])} {Style.RESET}')

        is_answer = False
        internal_DNS = ""

        while not is_answer:
            internal_DNS = case_check(input("Are these your companies INTERNAL DNS servers? y or n \n"))
            if internal_DNS in ['n', 'y']:
                is_answer = True
                result['internal_dns_flag'] = internal_DNS

                if internal_DNS == 'y':
                    y_or_n = yn_check(types='INTERNAL_DNS')
                    if y_or_n == 'y':
                        is_internal = False
                        while not is_internal:
                            add_internal = input(
                                "Enter any additional INTERNAL DNS IP address(s) comma separated:\n").strip()

                            if len(add_internal) > 0:
                                result, is_internal = ip_validation('ADDITIONAL INTERNAL_DNS', add_internal, result,
                                                                    is_internal)
                if internal_DNS == 'n':  # when retrieved internal DNS is incorrect get it from user itself
                    is_internal = False
                    while not is_internal:
                        internal = \
                            case_check(
                                input(
                                    "Please enter the company INTERNAL DNS server IP address(s) comma separated\n"))
                        if len(internal) > 0:
                            result, is_internal = ip_validation('INTERNAL_DNS', internal, result, is_internal)

            else:
                print(f'{Style.RED}Wrong value! Please input y or n{Style.RESET}')
        return result
    except Exception as error:
        logging.error(error)


def get_external_dns(result):
    """
    Function to validate the ip address. Used to extract EXTERNAL_DNS server information
    Args:
        result(dict): Input result dictionary with all network parameters and boolean flags
    Returns:
        result(dict): The updated result dictionary with network parameters
    Raises:
        Exception on Invalid IP addresses
    """
    logging.info('[%s] - Collect the external dns.', datetime.datetime.today())
    try:
        is_answer = False

        while not is_answer:
            external_dns = case_check(input("Do you have public EXTERNAL DNS IP servers? y or n \n"))
            if external_dns == 'n' or external_dns == 'y':
                result['external_dns_flag'] = external_dns
                is_answer = True
                if external_dns == 'y':
                    is_internal = False
                    while not is_internal:

                        external = case_check(
                            input("Enter the EXTERNAL DNS public IP address(s) comma separated or 's' to skip \n"))
                        if external == 's':
                            result['external_dns_flag'] = 's'
                            logging.info("EXTERNAL_DNS option skipped by user ")
                            break
                        if len(external) > 0:
                            result, is_internal = ip_validation('EXTERNAL_DNS', external, result, is_internal)

            else:
                print(f'{Style.RED}Wrong value! Please input y or n{Style.RESET}')
        return result
    except Exception as error:
        logging.error(error)


def get_internal_dhcp(result):
    """
    Function to validate the ip address. Used to extract DHCP_SERVER information
    Args:
        result(dict): Input result dictionary with all network parameters and boolean flags
    Returns:
        result(dict): The updated result dictionary with network parameters
    Raises:
        Exception on Invalid IP addresses
    """

    logging.info('[%s] - Started updating the collected dhcp information.', datetime.datetime.today())
    try:
        if result["DHCP_SERVER"] is not None:
            print(f'{Style.GREEN}Your DHCP SERVER is: {Style.CYAN}{", ".join(result["DHCP_SERVER"])} {Style.RESET}')

        is_answer = False
        while not is_answer:
            if result["DHCP_SERVER"] is not None:
                company_dhcp = case_check(input("Is this your company internal DHCP SERVER? y or n \n"))
            else:  # this happens when programmatic retrieval of dhcp is failed
                company_dhcp = 'n'

            if company_dhcp in ['n', 'y']:
                is_answer = True
                result["internal_dhcp_flag"] = company_dhcp
                if company_dhcp == 'y':

                    y_or_n = yn_check(types='DHCP SERVER')
                    if y_or_n == 'y':
                        is_internal = False
                        while not is_internal:
                            add_dhcp = input(
                                "Enter any additional DHCP SERVER IP address(s) comma separated or 's' to skip :\n").strip()

                            if len(add_dhcp) > 0:
                                if add_dhcp == 's':
                                    break
                                else:
                                    result, is_internal = ip_validation('ADDITIONAL DHCP_SERVER', add_dhcp, result,
                                                                        is_internal)
                if company_dhcp == 'n':
                    is_internal = False
                    while not is_internal:
                        dhcp = \
                            case_check(
                                input("Please enter the internal DHCP SERVER IP address(s) comma separated or 's' "
                                      "to skip\n"))
                        if dhcp == 's':
                            result["internal_dhcp_flag"] = 's'
                            logging.info("DHCP_SERVER option skipped by user")
                            break

                        if len(dhcp) > 0:
                            result, is_internal = ip_validation('DHCP_SERVER', dhcp, result, is_internal)

            else:
                print(f'{Style.RED}Wrong value! Please input y or n{Style.RESET}')
        return result
    except Exception as error:
        logging.error(error)
