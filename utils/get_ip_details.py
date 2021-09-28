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
import json
import logging
import platform
import socket
import subprocess
from functools import lru_cache
from shlex import split
from string import Template
from typing import List, Dict

import netaddr
import psutil
import requests
import xmltodict
from ipwhois import IPWhois

from utils import win_ip_cmd
from .get_dns_dhcp import get_windows_dhcp
from .misc import case_check, run_subprocess_command, ip_validation, \
    cidr_ip_validation, yn_check, Style


def get_public_ips(result: dict):
    """
    Function to validate the public ip address. Used to extract NAT_GATEWAY
    Args:
        result(dict): Input result dictionary with all network parameters and boolean flags
    Returns:
        result(dict): The updated result dictionary with network parameter for public NAT_GATEWAY
    Raises:
        Exception on Invalid IP addresses
    """
    logging.info('[%s] - API calls to retrieve public IP address.', datetime.datetime.today())
    print(f'{Style.GREEN}Gathering your public IP from http://diagnostic.opendns.com/myip{Style.RESET}')
    external_ip = None
    try:
        response = requests.get(url="http://diagnostic.opendns.com/myip", verify=False)
        external_ip = response.content.decode('utf-8', '')
        external_ip_list = list()
        external_ip_list.append(external_ip)

    except Exception as error:
        external_ip = None
        print(f"{Style.RED}Received the following error when retrieving public ip : {error}{Style.RESET}")
        logging.error(error)

    result['NAT_GATEWAY'] = list()
    result['nat_gateway_flag'] = 'y'
    result['public_range_flag'] = 'y'
    if external_ip is None:
        result['nat_gateway_flag'] = 'n'
        is_internal = False
        while not is_internal:
            gateway = \
                case_check(
                    input("Please enter company's NAT GATEWAY IP address(s) comma separated:\n"
                          "Note: CIDR range would be calculated for the first IP address in the list\n"))

            result, is_internal = ip_validation('NAT_GATEWAY', gateway, result, is_internal)
    else:
        is_answer = False
        while not is_answer:
            response = case_check(input(f"Is {Style.CYAN}{external_ip}{Style.RESET} your company's NAT GATEWAY? y or n:\n"))
            if response in ["y", "n"]:

                is_answer = True

                if response == "y":
                    result["NAT_GATEWAY"] = external_ip_list

                    y_or_n = yn_check(types='NAT GATEWAY')

                    if y_or_n == 'y':
                        is_internal = False
                        while not is_internal:
                            add_gateway = \
                                case_check(
                                    input("Please enter any additional NAT GATEWAY IP address(s) comma separated:\n"))
                            result, is_internal = ip_validation('ADDITIONAL NAT_GATEWAY', add_gateway, result, is_internal)
                else:
                    result['nat_gateway_flag'] = 'n'
                    is_internal = False
                    while not is_internal:
                        gateway = \
                            case_check(
                                input("Please enter company's NAT GATEWAY IP address(s) comma separated:\n"
                                      "Note: CIDR range would be calculated for the first IP address in the list\n"))

                        result, is_internal = ip_validation('NAT_GATEWAY', gateway, result, is_internal)
            else:
                print(f'{Style.RED}Wrong value! Please input y or n{Style.RESET}')
    return result


def get_public_cidr(result: dict):
    """
    Function to validate the public ip address. Used to extract PUBLIC_RANGE
    Args:
        result(dict): Input result dictionary with all network parameters and boolean flags
    Returns:
        result(dict): The updated result dictionary with network parameter for public PUBLIC_RANGE
    Raises:
        Exception on Invalid IP addresses
    """
    logging.info('[%s] - Update the PUBLIC RANGE address.', datetime.datetime.today())
    cidr = ''

    logging.info('[%s] - whois call on retrieved public IP to get CIDR block.', datetime.datetime.today())
    print(f'{Style.GREEN}Performing a whois on following IP address {Style.CYAN}{result["NAT_GATEWAY"][0]} '
          f'{Style.GREEN}to find CIDR block.{Style.RESET}')
    try:
        cidr = whois_ip(result["NAT_GATEWAY"][0])
        cidr = cidr.replace(" ", "")
    except Exception as error:
        cidr = ''
        print(f"{Style.RED}Received the following error when retrieving public range : {error}{Style.RESET}")
        logging.error(error)

    if cidr == '':
        result['public_range_flag'] = 'n'
        is_internal = False
        while not is_internal:
            valid_cidr = \
                input("Enter the PUBLIC RANGE IP address(s) owned by your company in CIDR format "
                      "comma separated:\n").strip()
            if len(valid_cidr) > 0:
                result, is_internal = cidr_ip_validation('PUBLIC_RANGE', valid_cidr, result, is_internal)
    else:
        is_answer = False
        while not is_answer:

            user_input = case_check(input(f"Is this full network {Style.CYAN}{cidr}{Style.RESET} "
                                          f"registered to your company? y or n \n"))

            if user_input in ['y', 'n']:

                is_answer = True
                if user_input == "y":
                    result["PUBLIC_RANGE"] = [s.strip() for s in cidr.split(",")]

                    y_or_n = yn_check(types='PUBLIC RANGE')
                    if y_or_n == 'y':
                        is_internal = False
                        while not is_internal:
                            additional_cidr = input(
                                "Enter any additional PUBLIC RANGE IP address(s) owned by your company in CIDR format "
                                "comma separated:\n").strip()
                            if len(additional_cidr) > 0:
                                result, is_internal = cidr_ip_validation('ADDITIONAL PUBLIC_RANGE', additional_cidr, result,
                                                                         is_internal)

                if user_input == "n":
                    result['public_range_flag'] = 'n'
                    is_internal = False
                    while not is_internal:
                        valid_cidr = \
                            input("Enter the PUBLIC RANGE IP address(s) owned by your company in CIDR format "
                                  "comma separated:\n").strip()
                        if len(valid_cidr) > 0:
                            result, is_internal = cidr_ip_validation('PUBLIC_RANGE', valid_cidr, result, is_internal)

            else:
                print(f'{Style.RED}Wrong value! Please input y or n{Style.RESET}')

    return result  # get_ip_details


def whois_ip(ip: str):
    """
    Function to extract CIDR range of the public ip address.
    Args:
        ip(str): Public IP address
    Returns:
        cidr(str): CIDR range of the public IP address
    Raises:
        Exception on Invalid IP addresses
    """
    logging.info('[%s] - Executing the command whois.', datetime.datetime.today())
    cidr = "CIDR not found"

    try:
        output_whois = IPWhois(ip).lookup_rdap(depth=1)
    except Exception as error:
        logging.error(error)
    cidr = dict()
    if output_whois['network'].get('cidr'):
        cidr = output_whois['network'].get('cidr')
        # print("from package", cidr)
    cidr_url = Template("https://whois.arin.net/rest/net/NET-209-182-176-0-1/pft?s=$url")  # getting xml response

    response = requests.get(cidr_url.substitute(url=ip))
    string_xml = response.content.decode()

    response_json = json.loads(json.dumps(xmltodict.parse(string_xml)))
    data = response_json['ns4:pft']['net']['netBlocks']['netBlock']
    cidr_block = f"{data['startAddress']}/{data['cidrLength']}"
    # print("from rest", cidr_block)
    return cidr


@lru_cache
def get_linux_nic_name():
    """
    Function to determine the current network interface name in linux machine
    Returns (str): current network interface name
    Raises: Exception on subprocess
    """
    try:
        ps = subprocess.run(split('ip route get 8.8.8.8'), check=True, capture_output=True)
        nic_ps = subprocess.run(split(r"sed -nr 's/.*dev ([^\ ]+).*/\1/p'"),
                                input=ps.stdout, capture_output=True)
        return nic_ps.stdout.decode().strip()
    except subprocess.CalledProcessError as e:
        print(str(e))


def get_mac_nic_name():
    """
        Function to determine the current network interface name in mac machine
        Returns (str): current network interface name
        """
    try:
        ps = subprocess.run(split('route get 8.8.8.8'), check=True, capture_output=True)
        nic_ps = subprocess.run(split(r"grep interface"),
                                input=ps.stdout, capture_output=True)
        return nic_ps.stdout.decode().strip().split(':')[1].strip()
    except subprocess.CalledProcessError as e:
        logging.error(str(e))
        addrs = psutil.net_if_addrs()
        nic = list(addrs.keys())
        return input(f"Please pick your active Network Interface Name, available NIC are {', '.join(nic)}").strip()


def get_dhcp_name() -> List:
    """
    Function to get the DHCP name on Linux
    Returns(List): returns list of dhcp server ip address
    Raises: Exception on subprocess
    """
    try:
        ps = subprocess.run(split('ip r'), check=True, capture_output=True)
        ps1 = subprocess.run(split("grep default"),
                             input=ps.stdout, capture_output=True)
        dhcp_ps = subprocess.run(split(r"grep -o '[0-9.]\{7,\}'"),
                                 input=ps1.stdout, capture_output=True)
        return list(set(dhcp_ps.stdout.decode().strip().splitlines()))
    except subprocess.CalledProcessError as e:
        print(str(e))


def get_ip_manual(result):
    """
    Function to manually extract the internal ip address
    Args:
        result(dict): Input result dictionary with all network parameters and boolean flags
    Returns:
        result(dict): The updated result dictionary with network parameter
    Raises:
        Exception on Invalid IP addresses
    """
    logging.info('[%s] - Manually collecting the ENDUSER_RANGE information.', datetime.datetime.today())
    is_internal = False
    while not is_internal:
        try:
            end_user = input("Please enter your ENDUSER RANGE IP address in CIDR format\n").strip()
            result, is_internal = cidr_ip_validation('ENDUSER_RANGE', end_user, result, is_internal)
        except Exception as error:
            logging.error(error)


def get_cidr(address, netmask):
    """
    Function to calculate the cidr format of an ip address when passed with subnet mask

    Returns:
        interface(str): Interface name in string format
        cidr: IP address of interface in cidr format with subnet mask
    Raises:
        Exception on socket connectivity issues
    """
    cidr = str(netaddr.IPNetwork('%s/%s' % (address, netmask)))
    addr = cidr.split('/')  # when connect to VPN  we get IP/32 so changing
    # address last digit to 0 and change 32 to 24
    if addr[1] == '32':
        tmp = addr[0].split('.')
        tmp[3] = '0'
        cidr = f"{'.'.join(tmp)}/24"
    return cidr


def get_ip_info(data: Dict):
    """
    Main function to extract and validate the enduser_range which is the internal IP address in cidr format
    Args:
        data(dict): Input result dictionary with all network parameters and boolean flags
    Returns:
        result(dict): The updated result dictionary with network parameter
    Raises:
        Exception on Invalid IP addresses
    """
    try:
        print(f'----------------REFERNCE LIST OF IP(s) FROM THE MACHINE---------------\n')
        ipv4 = list(get_list_interfaces())
        widths = [max(map(len, col)) for col in zip(*ipv4)]
        for row in ipv4:
            print(f'{Style.MAGENTA}{"  ".join((val.ljust(width) for val, width in zip(row, widths)))} {Style.RESET}')
        print(f'----------------------------------------------------------------------------------\n')

        get_ip_manual(data)

    except Exception as e:
        logging.error(str(e))
        get_ip_manual(data)


def get_dhcp_details(data):
    """
    Main function to extract and validate the DHCP Server details
    Args:
        data(dict): Input result dictionary with all network parameters and boolean flags
    Returns:
        result(dict): The updated result dictionary with network parameter
    Raises:
        Exception on Invalid IP addresses
    """
    data["DHCP_SERVER"] = None
    try:
        if platform.system() == 'Linux':
            # nic_name = get_linux_nic_name()
            # print(f"Your NIC name is {nic_name}")
            data["DHCP_SERVER"] = get_dhcp_name()
        elif platform.system() == "Windows" or platform.system() == "win32":
            output = run_subprocess_command(win_ip_cmd)
            get_windows_dhcp(data, output)  # capture local utils DNS and DHCP information
        # else:
        #     # nic_name = get_mac_nic_name()
        #     # print("NIC name is", nic_name)
        #     # try:
        #     #     packet_ps = subprocess.run(split(f'ipconfig getpacket {nic_name}'), check=True, capture_output=True)
        #     #     dhcp_ps = subprocess.run(split(r"grep  server_identifier"),
        #     #                              input=packet_ps.stdout, capture_output=True)
        #     #     dhcp = dhcp_ps.stdout.decode().strip().split(":")[1].replace("{", '').replace("}", '').strip().split(',')
        #     #     data["DHCP_SERVER"] = [e.strip() for e in dhcp]
        #     # except subprocess.CalledProcessError as e:
        #     #     logging.error(str(e))F
        #     data["DHCP_SERVER"] = None
    except Exception as error:
        logging.error(error)


def get_list_interfaces():
    """
    Function to return the ipaddress and subnet mask for the list of interfaces and validate the DHCP Server details

    Returns:
        interface(str): Interface name in string format
        cidr: IP address of interface in cidr format with subnet mask
    Raises:
        Exception on socket connectivity issues
    """
    try:
        for interface, snics in psutil.net_if_addrs().items():
            for snic in snics:
                if snic.family == socket.AF_INET and snic.address not in ["localhost", "127.0.0.1"]:
                    yield interface, get_cidr(snic.address, snic.netmask)
    except Exception as error:
        logging.error(error)
