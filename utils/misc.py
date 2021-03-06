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

import codecs
import datetime
import getpass
import json
import logging
import os
import platform
import subprocess
import ipaddress
import pathlib
from typing import Dict

import netaddr
import requests
from requests import HTTPError
from requests.packages.urllib3.exceptions import InsecureRequestWarning

from .smc_validator import Smc

requests.packages.urllib3.disable_warnings(InsecureRequestWarning)
smc_path = str(pathlib.Path.home())
mapping = {"NAT_GATEWAY": 51, "PUBLIC_RANGE": 65534, "ENDUSER_RANGE": 50076, "INTERNAL_DNS": 27, "EXTERNAL_DNS": 65532,
           "DHCP_SERVER": 36, "DOMAIN_CONTROLLER": 38, "EMAIL_SERVERS": 30, "CRITICAL_RANGE": 10}
base_dir = os.path.join(os.path.dirname(__file__), '..')
file_path = os.path.join(base_dir, '.result')
print(file_path)


class Style:
    BLACK = '\033[30m'
    RED = '\033[31m'
    GREEN = '\033[32m'
    YELLOW = '\033[33m'
    BLUE = '\033[34m'
    MAGENTA = '\033[35m'
    CYAN = '\033[36m'
    WHITE = '\033[37m'
    UNDERLINE = '\033[4m'
    RESET = '\033[0m'


def confirm_captured_results(result: Dict):
    """
    Update the result dictionary with the confirmation flag that the details collected are accurate
    Args:
        result(dict): All the network host groups
    Returns:
        result(dict): result dictionary updated with the confirmation flag
    """

    logging.info('[%s] - Get confirmation on captured information.', datetime.datetime.today())
    try:
        is_answer = False
        mandate_flag = ''
        host_group = ['NAT_GATEWAY', 'PUBLIC_RANGE', 'INTERNAL_DNS', 'EXTERNAL_DNS', 'DHCP_SERVER', 'DOMAIN_CONTROLLER',
                      'EMAIL_SERVERS', 'CRITICAL_RANGE', 'ENDUSER_RANGE']
        print(f'------------CONFIRMATION OF CAPTURED VALUES------------')
        print(f'-------------------------------------------------------')
        while not is_answer:
            for k in host_group:
                print(f' {Style.MAGENTA}{k:<{len(max(host_group,key=len))}}: '
                      f' {Style.CYAN}{",".join(result.get(k)) if isinstance(result.get(k),list) else result.get(k)} '
                      f'{Style.RESET}')
            print(f'-------------------------------------------------------')
            confirm = case_check(input(f"Please confirm smc.settings is correct: 'y' to post to smc or 'n' to "
                                       f"edit host groups?\n"))
            if confirm in ['y', 'n']:
                is_answer = True
                result["confirmation_flag"] = confirm
                if confirm == 'y':
                    mandatory_fields = ['NAT_GATEWAY', 'PUBLIC_RANGE', 'INTERNAL_DNS', 'ENDUSER_RANGE']
                    man_fields = [field for field in mandatory_fields if result.get(field) is None]
                    if len(man_fields) > 0:
                        print(
                            f'Before you can post the settings to smc server. Please enter the details for the '
                            f'mandatory fields {", ".join(man_fields)}')

                        get_mandatory_fields(result, man_fields)
                        mandate_flag = confirm_mandatory_results(result)
                    if mandate_flag == 'y' or mandate_flag == '':
                        post_settings(result)
                        Smc.parse_obj(result)
                    if mandate_flag == 'n':
                        edit_smc_settings(result)
                else:
                    edit_smc_settings(result)
            else:
                print(f'{Style.RED}Wrong value! Please input y or n{Style.RESET}')
    except Exception as error:
        logging.error(error)


def write_to_disk(func):
    """
    decorator used to write the data into disk  during each checkpoint to  help us to resume the operation
    Args:
        func:

    Returns:

    """

    def wrapper(*args, **kwargs):
        func(*args, **kwargs)
        with open("checkpoint.json", "r") as f:
            f.write(json.dumps(args[0]))

    return wrapper


def check_post_status(func):
    """
     call the func only if the smc.setting is not already posted via API
    Args:
        func:write_file

    Returns:
        wrapper: confirmation if the smc.settings file has been posted already
    """

    def wrapper(*args, **kwargs):
        # print("os.environ in decorator", os.environ.get('stealth_watch_post'))

        if os.environ.get("stealth_watch_post", '0') == '0':
            func(*args, **kwargs)
        else:
            print(f"{Style.RED}smc.setting file data is already posted to smc server from this machine,"
                  f" so skipping the operation for function {func.__qualname__}{Style.RESET}")
            print(f'{Style.GREEN}Thank you!{Style.RESET}')

    return wrapper


def write_file(result, smc_path: str):
    """
    Function to execute the Operating System command in Python
    Args:
        result(dict): The result dictionary which holds the network Host groups
        smc_path(str): The file path to which the smc.settings file will be written out.
    """
    logging.info('[%s] - writing to the smc.settings file.', datetime.datetime.today())
    try:
        with codecs.open(os.path.join(smc_path, 'smc.settings'), 'w', encoding='utf-8') as fp:
            json.dump(result, fp, indent=2)
            logging.info('[%s] - Successfully added to the smc.settings file in [%s].', datetime.datetime.today(),
                         str(smc_path))
    except Exception as error:
        logging.error(error)


@check_post_status
def post_settings(result: dict):
    """
    Function to post the network host groups to SMC server
    Args:
        result(dict): The result dictionary which holds the network Host groups
    """
    if result["confirmation_flag"] == "y":
        logging.info('[%s] - Capture server utils, username and password for posting to server.',
                     datetime.datetime.today())
        is_answer = False
        while not is_answer:
            smc_ip = case_check(input("What is the IP address of your smc or 's' to skip? \n"))

            if smc_ip != 's':
                try:
                    ipaddress.ip_address(smc_ip)
                    is_answer = True
                    result["smc_ip_address"] = smc_ip
                    username = input("Enter the Username:")
                    password = getpass.getpass("Enter the Password:")
                    result["username"] = username
                    result["password"] = password
                except Exception as error:
                    is_answer = False
                    logging.error(error)
                    print(f'{Style.RED}Please enter the ip in the correct format {Style.RESET}')
                if is_answer:
                    try:
                        post_tag_details(result)
                    except Exception as error:
                        logging.error(error)
                        print(f'{Style.RED}Please check the api parameters/data and execute script again to post to smc {Style.RESET}')
            else:
                is_answer = True
                print(f'{Style.GREEN}Thank you for executing the script. Please execute again to post to smc{Style.RESET}')


def get_tenant_id(api_session, host):
    """

    Args:
        api_session: Valid api session
        host: Str: The smc ip address

    Returns:
        smc_tenant_id: Int: Valid smc_tenant_id
    """
    logging.info('[%s] - getting the domain/tenant id information.', datetime.datetime.today())
    # Get the list of tenants (domains) from the SMC
    ip_ver = ipaddress.ip_address(host)
    if ip_ver.version == 4:
        url = 'https://' + host + '/sw-reporting/v1/tenants/'
    elif ip_ver.version == 6:
        url = 'https://[' + host + ']/sw-reporting/v1/tenants/'
    response = api_session.request("GET", url, verify=False)

    # If successfully able to get list of tenants (domains)
    if response.status_code == 200:

        # Store the tenant (domain) ID as a variable to use later
        tenant_list = json.loads(response.content)["data"]
        smc_tenant_id = tenant_list[0]["id"]

        # Print the SMC Tenant ID
        print(f'{Style.GREEN}Tenant ID connected to is : {Style.YELLOW} {smc_tenant_id}{Style.RESET}')
        return smc_tenant_id

    # If unable to fetch list of tenants (domains)
    else:
        raise Exception("An error has occurred, while fetching tenants (domains), with the following code {}".format(
            response.status_code))


def get_tag_append(api_session, smc_host, smc_tenant_id, tag_id, ip_range, coll_list):
    """

    Args:
        api_session: Valid api session
        smc_host: String: smc host address
        smc_tenant_id:Int: Tenant id fetched for the authentic connection
        tag_id: Int: Tag id for the host groups
        ip_range:List: List of ip addresses in the result dictionary for each host group
        coll_list: List of tag details for all host groups

    Returns:
        coll_list: List of tag details for all host groups
    """
    # Get the details of a given tag (host group) from the SMC
    ip_ver = ipaddress.ip_address(smc_host)
    if ip_ver.version == 4:
        url = 'https://' + smc_host + '/smc-configuration/rest/v1/tenants/' + str(smc_tenant_id) + '/tags/' + str(tag_id)
    elif ip_ver.version == 6:
        url = 'https://[' + smc_host + ']/smc-configuration/rest/v1/tenants/' + str(smc_tenant_id) + '/tags/' + str(tag_id)
    try:
        response = api_session.request("GET", url, verify=False)
        if response.status_code == 200:
            tag_details = json.loads(response.content)["data"]

        # Modify the details of thee given tag (host group) from the SMC
            if isinstance(ip_range,str):
                ip_range = ip_range.split(' ')
            if ip_range is not None:
                tag_details['ranges'].extend(ip_range)
                tag_details['ranges'] = list(set(tag_details['ranges']))
            coll_list.append(tag_details)
            return coll_list
        else:
            print(f'Response Message: {json.loads(response.content)["errors"]}')
            raise Exception(
                "An error has occurred, while updating tags (host groups), with the following code {}".format(
                    response.status_code))

    except Exception as error:
        logging.error(error)


def update_tag(api_session, smc_host, smc_tenant_id, coll_list, result):
    """

    Args:
        api_session: Valid api session
        smc_host: String: smc host address
        smc_tenant_id:Int: Tenant id fetched for the authentic connection
        coll_list: List of tag details for all host groups

    Returns:

    """
    logging.info('[%s] - post all the ip data to smc server.', datetime.datetime.today())
    # Get the details of a given tag (host group) from the SMC
    ip_ver = ipaddress.ip_address(smc_host)
    if ip_ver.version == 4:
        url = 'https://' + smc_host + '/smc-configuration/rest/v1/tenants/' + str(smc_tenant_id) + '/tags/'
    elif ip_ver.version == 6:
        url = 'https://[' + smc_host + ']/smc-configuration/rest/v1/tenants/' + str(smc_tenant_id) + '/tags/'
    response = api_session.request("GET", url, verify=False)
    if response.status_code == 200:
        print(f'{Style.GREEN}Host group url is accessible for for update operation{Style.RESET}')
    # Update the details of thee given tag (host group) in the SMC

    request_headers = {'Content-type': 'application/json', 'Accept': 'application/json'}
    response = api_session.request("PUT", url, verify=False, data=json.dumps(coll_list), headers=request_headers)
    # If successfully able to update the tag (host group)
    if response.status_code == 200:
        all_tags = json.loads(response.content)
        hgs = set()
        for k,v in mapping.items():
            if result.get(k) is not None:
                for i in range(9):  # Currently there are 9 valid host groups
                    if v == all_tags["data"][i]["id"]:
                        mapped = [item for item in result[k] if item in all_tags["data"][i]["ranges"]]
                        if mapped:
                            hgs.add(v)
                            break
        print(f"{Style.GREEN}Data has been successfully posted to following host groups: "
              f"{Style.YELLOW}{hgs}{Style.GREEN} from this machine.{Style.RESET}")
        with open(file_path, "w") as f:
            f.write("1")  # to indicate we already posted smc.settings
        print(f"{Style.GREEN}Thank you for executing the script !{Style.RESET}")

    # If unable to update the IPs for a given tag (host group)
    else:
        print(f'Response Message: {json.loads(response.content)["errors"]}')
        raise Exception("An error has occurred, while updating tags (host groups), with the following code {}".format(
            response.status_code))


def post_tag_details(result: Dict):
    """
    function to update the ip ranges for multiple tag id
    Args:
        result(dict): contains tag id & ip ranges

    Returns:

    """
    logging.info('[%s] - start of workflow to post to smc server.', datetime.datetime.today())
    # Set the URL for SMC login
    ip_ver = ipaddress.ip_address(result["smc_ip_address"])
    if ip_ver.version == 4:
        url = "https://" + result["smc_ip_address"] + "/token/v2/authenticate"
    elif ip_ver.version == 6:
        url = "https://[" + result["smc_ip_address"] + "]/token/v2/authenticate"
    # Let's create the login request data
    login_request_data = {
        "username": result['username'],
        "password": result['password']
    }
    # Initialize the Requests session
    api_session = requests.Session()
    base_dir = os.path.join(os.path.dirname(__file__), '..')
    file_path = os.path.join(base_dir, '.result')
    try:
        response = api_session.request("POST", url, verify=False, data=login_request_data)
        # If the login was successful
        if response.status_code == 200:
            print(f'{Style.GREEN}Successful logging to smc server{Style.RESET}')
            # Set XSRF token for future requests
            if response.cookies.get('XSRF-TOKEN') is not None:
                api_session.headers.update({'X-XSRF-TOKEN': response.cookies.get('XSRF-TOKEN')})
                tenant_id = get_tenant_id(api_session, result["smc_ip_address"])  # get a tenant id
                coll_list = list()
                for key, value in result.items():
                    if key in mapping:  # if the result dict have matching tag id we will proceed to update the tag
                        get_tag_append(api_session, result["smc_ip_address"], tenant_id, mapping[key], value, coll_list)
                # Any new host group introduced should be added to the mapping dictionary
                update_tag(api_session, result["smc_ip_address"], tenant_id, coll_list, result)

            else:
                raise HTTPError('XSRF-TOKEN is missing in cookie')
        else:
            raise HTTPError(f"api returned with status code {response.status_code}")

    except Exception as error:
        print(f"{Style.RED}Received the following error when connecting to smc server: {error}{Style.RESET}")
        logging.error(error)

    finally:
        if api_session:
            api_session.close()


def print_settings_info():
    """
    Function to print the welcome message to user
    """
    print(f'*************************************\n'
          f'{Style.GREEN}Welcome to Stealthwatch Setup Wizard:{Style.RESET }\n'
          f'************************************* ')


def print_settings_first():
    """
    Function to print the welcome message to user
    """
    print(f'{Style.GREEN}This script will walk through a series of questions to gather information\n'
          f'to post to Stealthwatch through an API once deployed, You can run the script\n'
          f'before Stealthwatch is deployed to prepare and build an smc.settings file that\n'
          f'can be posted once the SMC is online\n'
          f'\n'
          f'This script should be run from a user machine while connected to the company\n'
          f'network so it can gather IP information related to the company network like\n'
          f'Public NAT IP address and internal DNS Servers used.\n'
          f'\n'
          f'The script will save a local smc.settings config file that will be used to \n'
          f'provide information to Stealthwatch Management Console to streamline set up.\n'
          f'User machine runs on {Style.YELLOW}"{platform.system()}"{Style.GREEN} system\n {Style.RESET}')


def print_settings_return():
    """
    Function to print the message to returning user
    """
    print(f'-------------------------------------------------------------------------------------\n'
          f'{Style.GREEN}It appears you have previously run this set up script, here are your current settings '
          f'{Style.RESET}\n'
          f'-------------------------------------------------------------------------------------')


def run_subprocess_command(cmd: str):
    """
    Function to execute the Operating System command in Python
    Args:
        cmd(str): The OS command to be executed
    Returns:
         output(str): The output of the OS command which was executed.
    """
    process = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stdin=subprocess.PIPE, stderr=subprocess.PIPE)

    result, error = process.communicate()
    if error == b'':
        result = result.decode()
        return result
    else:
        logging.info("[%s] - Error executing OS command", datetime.datetime.today())  # TODO fix message
        logging.error(error)
        return result


def ip_validation(reference: str, user_input: str, result: dict, is_internal: bool):
    """
    Function to validate the ip address. Used to validate NAT_GATEWAY, INTERNAL_DNS, EXTERNAL_DNS, DHCP_SERVER,
    DOMAIN_CONTROLLER, EMAIL_SERVERS
    Args:
        reference(str): The input type in string format
        user_input(str): Console input entered by the user. comma separated string
        result(dict): Input result dictionary with all network parameters and boolean flags
        is_internal(bool): Boolean flag to validate if valid input entered
    Returns:
        result(dictionary),
        is_internal(bool): Updated flag
    Raises:
        Exception on Invalid IP addresses
    """
    if len(user_input) > 0 and len(user_input.split(',')) > 0:
        input_list = user_input.split(',')
        stripped_list = [s.strip() for s in input_list]
        try:
            for ele in stripped_list:
                if ele == '':
                    stripped_list.remove(ele)
                else:
                    ipaddress.ip_address(ele)
            is_internal = True
            value_map = {'ADDITIONAL NAT_GATEWAY': 'NAT_GATEWAY',
                         'ADDITIONAL INTERNAL_DNS': 'INTERNAL_DNS',
                         'ADDITIONAL DHCP_SERVER': 'DHCP_SERVER',
                         'NAT_GATEWAY': 'NAT_GATEWAY',
                         'INTERNAL_DNS': 'INTERNAL_DNS',
                         'EXTERNAL_DNS': 'EXTERNAL_DNS',
                         'DHCP_SERVER': 'DHCP_SERVER',
                         'DOMAIN_CONTROLLER': 'DOMAIN_CONTROLLER',
                         'EMAIL_SERVERS': 'EMAIL_SERVERS'}
            if reference in ('ADDITIONAL NAT_GATEWAY', 'ADDITIONAL INTERNAL_DNS', 'ADDITIONAL DHCP_SERVER'):
                result[value_map[reference]].extend(stripped_list)
            else:
                result[value_map[reference]] = stripped_list
        except Exception as error:
            logging.error(error)
            print(f'{Style.RED}Please enter {Style.BLUE}{reference} {Style.RED}IPs in the correct format {Style.RESET}')

    return result, is_internal


def cidr_ip_validation(reference: str, user_input: str, result: dict, is_internal: bool):
    """
    Function to validate the ip address and subnet mask when added via cidr format. Used to validate
    PUBLIC_RANGE , CRITICAL_RANGE and ENDUSER_RANGE
    Args:
        reference(str): The input type in string format
        user_input(str): Console input entered by the user. comma separated string
        result(dict): Input result dictionary with all network parameters and boolean flags
        is_internal(bool): Boolean flag to validate if valid input entered
    Returns:
        result(dictionary),
        is_internal(bool): Updated flag
    Raises:
        Exception on Invalid IP addresses
    """
    if len(user_input) > 0 and len(user_input.split(",")) > 0:
        internal_list = user_input.split(",")
        stripped_list = [s.strip() for s in internal_list]
        valid_mask = 'y'
        try:
            for ind, ele in enumerate(stripped_list):
                if ele == '':
                    stripped_list.remove(ele)
                else:
                    ip_value = ele.split("/", 1)[0].strip()
                    ipaddress.ip_address(ip_value)
                    if reference == 'CRITICAL_RANGE' and "/" not in ele:
                        print(f'{Style.CYAN}{Style.UNDERLINE}Note:{Style.RESET} {Style.CYAN}For single ip address inputs'
                              f' please enter /32 as the subnet mask value{Style.RESET}')
                        valid_mask = 'n'
                    else:
                        mask = ele.split("/", 1)[1].strip()
                        if not 0 < int(mask) <= 32:
                            valid_mask = 'n'
                            print(f'{Style.RED}Invalid subnet mask value entered in CIDR format of IP address{Style.RESET}')
                    if valid_mask != 'n' and reference != 'CRITICAL_RANGE':
                        ele = str(netaddr.IPNetwork('%s/%s' % (ip_value, mask)))
                        ipaddr = ele.split('/')  # when connect to VPN  we get IP/32 so changing
                        # address last digit to 0 and change 32 to 24
                        if ipaddr[1] == '32':
                            tmp = ipaddr[0].split('.')
                            tmp[3] = '0'
                            ele = f"{'.'.join(tmp)}/24"
                            stripped_list[ind] = ele
            if valid_mask != 'n':
                is_internal = True
                if reference in ['ENDUSER_RANGE']:
                    result['ENDUSER_RANGE'] = stripped_list
                elif reference in ['ADDITIONAL PUBLIC_RANGE']:
                    result['PUBLIC_RANGE'].extend(stripped_list)
                elif reference in ['PUBLIC_RANGE']:
                    result['PUBLIC_RANGE'] = stripped_list
                elif reference in ['CRITICAL_RANGE']:
                    result['CRITICAL_RANGE'] = stripped_list

        except Exception as error:
            logging.error(error)
            print(f'{Style.RED}Please check if the CIDR format of IP address(s) entered is valid{Style.RESET}')
        return result, is_internal


def case_check(inp: str):
    """
    A function to check if the value entered via console is 'y' or 'n'
    Args:
         inp(str): Input string
    Returns:
        lower.inp(str): lower function on the input string
    """
    return inp.strip().lower()


def yn_check(types: str):
    """
    A function to check if the value entered via console is 'y' or 'n'
    Args:
         types(str): Input string
    Returns:
        y_or_n(str): Input string which is either a y or n
    """
    is_y_or_n = False
    while not is_y_or_n:
        y_or_n = case_check(input(f"Do you have additional {types} IP address(s)? y or n\n"))
        if y_or_n in ["y", "n"]:
            is_y_or_n = True
            return y_or_n
        else:
            print(f'{Style.RED}Wrong value! Please input y or n{Style.RESET}')


def edit_smc_settings(result):
    """
    Function to display and edit the smc.settings files.
    Args:
        result(dict): Input result dictionary with all network parameters and boolean flags
    Returns:
        result(dict): The updated result dictionary with network parameters
    Raises:
        Exception on Invalid IP addresses
    """
    try:
        host_groups = {0: 'NAT_GATEWAY', 1: 'PUBLIC_RANGE', 2: 'INTERNAL_DNS', 3: 'EXTERNAL_DNS', 4: 'DHCP_SERVER',
                       5: 'DOMAIN_CONTROLLER', 6: 'EMAIL_SERVERS', 7: 'CRITICAL_RANGE', 8: 'ENDUSER_RANGE'}
        is_edit = False
        while not is_edit:
            nums = '123456789'
            print_formatted_output(host_groups, result)
            edit_field = input(f'Please enter the host group value to be edited(1-9) or "s" to skip\n')
            if edit_field in (list(nums)):

                host_index = int(edit_field) - 1
                print(f'{Style.GREEN}You have chosen to edit {Style.CYAN}{edit_field}:\t{host_groups.get(host_index)}'
                      f'{Style.RESET}')
                print(f'{Style.YELLOW}Warning: Please note the edit option will replace the current values with '
                      f'updated values and not append to the end{Style.RESET}')
                if host_groups.get(host_index) == 'PUBLIC_RANGE' or host_groups.get(host_index) == 'ENDUSER_RANGE'\
                        or host_groups.get(host_index) == 'CRITICAL_RANGE':
                    get_input_cidr(host_index, host_groups, result)
                else:
                    get_input_idr(host_index, host_groups, result)
                is_external = False
                while not is_external:
                    more_edits = case_check(input('Do you want to edit more fields? y or n\n'))
                    if more_edits in ['y', 'n']:
                        is_external = True
                        if more_edits == 'y':
                            is_edit = False
                        else:
                            is_edit = True
                            print_formatted_output(host_groups, result)
                            write_file(result, smc_path)
                            confirm_captured_results(result)
                    else:
                        print(f'{Style.RED}Wrong value! Please input y or n{Style.RESET}')
            elif edit_field == 's':
                is_edit = True
                confirm_captured_results(result)
            else:
                print(f'{Style.RED}Wrong choice of input. Please enter number between 1-9 or "s" to skip {Style.RESET}')
    except Exception as error:
        logging.error(error)


def print_formatted_output(host_groups, result):
    """
    Function to validate smc.settings files for CIDR fields.
    Args:
        host_groups(dict): Dictionary holding all the valid host groups
        result(dict): Input result dictionary with all network parameters and boolean flags
    Returns:
        None
    Raises:
        Exception on key errors
    """
    try:
        print(f'---------EDIT/MODIFY THE CAPTURED VALUES---------------')
        print(f'-------------------------------------------------------')
        for key, value in host_groups.items():
            ips = result.get(value, None)
            if isinstance(ips, list):
                ips = ', '.join(ips)
            print(f'{key + 1}:\t{Style.MAGENTA}{value:<{len(max(host_groups.values(), key=len))}}:\t{Style.CYAN}{ips}'
                  f'{Style.RESET}')
        print(f'-------------------------------------------------------')
    except Exception as error:
        logging.error(error)


def get_input_cidr(host_index, host_groups, result):
    """
    Function to validate smc.settings files for CIDR fields.
    Args:
        host_index(int): Index of item from the host_groups dictionary
        host_groups(dict): Dictionary holding all the valid host groups
        result(dict): Input result dictionary with all network parameters and boolean flags
    Returns:
        result(dict): The updated result dictionary with network parameters
    Raises:
        Exception on Invalid IP addresses
    """
    try:
        is_internal = False
        parameter = host_groups.get(host_index)
        while not is_internal:
            if parameter == 'CRITICAL_RANGE':
                cidr_input = input(
                    "Enter the IP address(s) owned by your company in CIDR format comma separated or 'r' to "
                    "reset to None or 's' to exit without changes:\n").strip()
            else:
                cidr_input = input(
                    "Enter the IP address(s) owned by your company in CIDR format comma separated or 's' to "
                    "exit without changes:\n").strip()
            if parameter == 'CRITICAL_RANGE':
                if cidr_input == 'r':
                    if result.get(parameter):
                        result[parameter] = None
                        is_internal = True
                    elif result.get(parameter) is None:
                        print(f'{Style.RED}This field is already empty. Please validate your input once again{Style.RESET}')
                        is_internal = True
                elif cidr_input == 's':
                    is_internal = True
                elif len(cidr_input) > 0:
                    result, is_internal = cidr_ip_validation(parameter, cidr_input, result, is_internal)
            else:
                if cidr_input == 's':
                    is_internal = True
                elif len(cidr_input) > 0:
                    result, is_internal = cidr_ip_validation(parameter, cidr_input, result, is_internal)

    except Exception as error:
        logging.error(error)


def get_input_idr(host_index, host_groups, result):
    """
    Function to validate the smc.settings files for IP address fields.
    Args:
        host_index(int): Index of item from the host_groups dictionary
        host_groups(dict): Dictionary holding all the valid host groups
        result(dict): Input result dictionary with all network parameters and boolean flags
    Returns:
        result(dict): The updated result dictionary with network parameters
    Raises:
        Exception on Invalid IP addressesgit
    """
    try:
        is_internal = False
        parameter = host_groups.get(host_index)
        while not is_internal:

            if parameter in ['EXTERNAL_DNS', 'DHCP_SERVER', 'DOMAIN_CONTROLLER', 'EMAIL_SERVERS', 'CRITICAL_RANGE']:
                idr_input = input(
                    "Enter the IP address(s) comma separated or 'r' to reset field to None or 's' "
                    "to skip without changes:\n").strip()
                if idr_input == 'r':
                    if result.get(parameter):
                        result[parameter] = None
                        is_internal = True
                    elif result.get(parameter) is None:
                        print(f'This field is already empty. Please validate your input once again')
                        is_internal = True
                elif idr_input == 's':
                    is_internal = True

                elif len(idr_input) > 0:
                    result, is_internal = ip_validation(parameter, idr_input, result, is_internal)
            elif parameter in ['NAT_GATEWAY', 'INTERNAL_DNS']:
                idr_input = input(
                    "Enter the IP address(s) comma separated or 's' to skip without changes\n").strip()
                if idr_input == 's':
                    is_internal = True
                elif len(idr_input) > 0:
                    result, is_internal = ip_validation(parameter, idr_input, result, is_internal)
    except Exception as error:
        logging.error(error)


def get_mandatory_fields(result, man_fields):
    """
    Function to get the user to enter the mandatory fields as inputs.
    Args:
        result(dict): Input result dictionary with all network parameters and boolean flags
        man_fields(list): List of missing mandatory host groups
    Returns:
        result(dict): The updated result dictionary with network parameters
    Raises:
        Exception on Invalid IP addresses
    """
    if man_fields:
        for field in man_fields:
            if result.get(field) is None:
                if field in ['NAT_GATEWAY', 'INTERNAL_DNS']:
                    is_internal = False
                    while not is_internal:
                        if field == 'NAT_GATEWAY':
                            ip = \
                                case_check(
                                    input("Please enter NAT GATEWAY IP address(s) comma separated:\n"))
                        elif field == 'INTERNAL_DNS':
                            ip = \
                                case_check(
                                    input("Please enter INTERNAL DNS IP address(s) comma separated:\n"))

                        result, is_internal = ip_validation(field, ip, result, is_internal)

                if field in ['PUBLIC_RANGE', 'ENDUSER_RANGE']:
                    is_internal = False
                    while not is_internal:
                        if field == 'PUBLIC_RANGE':
                            ip = \
                                case_check(
                                    input("Please enter PUBLIC RANGE IP address(s) in CIDR format comma separated:\n"))
                        elif field == 'ENDUSER_RANGE':
                            ip = \
                                case_check(
                                    input("Please enter ENDUSER_RANGE IP address(s) in CIDR format comma separated:\n"))

                        result, is_internal = cidr_ip_validation(field, ip, result, is_internal)
        write_file(result, smc_path)


def confirm_mandatory_results(result: Dict):
    """
    Update the result dictionary with the confirmation flag that the details collected are accurate
    Args:
        result(dict): All the network host groups
    Returns:
        result(dict): result dictionary updated with the confirmation flag
    """

    logging.info('[%s] - Get confirmation on mandatory information.', datetime.datetime.today())
    try:
        is_mandatory = False
        host_group = ['NAT_GATEWAY', 'PUBLIC_RANGE', 'INTERNAL_DNS', 'EXTERNAL_DNS', 'DHCP_SERVER', 'DOMAIN_CONTROLLER',
                      'EMAIL_SERVERS', 'CRITICAL_RANGE', 'ENDUSER_RANGE']
        print(f'------------CONFIRMATION OF CAPTURED VALUES------------')
        print(f'-------------------------------------------------------')
        while not is_mandatory:
            for k in host_group:
                print(f' {Style.MAGENTA}{k:<{len(max(host_group,key=len))}}: '
                      f' {Style.CYAN}{",".join(result.get(k)) if isinstance(result.get(k),list) else result.get(k)} '
                      f'{Style.RESET}')
            print(f'-------------------------------------------------------')
            mandate = case_check(input(f"Please confirm smc.settings is correct: 'y' to post to smc or 'n' to "
                                       f"edit host groups?\n"))
            if mandate in ['y', 'n']:
                is_mandatory = True
            else:
                print(f'{Style.RED}Wrong value! Please input y or n{Style.RESET}')
        return mandate
    except Exception as error:
        logging.error(error)
        return mandate

