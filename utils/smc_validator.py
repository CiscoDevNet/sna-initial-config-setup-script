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

import ipaddress
from typing import List, Literal, Optional

from pydantic import BaseModel, validator


class InvalidIpAddressException(Exception):
    """
    A class that is used to raise the base Invalid IP address exception when the IP address is not valid
    """


class Smc(BaseModel):
    """
    A base class that is used to validate the data types for the output network parameters
    """
    nat_gateway_flag: Optional[Literal['y', 'n', 's']]
    public_range_flag: Optional[Literal['y', 'n', 's']]
    internal_dns_flag: Optional[Literal['y', 'n', 's']]
    external_dns_flag: Optional[Literal['y', 'n', 's']]
    internal_dhcp_flag: Optional[Literal['y', 'n', 's']]
    domain_control_flag: Optional[Literal['s']]
    mail_server_flag: Optional[Literal['s']]
    critical_subnet_flag: Optional[Literal['s']]
    confirmation_flag: Literal['y', 'n']
    NAT_GATEWAY: List[str]
    PUBLIC_RANGE: List[str]
    INTERNAL_DNS: List[str]
    EXTERNAL_DNS: Optional[List[str]]
    DHCP_SERVER: Optional[List[str]]
    DOMAIN_CONTROLLER: Optional[List[str]]
    EMAIL_SERVERS: Optional[List[str]]
    CRITICAL_RANGE: Optional[List[str]]
    ENDUSER_RANGE: List[str]
    smc_ip_address: Optional[str]
    username: Optional[str]
    password: Optional[str]

    @validator('DHCP_SERVER', 'INTERNAL_DNS', 'EXTERNAL_DNS', 'NAT_GATEWAY', 'DOMAIN_CONTROLLER', 'EMAIL_SERVERS',
               'CRITICAL_RANGE')
    def ip_validator(cls, v):
        try:
            if isinstance(v, str):
                ipaddress.ip_address(v)
            elif isinstance(v, list):
                [ipaddress.ip_address(e) for e in v]
            return v
        except ValueError as e:
            raise InvalidIpAddressException(f"Invalid IP address : {v}") from e
