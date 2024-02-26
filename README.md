# fortilib - a Python Library to interact with Fortigate Firewalls

This Python module contains the ability to get and configure following object on [Fortigate Firewalls](https://www.fortinet.com/products/next-generation-firewall):
* Addresses
* Address Groups
* Interfaces
* IPPools
* Policies
* Proxy Addresses
* Proxy Address Groups
* Proxy Policies
* Routes
* Services
* Service Groups
* Vips
* Vip Groups

## Installation
Python >= 3.8 is required.

Dependencies:
* [httpx](https://www.python-httpx.org/)

Simply install fortilib via pip:
```
> pip install fortilib
```

## Quickstart

```python
import ipaddress

from fortilib.firewall import FortigateFirewall
from fortilib.fortigateapi import FortigateFirewallApi
from fortilib.address import FortigateIpMask


api = FortigateFirewallApi(
    ipaddr="127.0.0.1", # firewall ip
    vdom="vdom", # use "root" if you dont have vdoms activated
    access_token="token",
    # username="username", #  alternative login with username
    # password="password", #  and password
)
firewall = FortigateFirewall("fw01", api)
firewall.login()

# load all objects from fortigate
firewall.get_all_objects()

# create an firewall address
address = FortigateIpMask()
address.name = "Test Address"
address.subnet = ipaddress.ip_network("127.0.0.1/32")

# add object to firewall
firewall.create_firewall_address(address)

# print all addresses on firewall
for address in firewall.addresses:
    print(address.name)
```

## Contributing

See [Contributing](CONTRIBUTING.md).

## License

GPLv3
