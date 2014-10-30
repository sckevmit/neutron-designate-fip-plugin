neutron-designate-fip-plugin
===========================

# Description

This middleware creates a domain and 'A' record automatically for floating IPs
in a multi-tenant environment via Designate. This means whenever a floating IP
(fip) is created via Neutron, a DNS domain for the tenant will be created if
it doesn't exist and a DNS 'A' record will be created in the tenant dns domain.

# Prerequisites

A working Designate and Neutron service is required.

# Installation

```
1. git clone https://github.com/Symantec/neutron-designate-fip-plugin.git
2. cd neutron-designate-fip-plugin/
3. sudo python setup.py install
4. Configure /etc/neutron/api-paste.ini as shown below
4. Restart Neutron api service
```

# Configuration

#### vim /etc/neutron/api-paste.ini

```
[filter:designate-extension]
paste.filter_factory = symc.designate_middleware:designate_factory
designate_url=http://<Designate endpoint>/v1
fip_tld=example.com #Parent domain to create tenant dns domains.
ttl=3600
```

Add the filter "designate-extension" to the [composite:neutronapi_v2_0] as
below:
```
keystone = authtoken keystonecontext designate-extension extensions neutronapiapp_v2_0
```

# License

Copyright 2014 Symantec Corporation.

Licensed under the Apache License, Version 2.0 (the “License”); you may not use
this file except in compliance with the License. You may obtain a copy of the
license at

http://www.apache.org/license/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed
under the License is distributed on an “AS IS" BASIS, WITHOUT WARRANTIES OR
CONDITIONS OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
