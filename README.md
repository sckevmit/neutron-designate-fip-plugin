neutron-designate-fip-plugin
===========================

# Description
Create a domain and fip records automatically for multi-tenancy via designate. This means whenever a floating ip(fip) is created via neutron, a DNS domain for the tenent will be created if doesn't exist and a DNS 'A' record will be created in the tenant dns domain.

# Prerequisites

A working Desgnate and neutron services required

# Installation

```
1. git clone <project>  and copy symc dir to the python dist-packages or site-packages
2. change the config options as stated below
3. restart the neutron api service(/etc/init.d/neutron-api restart)
```

# Configuration

#### vim /etc/neutron/api-paste.ini

```
[filter:designate-extention]
paste.filter_factory = symc.designate_middleware:designate_factory
designate_url=http://<designate VIP/NODE>/v1
fip_tld=example.com # like a parent domain to create tenant dns domains.
ttl=3600
```
#### add the filter "designate-extention" to the [composite:neutronapi_v2_0] as below.
keystone = authtoken keystonecontext ```designate-extention``` extensions neutronapiapp_v2_0


# License

Copyright 2014 Symantec Corporation.

Licensed under the Apache License, Version 2.0 (the “License”); you may not use this file except in compliance with the License. You may obtain a copy of the license at

http://www.apache.org/license/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an “AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
