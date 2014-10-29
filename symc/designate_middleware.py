# Copyright 2014 Symantec.
#
# Licensed under the Apache License, Version 2.0 (the "License"); you may
# not use this file except in compliance with the License. You may obtain
# a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
# WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
# License for the specific language governing permissions and limitations
# under the License.

import logging
import json
import requests
import __main__
import ConfigParser
from oslo.config import cfg

class DesignateMiddleware(object):
    def __init__(self, app, conf):
        self._logger = logging.getLogger(__name__)
        self._app = app
        self._conf = conf
        self._auth_user = cfg.CONF.keystone_authtoken.admin_user 
        self._auth_passwd = cfg.CONF.keystone_authtoken.admin_password
        self._admin_token = cfg.CONF.keystone_authtoken.admin_token
        self._admin_tenant = cfg.CONF.keystone_authtoken.admin_tenant_name
	self._auth_url = "%s://%s:%s/v2.0" %(cfg.CONF.keystone_authtoken.auth_protocol, 
		cfg.CONF.keystone_authtoken.auth_host,cfg.CONF.keystone_authtoken.auth_port)

    def _get_admin_token(self):
	self._logger.debug('TENANT( %s)', self._admin_tenant)
	self._logger.debug('URL( %s)', self._auth_url)
	body = {'auth' : {'tenantName': self._admin_tenant,
                'passwordCredentials': {'username': self._auth_user,
		'password': self._auth_passwd}}}
	url = '%s/tokens' %(self._auth_url)
	resp = requests.post(url, data=json.dumps(body),
				headers={'Content-Type': 'application/json',
					'Accept': 'application/json'})
	if resp.status_code == 200:
		admin_token = json.loads(resp.text)['access']['token']['id']
		#self._logger.info('Token generated( %s ).', admin_token)
		return admin_token

    def _find_dc_domain(self, env):
	dc_dom_name = '%s.' %(self._conf['fip_tld'].lower())
	self._admin_token = self._get_admin_token()
	url = '%s/domains' %(self._conf['designate_url'])
	resp = requests.get(url,
		headers={'X-Auth-Token': self._admin_token})
	if resp.status_code != 200:
		raise Exception('Auth failed, status %s, msg %s, env %s',
                	resp.status_code, resp.text, env)


	dc_domains = json.loads(resp.text)
	found = False
        dc_dom_id = None
	for dom in dc_domains.get('domains', []):
		self._logger.info('Check Dom name( %s ).', dom['name'])
		if dom['name'] == dc_dom_name:
			found = True
			dc_dom_id = dom['id']
			break

        return dc_dom_id

    def _get_fip_domain_name(self, env):
        proj_name = env['HTTP_X_PROJECT_NAME'].lower()
        fip_dom_name = '%s.%s' %(proj_name, self._conf['fip_tld'].lower())
        return fip_dom_name

    def _find_designate_server(self, X_Auth_Token, env):
	server_list = []
	token = X_Auth_Token
 	url = '%s/servers' %(self._conf['designate_url'])
	print "token is ",token
        resp = requests.get(url,
	    headers={'X-Auth-Token': token})
	if resp.status_code != 200:
            raise Exception('Auth failed, status %s, msg %s, env %s',
                resp.status_code, resp.text, env)	

	dsg_servers = json.loads(resp.text)
	for server in dsg_servers.get('servers', []):
		server_list.append(server['name'])

	return server_list	

    def _find_designate_domain(self, dom_name, env):
	dom_name = dom_name + '.'
        url = '%s/domains' %(self._conf['designate_url'])
        resp = requests.get(url,
            headers={'X-Auth-Token': env['HTTP_X_AUTH_TOKEN']})
        if resp.status_code != 200:
            raise Exception('Auth failed, status %s, msg %s, env %s',
                resp.status_code, resp.text, env)

        dsg_domains = json.loads(resp.text)
        found = False
        dom_id = None
        for dom in dsg_domains.get('domains', []):
            if dom['name'] == dom_name:
                found = True
                dom_id = dom['id']
                break

        return dom_id

    def _get_fip_rec_name(self, fip_addr, env):
        proj_name = env['HTTP_X_PROJECT_NAME'].lower()
        fip_rec_name = '%s.%s.%s' %(fip_addr.replace('.', '-'),
            proj_name, self._conf['fip_tld'].lower())

        return fip_rec_name

    def _find_designate_record(self, dom_id, rec_name, env):
	rec_name = rec_name + '.'
        url = '%s/domains/%s/records' %(self._conf['designate_url'], dom_id)
        resp = requests.get(url,
            headers={'X-Auth-Token': env['HTTP_X_AUTH_TOKEN']})
        if resp.status_code != 200:
            raise Exception('Auth failed, status %s, msg %s, env %s',
                resp.status_code, resp.text, env)

        dsg_records = json.loads(resp.text)
        found = False
        rec_id = None
        for rec in dsg_records.get('records', []):
            if rec['name'] == rec_name:
                found = True
                rec_id = rec['id']
                break

        return rec_id

    # Start _create_designate_domain
    def _create_designate_domain(self, dom_name, X_Auth_Token, email, ttl=3600):
	conf = self._conf
	dom_name = '%s.' %(dom_name.lower())
	#dom_name_format = dom_name.lower()
	token = X_Auth_Token 
	ttl = ttl
	email = email.lower()
	self._logger.debug('Designate domain %s not found, creating..', dom_name)
	body = {'name': dom_name,
		 'ttl': int(ttl),
		 'email': email}
	url = '%s/domains' %(conf['designate_url'])
	resp = requests.post(url, data=json.dumps(body),
		headers={'X-Auth-Token': token,
			    'Content-Type': 'application/json'})
	if resp.status_code == 200:
	 	dom_id = json.loads(resp.text)['id']
		self._logger.info('Designate domain %s created(id: %s).', dom_name, dom_id)
		return dom_id
	else:
		self._logger.error('Error in creating domain code %s msg %s', resp.status_code, resp.text)
		return
    # END of _create_designate_domain

    # Start of the _delete_designate_domain
    def _delete_designate_domain(self, dom_name, dom_id, X_Auth_Token):
	conf = self._conf
	dom_id = dom_id
	dom_name = dom_name
	token = X_Auth_Token
	url = conf['designate_url'] + '/domains/%s', dom_id
        resp = requests.delete(url,
                    headers={'X-Auth-Token': token,
                             'Content-Type': 'application/json'})
        if resp.status_code == 200:
                   self._logger.info('Designate domain(%s) with id %s deleted', dom_name, dom_id)
        else:
                   self._logger.error("Error designate domain(%s) delete, response status %s text %s" %(dom_name, resp.status_code, resp.text))
                   return
    # END of _delete_designate_domain

    # Start _create_designate_record
    def _create_designate_record(self, dom_id, rec_name, X_Auth_Token, rec_type, rec_ip, ttl=3600):
	conf = self._conf
	dom_id = dom_id
	rec_name = rec_name + '.'
	rec_type = rec_type.upper()
	token = X_Auth_Token
	fip_addr = rec_ip 
    	url = conf['designate_url'] + '/domains/%s/records' %(dom_id)
        body = {'name': rec_name,
                'type': rec_type,
                'data': fip_addr,
		'ttl': int(ttl) }
        resp = requests.post(url, data=json.dumps(body),
                 headers={'X-Auth-Token': token,
                             'Content-Type': 'application/json'})
        if resp.status_code == 200:
                 self._logger.info('Designate "%s" record "%s" created(addr: %s)' %(rec_type, rec_name, fip_addr))
        else:
                 self._logger.error("Error creating designate record(%s), response status %s text %s" %(rec_name, resp.status_code, resp.text))
                 return
    # END of _create_designate_record

    # Start _delete_designate_record
    def _delete_designate_record(self, dom_id, rec_name, rec_id, X_Auth_Token):
	conf = self._conf
	dom_id = dom_id
	rec_id = rec_id
	rec_name = rec_name
	token = X_Auth_Token
    	url = conf['designate_url'] + '/domains/%s/records/%s' %(dom_id, rec_id)
        resp = requests.delete(url,
                    headers={'X-Auth-Token': token,
                             'Content-Type': 'application/json'})
        if resp.status_code == 200:
                   self._logger.info('Designate A record %s deleted', rec_name)
        else:
                   self._logger.error("Error deleteing designate recored %s, response status %s text %s" %(rec_name, resp.status_code, resp.text))
                   return
    # End _delete_designate_record
        
    def __call__(self, env, start_response):
        def _d_start_response(status, headers, exc_info=None):
            try:
                if ('POST' in env.get('REQUEST_METHOD', '') and
                    '/floatingips' in env.get('PATH_INFO', '')):
                    self._logger.debug('status %s for floatingips post', status)
                    self._status = status.split(' ')[0]
                elif ('DELETE' in env.get('REQUEST_METHOD', '') and
                    '/floatingips' in env.get('PATH_INFO', '')):
                    self._logger.debug('status %s for floatingips delete', status)
                    self._status = status.split(' ')[0]
            finally:
                return start_response(status, headers, exc_info)

        conf = self._conf
        if ('DELETE' in env.get('REQUEST_METHOD', '') and
            '/floatingips' in env.get('PATH_INFO', '')):
            try:
                fip_url_base = conf.get('contrail_fip_url_base',
                                        'http://127.0.0.1:8082/floating-ip')
                fip_id = env['PATH_INFO'].split('/')[-1].replace('.json','')
                fip_url = '%s/%s' %(fip_url_base, fip_id)
                resp = requests.get(fip_url, headers={'X-Auth-Token': env['HTTP_X_AUTH_TOKEN']})
                if resp.status_code != 200:
                    raise Exception('status %s for floating ip read' %(resp.status_code))

                fip_dict = json.loads(resp.text)['floating-ip']
                self._logger.debug('Read in floating ip info of %s for delete of %s',
                                   fip_dict, fip_id)
            except Exception as e:
                self._logger.exception('Exception %s in reading floating ip info', e)

        app_iter = self._app(env, _d_start_response)
        try:
            if ('POST' in env.get('REQUEST_METHOD', '') and
                '/floatingips' in env.get('PATH_INFO', '')):
                if self._status not in ('200', '201'):
                    self._logger.error('Status %s in floating ip create', self._status)
                    return

		dc_dom_id = self._find_dc_domain(env)

		# Create dc_domain(dc.example.com) if does not exist!
		if not dc_dom_id:
		   dc_dom_name = self._conf['fip_tld']
		   admin_token = self._admin_token
		   email = 'admin@' + str(dc_dom_name)
		   ttl = conf.get('ttl', 3600)
		   dc_dom_id = self._create_designate_domain(dc_dom_name, admin_token, email, ttl)
		####

                fip_dom_name = self._get_fip_domain_name(env)
                fip_dom_id = self._find_designate_domain(fip_dom_name, env)

                if not fip_dom_id:
                    self._logger.debug('Designate domain %s not found, creating...', fip_dom_name)
		    ## Creating NS record in dc_domain(fip_tld)
		    #dsg_ns_srvs = self._find_designate_server(self._admin_token, env) #FIXME
		    dsg_ns_srvs = self._find_designate_server(env['HTTP_X_AUTH_TOKEN'], env)
		    if dsg_ns_srvs:
			for srv in dsg_ns_srvs:
		    		self._create_designate_record(dc_dom_id, fip_dom_name, self._admin_token,'NS', srv)
		    ###
		    email = 'admin@' + str(fip_dom_name)
		    ttl = conf.get('ttl', 3600)
		    fip_dom_id = self._create_designate_domain(fip_dom_name, env['HTTP_X_AUTH_TOKEN'], email, ttl)
		
                fip_dict = json.loads(app_iter[0])['floatingip']
                fip_addr = fip_dict['floating_ip_address']
                fip_rec_name = self._get_fip_rec_name(fip_addr, env)
		self._create_designate_record(fip_dom_id, fip_rec_name, env['HTTP_X_AUTH_TOKEN'], 'A', fip_addr)
### Need to complete DELETE
            elif ('DELETE' in env.get('REQUEST_METHOD', '') and
                  '/floatingips' in env.get('PATH_INFO', '')):
                if self._status not in ('200', '204'):
                    self._logger.error('Status %s in floating ip delete for %s',
                        self._status, env.get('PATH_INFO', ''))
                    return
                fip_dom_name = self._get_fip_domain_name(env)
                dom_id = self._find_designate_domain(fip_dom_name, env)
                if not dom_id:
                    self._logger.error('Designate domain %s not found', fip_dom_name)
                    return

                fip_addr = fip_dict['floating_ip_address']
                fip_rec_name = self._get_fip_rec_name(fip_addr, env)
                rec_id = self._find_designate_record(dom_id, fip_rec_name, env)
                if not rec_id:
                    self._logger.error('Designate record %s not found', fip_rec_name)

		self._delete_designate_record(dom_id, fip_rec_name, rec_id, env['HTTP_X_AUTH_TOKEN'])
        except Exception as e:
            self._logger.exception('Exception %s in %s floating ip to designate',
                e, env.get('REQUEST_METHOD', ''))
        finally:
            return app_iter

def designate_factory(global_conf, **local_conf):
    """Paste factory."""

    conf = global_conf.copy()
    conf.update(local_conf)

    def _factory(app):
        return DesignateMiddleware(app, conf)
    return _factory

