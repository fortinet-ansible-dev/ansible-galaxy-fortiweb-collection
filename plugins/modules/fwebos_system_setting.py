#!/usr/bin/python
#
# This file is part of Ansible
#
#
# updata date:2019/03/12

from __future__ import (absolute_import, division, print_function)
import json
from ansible_collections.fortinet.fortiweb.plugins.module_utils.network.fwebos.fwebos import (fwebos_argument_spec, is_global_admin, is_vdom_enable, check_mode_process)
from ansible.module_utils.connection import Connection
from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import ConnectionError
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}


DOCUMENTATION = """
---
module: fwebos_system_setting
short_description: Config System Administrators Settings in FortiWeb
description:
  - Config System Administrators Settings in FortiWeb
version_added: "7.0.0"
author:
  - Jie Li
  - Brad Zhang
requirements:
    - ansible>=2.11
options:
    hostname:
        description:
            - The Host Name
        type: string
    idle_timeout:
        description:
            - Type the number of minutes that a web UI connection can be idle before the administrator must log in again. 
        type: integer
"""

EXAMPLES = """
    - name: Manage system setting
      fwebos_system_setting:
       idle_timeout: 468
       hostname: testhost1


"""

RETURN = """
changed:
  description: Whether the status of FortiWeb is changed. The value is either 'true' or 'false'
  returned: always
  type: bool
invocation:
  description: The parameters in ansible tasks.
  returned: always
  type: JSON
res:
  description: The return from related Rest API.
  returned: always
  type: JSON
"""

rep_dict = {
    "https_server_cert": "httpsServerCertificate"
}

def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)

def get__sys_setting(module, connection):
    payload = {}
    code, response = connection.send_request(
        '/api/v2.0/system/admin.settings', payload, 'GET')

    return code, response['results']


def update_sys_setting(payload, connection):

    code, response = connection.send_request(
        '/api/v2.0/system/admin.settings', payload, 'PUT')

    return code, response

def param_check(module, connection):
    res = True
    err_msg = ''
    if module.params['idle_timeout'] and isinstance(module.params['idle_timeout'], int)== False:
        res = False
        err_msg = "\'idle_timeout\' needs to be an integer."
    return res, err_msg


def needs_update(module, sys_setting):
    res = False
    before = {}
    after = {}
    if module.params['idle_timeout'] and module.params['idle_timeout'] != sys_setting['idleTimeout']:
        before['idle_timeout'] = sys_setting['idleTimeout']
        after['idle_timeout'] = module.params['idle_timeout']
        sys_setting['idleTimeout'] = module.params['idle_timeout']
        res = True
    if module.params['config_sync'] and module.params['config_sync'] != sys_setting['configSync']:
        before['config_sync'] = sys_setting['configSync']
        after['config_sync'] = module.params['config_sync']
        sys_setting['configSync'] = module.params['config_sync']
        res = True
    if module.params['intermediate_ca_group'] and ('httpsIntermediateCertificate' not in sys_setting.keys() or module.params['intermediate_ca_group'] != sys_setting['httpsIntermediateCertificate']):
        if 'httpsIntermediateCertificate' not in sys_setting.keys():
            before['intermediate_ca_group'] = ''
        else:
            before['intermediate_ca_group'] = sys_setting['httpsIntermediateCertificate']
        after['intermediate_ca_group'] = module.params['intermediate_ca_group']
        sys_setting['httpsIntermediateCertificate'] = module.params['intermediate_ca_group']
        res = True
    if module.params['hostname'] and module.params['hostname'] != sys_setting['hostname']:
        before['hostname'] = sys_setting['hostname']
        after['hostname'] = module.params['hostname']
        sys_setting['hostname'] = module.params['hostname']
        res = True
    if module.params['http_port'] and module.params['http_port'] != sys_setting['http']:
        before['http_port'] = sys_setting['http']
        after['http_port'] = module.params['http_port']
        sys_setting['http'] = module.params['http_port']
        res = True
    if module.params['https_port'] and module.params['https_port'] != sys_setting['https']:
        before['https_port'] = sys_setting['https']
        after['https_port'] = module.params['https_port']
        sys_setting['https'] = module.params['https_port']
        res = True
    if module.params['https_server_cert'] and ('httpsServerCertificate' not in sys_setting.keys() or module.params['https_server_cert'] != sys_setting['httpsServerCertificate']):
        before['https_server_cert'] = sys_setting['httpsServerCertificate']
        after['https_server_cert'] = module.params['https_server_cert']
        sys_setting['httpsServerCertificate'] = module.params['https_server_cert']
        res = True
    if module.params['sys_global_language'] and module.params['sys_global_language'] != sys_setting['language']:
        before['sys_global_language'] = sys_setting['language']
        after['sys_global_language'] = module.params['sys_global_language']
        sys_setting['language'] = module.params['sys_global_language']
        res = True
    out_data = sys_setting
    return res, out_data, before, after


def main():
    argument_spec = dict(
        idle_timeout=dict(type='int'),
        config_sync=dict(type='str'),
        intermediate_ca_group=dict(type='str'),
        hostname=dict(type='str'),
        http_port=dict(type='int'),
        https_port=dict(type='int'),
        https_server_cert=dict(type='str'),
        sys_global_language=dict(type='str'),
    )
    argument_spec.update(fwebos_argument_spec)

    required_if = []
    module = AnsibleModule(argument_spec=argument_spec,
                           required_if=required_if,
                           supports_check_mode=True)
    connection = Connection(module._socket_path)

    param_pass, param_err = param_check(module, connection)

    result = {'changed': False}

    # if not is_global_admin(connection):
    if is_vdom_enable(connection):
        connection.change_auth_for_vdom("root")

    if 0:
        result['err_msg'] = 'The user is not global, can not access system setting config!'
        result['failed'] = True
    else:
        res, data = get__sys_setting(module, connection)
        update, update_data, before, after = needs_update(module, data.copy())

        if update:
            result['changed'] = True
            result['update_data'] = {'data': update_data}
            # Generate before/after diffs from relevant fields
            result['diff'] = {
                'before': before,
                'after': after
            }
            if not param_pass:
                result['err_msg'] = param_err
                result['failed'] = True
                module.exit_json(**result)

            if module.check_mode:
                result['res'] = 'Check mode: changes detected.'
            else:
                payload = {}
                payload = {'data': update_data}
                result['update_data'] = payload
                err = False
                result['changed'] = True
                try:
                    code, response = update_sys_setting(payload, connection)
                except ConnectionError as e:
                    err = True
        else:
            result['res'] = 'Do not update'
    module.exit_json(**result)


if __name__ == '__main__':
    main()