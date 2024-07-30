#!/usr/bin/python
#
# This file is part of Ansible
#
#
# updata date:2019/03/12

from __future__ import (absolute_import, division, print_function)
import json
from ansible_collections.fortinet.fortiweb.plugins.module_utils.network.fwebos.fwebos import (fwebos_argument_spec, is_global_admin, is_vdom_enable)
from ansible.module_utils.connection import Connection
from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}


DOCUMENTATION = """
module: fwebos_system_setting
description:
  - Configure system setting on FortiWeb devices via RESTful APIs
"""

EXAMPLES = """
"""

RETURN = """
"""


def get__sys_setting(module, connection):
    payload = {}
    code, response = connection.send_request(
        '/api/v2.0/system/admin.settings', payload, 'GET')

    return code, response['results']


def update_sys_setting(payload, connection):

    code, response = connection.send_request(
        '/api/v2.0/system/admin.settings', payload, 'PUT')

    return code, response


def needs_update(module, sys_setting):
    res = False

    if module.params['idle_timeout'] and module.params['idle_timeout'] != sys_setting['idleTimeout']:
        sys_setting['idleTimeout'] = module.params['idle_timeout']
        res = True
    if module.params['config_sync'] and module.params['config_sync'] != sys_setting['configSync']:
        sys_setting['configSync'] = module.params['config_sync']
        res = True
    # if module.params['intermediate_ca_group'] and module.params['intermediate_ca_group'] != sys_setting['default-intermediate-ca-group']:
    #    sys_setting['default-intermediate-ca-group'] = module.params['intermediate_ca_group']
    #    res = True
    if module.params['hostname'] and module.params['hostname'] != sys_setting['hostname']:
        sys_setting['hostname'] = module.params['hostname']
        res = True
    if module.params['http_port'] and module.params['http_port'] != sys_setting['http']:
        sys_setting['http'] = module.params['http_port']
        res = True
    if module.params['https_port'] and module.params['https_port'] != sys_setting['https']:
        sys_setting['https'] = module.params['https_port']
        res = True
    # if module.params['https_server_cert'] and module.params['https_server_cert'] != sys_setting['https-server-cert']:
    #    sys_setting['https-server-cert'] = module.params['https_server_cert']
    #    res = True
    if module.params['sys_global_language'] and module.params['sys_global_language'] != sys_setting['language']:
        sys_setting['language'] = module.params['sys_global_language']
        res = True
    out_data = sys_setting
    return res, out_data


def main():
    argument_spec = dict(
        idle_timeout=dict(type='str'),
        config_sync=dict(type='str'),
        intermediate_ca_group=dict(type='str'),
        hostname=dict(type='str'),
        http_port=dict(type='str'),
        https_port=dict(type='str'),
        https_server_cert=dict(type='str'),
        sys_global_language=dict(type='str'),
    )
    argument_spec.update(fwebos_argument_spec)

    required_if = []
    module = AnsibleModule(argument_spec=argument_spec,
                           required_if=required_if)
    connection = Connection(module._socket_path)
    result = {'changed': False}
    # if not is_global_admin(connection):
    if is_vdom_enable(connection):
        connection.change_auth_for_vdom("root")

    if 0:
        result['err_msg'] = 'The user is not global, can not access system setting config!'
        result['failed'] = True
    else:
        res, data = get__sys_setting(module, connection)
        update, update_data = needs_update(module, data)
        if update:
            payload = {}
            payload['data'] = update_data
            result['update_data'] = payload
            code, response = update_sys_setting(payload, connection)
            result['changed'] = True
            result['code'] = code
            result['res'] = response
        else:
            result['res'] = 'Do not update'
    module.exit_json(**result)


if __name__ == '__main__':
    main()
