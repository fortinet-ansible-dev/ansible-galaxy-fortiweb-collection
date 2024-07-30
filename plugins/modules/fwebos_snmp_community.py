#!/usr/bin/python
#
# This file is part of Ansible
#
#
# updata date:2019/03/12

from __future__ import (absolute_import, division, print_function)
import json
from ansible_collections.fortinet.fortiweb.plugins.module_utils.network.fwebos.fwebos import (fwebos_argument_spec, is_global_admin)
from ansible.module_utils.connection import Connection
from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}


DOCUMENTATION = """
---
module: fwebos_snmp_community
short_description: Configure FortiWeb function by RESTful API
description:
  - Manage function on FortiWeb devices including creating, updating, removing function objects,
    All operations are performed RESTful API.
version_added: "2.8"
author: "Ansible by Red Hat (@rcarrillocruz)"
"""

EXAMPLES = """
"""

RETURN = """
"""

obj_url = '/api/v2.0/cmdb/system/snmp.community'


rep_dict = {
    'query_v1_status': 'query-v1-status',
    'query_vl_status_val': 'query-v1-status_val',
    'query_vl_port': 'query-v1-port',
    'query_v2c_status': 'query-v2c-status',
    'query_v2c_status_val': 'query-v2c-status_val',
    'query_v2c_port': 'query-v2c-port',
    'trap_v1_status': 'trap-v1-status',
    'trap_v1_status_val': 'trap-v1-status_val',
    'trap_v1_lport': 'trap-v1-lport',
    'trap_v1_rport': 'trap-v1-rport',
    'trap_v2c_status': 'trap-v2c-status',
    'trap_v2c_status_val': 'trap-v2c-status_val',
    'trap_v2c_lport': 'trap-v2c-lport',
    'trap_v2c_rport': 'trap-v2c-rport'
}


def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)


def add_obj(module, connection):
    # print('---zzg:add_obj\n')
    # module.log(msg='test!!!!!!!!!!!!!!!!!')
    # print(module.params)
    # print('---zzg:add_obj111\n')
    # raise Exception(module)
    # profile = module.params['profile']
    # password = module.params['password']

    payload1 = {}
    payload1['data'] = module.params
    payload1['data'].pop('action')
    replace_key(payload1['data'], rep_dict)

    code, response = connection.send_request(obj_url, payload1)

    return code, response


def edit_obj(module, payload, connection):
    name = module.params['id']
    url = obj_url + '?mkey=' + name
    code, response = connection.send_request(url, payload, 'PUT')

    return code, response


def get_obj(module, connection):
    name = module.params['id']
    payload = {}
    url = obj_url
    if name:
        url += '?mkey=' + name
    code, response = connection.send_request(url, payload, 'GET')

    # raise Exception(response)
    return code, response


def delete_obj(module, connection):
    name = module.params['id']
    payload = {}
    url = obj_url + '?mkey=' + name
    code, response = connection.send_request(url, payload, 'DELETE')

    return code, response


def combine_dict(src_dict, dst_dict):
    changed = False
    for key in dst_dict:
        if key in src_dict and src_dict[key] is not None and dst_dict[key] != src_dict[key]:
            dst_dict[key] = src_dict[key]
            changed = True

    return changed


def needs_update(module, data):
    res = False
    payload1 = {}
    payload1['data'] = module.params
    payload1['data'].pop('action')
    replace_key(payload1['data'], rep_dict)

    res = combine_dict(payload1['data'], data)

    return res, data


def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = ''

    if (action == 'add' or action == 'edit' or action == 'delete') and module.params['name'] is None:
        err_msg = 'name need to set'
        res = False
    # if (action == 'add' or action == 'edit' or action == 'delete') and module.params['name'] != str(connection.get_option('remote_user')):
    #    err_msg = 'name need to set'
    #    res = False

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        id=dict(type='str'),
        name=dict(type='str'),
        status=dict(type='str', default='enable'),
        status_val=dict(type='str', default='1'),
        sz_hosts=dict(type='int'),
        query_v1_status=dict(type='str'),
        query_vl_status_val=dict(type='str'),
        query_vl_port=dict(type='int'),
        query_v2c_status=dict(type='str'),
        query_v2c_status_val=dict(type='str'),
        query_v2c_port=dict(type='int'),
        trap_v1_status=dict(type='str'),
        trap_v1_status_val=dict(type='str'),
        trap_v1_lport=dict(type='int'),
        trap_v1_rport=dict(type='int'),
        trap_v2c_status=dict(type='str'),
        trap_v2c_status_val=dict(type='str'),
        trap_v2c_lport=dict(type='int'),
        trap_v2c_rport=dict(type='int'),
        events=dict(type='str'),
        events_val=dict(type='str')
    )
    argument_spec.update(fwebos_argument_spec)

    required_if = [('name')]
    module = AnsibleModule(argument_spec=argument_spec,
                           required_if=required_if)
    action = module.params['action']
    result = {}
    connection = Connection(module._socket_path)
    param_pass, param_err = param_check(module, connection)
    if not param_pass:
        result['err_msg'] = param_err
        result['failed'] = True
    elif action == 'add':
        code, response = add_obj(module, connection)
        result['res'] = response
        result['changed'] = True
    elif action == 'get':
        code, response = get_obj(module, connection)
        result['res'] = response
    elif action == 'edit':				
        code, data = get_obj(module, connection)
        if 'errcode' in str(data):
            result['changed'] = False
            result['res'] = data
        else:
            res, new_data = needs_update(module, data['results'])
            if res:
                new_data1 = {}
                new_data1['data'] = new_data
                code, response = edit_obj(module, new_data1, connection)
                result['res'] = response
                result['changed'] = True				
    elif action == 'delete':
        code, data = get_obj(module, connection)
        if 'errcode' in str(data):
            result['changed'] = False
            result['res'] = data
        else:
            code, response = delete_obj(module, connection)
            result['res'] = response
            result['changed'] = True
    else:
        result['err_msg'] = 'error action: ' + action
        result['failed'] = True

    if 'errcode' in str(result):
        result['changed'] = False
        result['failed'] = True
        if result['res']['results']['errcode'] == -3 or result['res']['results']['errcode'] == -5:
            result['failed'] = False


    module.exit_json(**result)


if __name__ == '__main__':
    main()
