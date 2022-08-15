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
module: fwebos_snmp_user_default
description:
  - Configure FortiWeb devices via RESTful APIs
"""

EXAMPLES = """

"""

RETURN = """
"""

obj_url = '/api/v2.0/cmdb/system/snmp.user'


rep_dict = {
    'security_level': 'security-level',
    'security_level_val': 'security-level_val',
    'auth_proto': 'auth-proto',
    'auth_proto_val': 'auth-proto_val',
    'auth_pwd': 'auth-pwd',
    'priv_proto': 'priv-proto',
    'priv_proto_val': 'priv-proto_val',
    'priv_pwd': 'priv-pwd',
    'query_status': 'query-status',
    'query_status_val': 'query-status_val',
    'query_port': 'query-port',
    'trap_status': 'trap-status',
    'trap_status_val': 'trap-status_val',
    'trapport_local': 'trapport-local',
    'trapport_remote': 'trapport-remote',
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
    name = module.params['name']
    url = obj_url + '?mkey=' + name
    code, response = connection.send_request(url, payload, 'PUT')

    return code, response


def get_obj(module, connection):
    name = module.params['name']
    payload = {}
    url = obj_url
    if name:
        url += '?mkey=' + name
    code, response = connection.send_request(url, payload, 'GET')

    # raise Exception(response)
    return code, response


def delete_obj(module, connection):
    name = module.params['name']
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
        name=dict(type='str'),
        status=dict(type='str', default="enable"),
        status_val=dict(type='str', default="1"),
        security_level=dict(type='str', default="noauthnopriv"),
        security_level_val=dict(type='str', default="1"),
        auth_proto=dict(type='str', default="sha1"),
        auth_proto_val=dict(type='str', default="1"),
        auth_pwd=dict(type='str', default="ENC XXXX"),
        priv_proto=dict(type='str', default="aes"),
        priv_proto_val=dict(type='str', default="1"),
        priv_pwd=dict(type='str', default="ENC XXXX"),
        query_status=dict(type='str', default="enable"),
        query_status_val=dict(type='str', default="1"),
        query_port=dict(type='int', default=161),
        trap_status=dict(type='str', default="enable"),
        trap_status_val=dict(type='str', default="1"),
        trapport_local=dict(type='int', default=162),
        trapport_remote=dict(type='int', default=162),
        trapevent=dict(type='str', default=""),
        trapevent_val=dict(type='str', default="0"),
        sz_hosts=dict(type='int', default=-1)
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
        if 'results' in data.keys() and data['results'] and type(data['results']) is not int:
            res, new_data = needs_update(module, data['results'])
        else:
            result['failed'] = True
            res = False
            result['err_msg'] = 'Entry not found'
        if res:
            new_data1 = {}
            new_data1['data'] = new_data
            code, response = edit_obj(module, new_data1, connection)
            result['res'] = response
            result['changed'] = True
    elif action == 'delete':
        code, data = get_obj(module, connection)
        if 'results' in data.keys() and data['results'] and type(data['results']) is not int:
            code, response = delete_obj(module, connection)
            result['res'] = response
            result['changed'] = True
        else:
            result['failed'] = True
            res = False
            result['err_msg'] = 'Entry not found'
    else:
        result['err_msg'] = 'error action: ' + action
        result['failed'] = True

    # if 'res' in result.keys() and type(result['res']) is dict\
    #        and type(result['res']['results']) is int and result['res']['results'] < 0:
        # result['err_msg'] = get_err_msg(connection, result['res']['payload'])
    #    result['changed'] = False
    #    result['failed'] = True
    if 'errcode' in str(result):
        result['changed'] = False
        result['failed'] = True
    module.exit_json(**result)


if __name__ == '__main__':
    main()
