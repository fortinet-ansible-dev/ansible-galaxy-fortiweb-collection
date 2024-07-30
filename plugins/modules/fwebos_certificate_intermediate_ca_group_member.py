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
---
module: fwebos_certificate_intermediate_ca_group_member
description:
  - Configure FortiWeb devices via RESTful APIs
"""

EXAMPLES = """
"""

RETURN = """
"""

obj_url = '/api/v2.0/cmdb/system/certificate.intermediate-certificate-group/members'

rep_dict = {
}


def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)


def add_obj(module, connection):
    table_name = module.params['table_name']
    payload1 = {}
    payload1['data'] = module.params
    payload1['data'].pop('action')
    payload1['data'].pop('vdom')
    payload1['data'].pop('table_name')
    payload1['data'].pop('id')
    replace_key(payload1['data'], rep_dict)
    for key in list(payload1['data']):
        if not payload1['data'][key]:
            payload1['data'].pop(key)

    url = obj_url + '?mkey=' + table_name

    # raise Exception(url)
    # raise Exception(payload1)
    code, response = connection.send_request(url, payload1)

    return code, response


def edit_obj(module, payload, connection):
    table_name = module.params['table_name']
    name = module.params['id']
    url = obj_url + '?mkey=' + table_name + '&sub_mkey=' + name
    for key in list(payload['data']):
        if not payload['data'][key]:
            payload['data'].pop(key)

    code, response = connection.send_request(url, payload, 'PUT')

    return code, response


def get_obj(module, connection):
    table_name = module.params['table_name']
    name = module.params['id']
    payload = {}
    url = obj_url
    if name:
        url += '?mkey=' + table_name + '&sub_mkey=' + name
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_obj(module, connection):
    table_name = module.params['table_name']
    name = module.params['id']
    payload = {}
    url = obj_url + '?mkey=' + table_name + '&sub_mkey=' + name
    # raise Exception(url)
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

    if (action == 'add' or action == 'edit' or action == 'delete') and module.params['table_name'] is None:
        err_msg = 'table_name need to set'
        res = False

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        vdom=dict(type='str'),
        table_name=dict(type='str'),
        name=dict(type='str'),
        id=dict(type='str'),
    )
    argument_spec.update(fwebos_argument_spec)

    required_if = [('name')]
    module = AnsibleModule(argument_spec=argument_spec,
                           required_if=required_if)
    action = module.params['action']
    result = {}
    connection = Connection(module._socket_path)
    param_pass, param_err = param_check(module, connection)
    if is_vdom_enable(connection) and param_pass:
        connection.change_auth_for_vdom(module.params['vdom'])

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

    # if 'res' in result.keys() and type(result['res']) is dict\
    #        and type(result['res']['results']) is int and result['res']['results'] < 0:
        # result['err_msg'] = get_err_msg(connection, result['res']['payload'])
    #    result['changed'] = False
    #    result['failed'] = True

    module.exit_json(**result)


if __name__ == '__main__':
    main()
