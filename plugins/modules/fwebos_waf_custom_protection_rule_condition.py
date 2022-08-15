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
module: fwebos_waf_custom_protection_rule_condition
description:
  - Configure FortiWeb devices via RESTful APIs
"""

EXAMPLES = """
"""

RETURN = """
"""

obj_url = '/api/v2.0/cmdb/waf/custom-protection-rule/meet-condition'


def add_obj(module, connection):

    table_name = module.params['table_name']
    name = module.params['name']
    operator = module.params['operator']
    threshold = module.params['threshold']
    case_sensitive = module.params['case_sensitive']
    expression = module.params['expression']
    request_target = module.params['request_target']

    payload = {
        'data':
        {
            'operator': operator,
            'threshold': threshold,
            'case-sensitive': case_sensitive,
            'expression': expression,
            'request-target': request_target,
        },
    }

    url = obj_url + '?mkey=' + table_name

    code, response = connection.send_request(url, payload)

    return code, response, payload


def edit_obj(module, payload, connection):
    table_name = module.params['table_name']
    name = module.params['name']
    url = obj_url + '?mkey=' + table_name + '&sub_mkey=' + name
    code, response = connection.send_request(url, payload, 'PUT')

    return code, response


def get_obj(module, connection):
    table_name = module.params['table_name']
    name = module.params['name']
    payload = {}
    url = obj_url + '?mkey=' + table_name
    if name:
        url += '&sub_mkey=' + name
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_obj(module, connection):
    table_name = module.params['table_name']
    name = module.params['name']
    payload = {}
    url = obj_url + '?mkey=' + table_name + '&sub_mkey=' + name
    code, response = connection.send_request(url, payload, 'DELETE')

    return code, response


def needs_update(module, data):
    res = False

    if module.params['operator'] and module.params['operator'] != data['operator']:
        data['operator'] = module.params['operator']
        res = True
    if module.params['threshold'] and module.params['threshold'] != data['threshold']:
        data['threshold'] = module.params['threshold']
        res = True
    if module.params['case_sensitive'] and module.params['case_sensitive'] != data['case-sensitive']:
        data['case-sensitive'] = module.params['case_sensitive']
        res = True
    if module.params['expression'] and module.params['expression'] != data['expression']:
        data['expression'] = module.params['expression']
        res = True
    if module.params['request_target'] and module.params['request_target'] != data['request-target']:
        data['request-target'] = module.params['request_target']
        res = True

    out_data = {}
    out_data['data'] = data
    return res, out_data


def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = ''

    if (action == 'add' or action == 'edit' or action == 'delete') and module.params['table_name'] is None:
        err_msg = 'table_name need to set'
        res = False
    # if (action == 'add' or action == 'edit' or action == 'delete') and module.params['name'] != str(connection.get_option('remote_user')):
    #    err_msg = 'name need to set'
    #    res = False

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        table_name=dict(type='str'),
        name=dict(type='str'),
        operator=dict(type='str'),
        threshold=dict(type='str', default='0'),
        case_sensitive=dict(type='str', default='disable'),
        expression=dict(type='str'),
        request_target=dict(type='str'),
        vdom=dict(type='str'),

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
        code, response, out_data = add_obj(module, connection)
        result['res'] = response
        result['changed'] = True
    elif action == 'get':
        code, response = get_obj(module, connection)
        result['res'] = response
    elif action == 'edit':
        code, data = get_obj(module, connection)
        result['old'] = data
        if code != 500 and 'results' in data.keys() and data['results'] and type(data['results']) is not int:
            res, new_data = needs_update(module, data['results'])
            result['out'] = new_data
        else:
            result['failed'] = True
            res = False
            result['err_msg'] = 'Entry not found'
        if res:
            code, response = edit_obj(module, new_data, connection)
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

    if 'errcode' in str(result):
        result['changed'] = False
        result['failed'] = True
        result['err_msg'] = 'Please check error code'

    module.exit_json(**result)


if __name__ == '__main__':
    main()
