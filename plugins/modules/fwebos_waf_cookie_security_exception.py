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
module: fwebos_waf_cookie_security_exception
description:
  - Configure FortiWeb devices via RESTful APIs
"""

EXAMPLES = """
"""

RETURN = """
"""

obj_url = '/api/v2.0/cmdb/waf/cookie-security/cookie-security-exception-list'


def add_obj(module, connection):

    table_name = module.params['table_name']
    name = module.params['name']
    cookie_name = module.params['cookie_name']
    cookie_domain = module.params['cookie_domain']
    cookie_path = module.params['cookie_path']

    payload = {
        'data':
        {
            'cookie-name': cookie_name,
            'cookie-domain': cookie_domain,
            'cookie-path': cookie_path,
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

    if module.params['cookie_name'] and module.params['cookie_name'] != data['cookie-name']:
        data['cookie-name'] = module.params['cookie_name']
        res = True
    if module.params['cookie_domain'] and module.params['cookie_domain'] != data['cookie-domain']:
        data['cookie-domain'] = module.params['cookie_domain']
        res = True
    if module.params['cookie_path'] and module.params['cookie_path'] != data['cookie-path']:
        data['cookie-path'] = module.params['cookie_path']
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
        cookie_name=dict(type='str'),
        cookie_domain=dict(type='str'),
        cookie_path=dict(type='str'),
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
        if 'errcode' in str(data):
            result['changed'] = False
            result['res'] = data
        else:
            res, new_data = needs_update(module, data['results'])
            if res:
                code, response = edit_obj(module, new_data, connection)
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
        result['err_msg'] = 'Please check error code'
        if result['res']['results']['errcode'] == -3 or result['res']['results']['errcode'] == -5:
            result['failed'] = False

    module.exit_json(**result)


if __name__ == '__main__':
    main()
