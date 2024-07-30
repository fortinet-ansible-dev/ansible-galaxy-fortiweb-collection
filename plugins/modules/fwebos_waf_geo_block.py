#!/usr/bin/python
#
# This file is part of Ansible
#
#
# updata date:2019/03/12

from __future__ import (absolute_import, division, print_function)
import json
from ansible_collections.fortinet.fortiweb.plugins.module_utils.network.fwebos.fwebos import (fwebos_argument_spec, is_global_admin, is_vdom_enable)
# from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fwebos.fwebos import get_err_msg
# from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fwebos.fwebos import list_to_str
# from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fwebos.fwebos import list_need_update
# from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fwebos.fwebos import is_vdom_enable
# from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fwebos.fwebos import is_user_in_vdom
from ansible.module_utils.connection import Connection
from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}


DOCUMENTATION = """
module: fwebos_waf_geo_block
description:
  - Configure FortiWeb devices via RESTful APIs
"""

EXAMPLES = """
"""

RETURN = """
"""

obj_url = '/api/v2.0/cmdb/waf/geo-block-list'


def add_obj(module, connection):
    name = module.params['name']
    ip_action = module.params['ip_action']
    block_period = module.params['block_period']
    severity = module.params['severity']
    ignore_x_forwarded_for = module.params['ignore_x_forwarded_for']
    trigger = module.params['trigger']
    exception_rule = module.params['exception_rule']

    payload = {
        'data':
        {
            'name': name,
            'action': ip_action,
            'block-period': block_period,
            'severity': severity,
            'ignore-x-forwarded-for': ignore_x_forwarded_for,
            'trigger': trigger,
            'exception-rule': exception_rule,
        },
    }

    code, response = connection.send_request(obj_url, payload)

    return code, response, payload


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

    return code, response


def delete_obj(module, connection):
    name = module.params['name']
    payload = {}
    url = obj_url + '?mkey=' + name
    code, response = connection.send_request(url, payload, 'DELETE')

    return code, response


def needs_update(module, data):
    res = False

    if module.params['ip_action'] and module.params['ip_action'] != data['action']:
        data['action'] = module.params['ip_action']
        res = True
    if module.params['severity'] and module.params['severity'] != data['severity']:
        data['severity'] = module.params['severity']
        res = True
    if module.params['ignore_x_forwarded_for'] and module.params['ignore_x_forwarded_for'] != data['ignore-x-forwarded-for']:
        data['ignore-x-forwarded-for'] = module.params['ignore_x_forwarded_for']
        res = True
    if module.params['trigger'] and module.params['trigger'] != data['trigger']:
        data['trigger'] = module.params['trigger']
        res = True
    if module.params['block_period'] and module.params['block_period'] != data['block-period']:
        data['block-period'] = module.params['block_period']
        res = True
    if module.params['exception_rule'] and module.params['exception_rule'] != data['exception-rule']:
        data['exception-rule'] = module.params['exception_rule']
        res = True

    out_data = {}
    out_data['data'] = data
    return res, out_data


def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = ''

    if (action == 'add' or action == 'edit' or action == 'delete') and module.params['name'] is None:
        err_msg = 'name need to set'
        res = False
    if is_vdom_enable(connection) and module.params['vdom'] is None:
        err_msg = 'vdom enable, vdom need to set'
        res = False

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
        ip_action=dict(type='str', default='block-period'),
        block_period=dict(type='str', default='60'),
        severity=dict(type='str', default='Low'),
        ignore_x_forwarded_for=dict(type='str', default='disable'),
        trigger=dict(type='str', default=''),
        exception_rule=dict(type='str', default=''),
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
        code, response, out = add_obj(module, connection)
        # result['out'] = json.dumps(out),
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
                result['new_data'] = new_data
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

    result['name'] = module.params['name']
    module.exit_json(**result)


if __name__ == '__main__':
    main()
