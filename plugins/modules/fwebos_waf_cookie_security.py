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
module: fwebos_waf_cookie_security
description:
  - Configure FortiWeb devices via RESTful APIs
"""

EXAMPLES = """
"""

RETURN = """
"""

obj_url = '/api/v2.0/cmdb/waf/cookie-security'


def add_obj(module, connection):
    name = module.params['name']
    security_mode = module.params['security_mode']
    cookie_replay_protection_type = module.params['cookie_replay_protection_type']
    allow_suspicious_cookies = module.params['allow_suspicious_cookies']
    allow_time_model = module.params['allow_time_model']
    cookie_action = module.params['cookie_action']
    severity = module.params['severity']
    block_period = module.params['block_period']
    max_age = module.params['max_age']
    http_only = module.params['http_only']
    secure_cookie = module.params['secure_cookie']
    samesite = module.params['samesite']
    samesite_value = module.params['samesite_value']
    allow_time = module.params['allow_time']

    payload = {
        'data':
        {
            'name': name,
            'security-mode': security_mode,
            'cookie-replay-protection-type': cookie_replay_protection_type,
            'allow-suspicious-cookies': allow_suspicious_cookies,
            'allow-time-model': allow_time_model,
            'action': cookie_action,
            'severity': severity,
            'block-period': block_period,
            'max-age': max_age,
            'http-only': http_only,
            'secure-cookie': secure_cookie,
            'samesite': samesite,
            'samesite-value': samesite_value,
            'allow-time': allow_time,
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
    if module.params['security_mode'] and module.params['security_mode'] != data['security-mode']:
        data['security-mode'] = module.params['security_mode']
        res = True
    if module.params['cookie_replay_protection_type'] and module.params['cookie_replay_protection_type'] != data['cookie-replay-protection-type']:
        data['cookie-replay-protection-type'] = module.params['cookie_replay_protection_type']
        res = True
    if module.params['allow_suspicious_cookies'] and module.params['allow_suspicious_cookies'] != data['allow-suspicious-cookies']:
        data['allow-suspicious-cookies'] = module.params['allow_suspicious_cookies']
        res = True
    if module.params['allow_time_model'] and module.params['allow_time_model'] != data['allow-time-model']:
        data['allow-time-model'] = module.params['allow_time_model']
        res = True
    if module.params['cookie_action'] and module.params['cookie_action'] != data['action']:
        data['action'] = module.params['cookie_action']
        res = True
    if module.params['severity'] and module.params['severity'] != data['severity']:
        data['severity'] = module.params['severity']
        res = True
    if module.params['block_period'] and module.params['block_period'] != data['block-period']:
        data['block-period'] = module.params['block_period']
        res = True
    if module.params['max_age'] and module.params['max_age'] != data['max-age']:
        data['max-age'] = module.params['max_age']
        res = True
    if module.params['http_only'] and module.params['http_only'] != data['http-only']:
        data['http-only'] = module.params['http_only']
        res = True
    if module.params['secure_cookie'] and module.params['secure_cookie'] != data['secure-cookie']:
        data['secure-cookie'] = module.params['secure_cookie']
        res = True
    if module.params['samesite'] and module.params['samesite'] != data['samesite']:
        data['samesite'] = module.params['samesite']
        res = True
    if module.params['samesite_value'] and module.params['samesite_value'] != data['samesite-value']:
        data['samesite-value'] = module.params['samesite_value']
        res = True
    if module.params['allow_time'] and module.params['allow_time'] != data['allow-time']:
        data['allow-time'] = module.params['allow_time']
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
        security_mode=dict(type='str', default='no'),
        cookie_replay_protection_type=dict(type='str', default='IP'),
        allow_suspicious_cookies=dict(type='str', default='Custom'),
        allow_time_model=dict(type='str', default='2022-04-25T15:05:12.000Z'),
        cookie_action=dict(type='str', default='alert'),
        severity=dict(type='str', default='Medium'),
        block_period=dict(type='str', default='600'),
        max_age=dict(type='str', default='0'),
        http_only=dict(type='str', default='disable'),
        secure_cookie=dict(type='str', default='disable'),
        samesite=dict(type='str', default='disable'),
        samesite_value=dict(type='str', default='Lax'),
        allow_time=dict(type='str', default='2022/04/25'),
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
        result['out'] = out,
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
            code, response = edit_obj(module, new_data, connection)
            result['new_data'] = new_data
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

    result['name'] = module.params['name']
    module.exit_json(**result)


if __name__ == '__main__':
    main()
