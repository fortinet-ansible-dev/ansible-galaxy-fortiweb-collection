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
module: fwebos_waf_cookie_security
description:
  - Config FortiWeb Web Protection Cookie Security
version_added: "7.0.0"
authors:
  - Jie Li
  - Brad Zhang
requirements:
    - ansible>=2.11
options:
    name:
        description:
            - name
        type: string
    security-mode:
        description:
            - security mode
        type: string
        choices:
            - 'no'
            - 'encrypted'
            - 'signed'
    action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'remove_cookie'
            - 'block-period'
            - 'client-id-block-period'
    block-period:
        description:
            - action block period(1-3600) (range: 1-3600)
        type: integer
    severity:
        description:
            - High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    cookie-replay-protection-type:
        description:
            - cookie replay protection type
        type: string
        choices:
            - 'no'
            - 'IP'
    max-age:
        description:
            - max-age(0-65535) (range: 0-65535)
        type: integer
    secure-cookie:
        description:
            - secure cookie
        type: string
        choices:
            - 'enable'
            - 'disable'
    http-only:
        description:
            - http only
        type: string
        choices:
            - 'enable'
            - 'disable'
    allow-suspicious-cookies:
        description:
            - allow suspicious cookies
        type: string
        choices:
            - 'Never'
            - 'Always'
            - 'Custom'
    samesite:
        description:
            - samesite: enable/disable
        type: string
        choices:
            - 'enable'
            - 'disable'
    samesite-value:
        description:
            - samesite value
        type: string
        choices:
            - 'Strict'
            - 'Lax'
            - 'None'
"""

EXAMPLES = """
     - name: delete
       fwebos_waf_cookie_security:
        action: delete
        vdom: root
        name: test

     - name: Create
       fwebos_waf_cookie_security:
        action: add
        vdom: root
        security_mode: encrypted
        cookie_replay_protection_type: IP
        allow_suspicious_cookies: Custom
        allow_time_model: 2022-10-28T17:11:54.000Z
        security_action: alert
        severity: Medium
        block_period: 600
        max_age: 0
        http_only: disable
        name: test
        trigger: test
        allow_time: 2022/10/28

     - name: edit
       fwebos_waf_cookie_security:
        action: edit
        vdom: root
        security_mode: encrypted
        cookie_replay_protection_type: IP
        allow_suspicious_cookies: Custom
        allow_time_model: 2022-10-28T17:11:54.000Z
        security_action: alert
        severity: Medium
        block_period: 600
        max_age: 0
        http_only: disable
        name: test
        trigger: test
        allow_time: 2022/10/27


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

obj_url = '/api/v2.0/cmdb/waf/cookie-security'

rep_dict = {
    'security_mode': 'security-mode',
    'cookie_replay_protection_type': 'cookie-replay-protection-type',
    'allow_suspicious_cookies': 'allow-suspicious-cookies',
    'allow_time_model': 'allow-time-model',
    'block_period': 'block-period',
    'max_age': 'max-age',
    'http_only': 'http-only',
    'allow_time': 'allow-time',
    'security_action': 'action',
}


def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)


def add_obj(module, connection):
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

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        vdom=dict(type='str'),
        security_mode=dict(type='str'),
        cookie_replay_protection_type=dict(type='str'),
        allow_suspicious_cookies=dict(type='str'),
        allow_time_model=dict(type='str'),
        security_action=dict(type='str'),
        severity=dict(type='str'),
        block_period=dict(type='int'),
        max_age=dict(type='int'),
        http_only=dict(type='str'),
        name=dict(type='str'),
        trigger=dict(type='str'),
        allow_time=dict(type='str'),
    )
    argument_spec.update(fwebos_argument_spec)

    required_if = [('name')]
    module = AnsibleModule(argument_spec=argument_spec,
                           required_if=required_if)
    action = module.params['action']
    result = {}
    connection = Connection(module._socket_path)
    param_pass, param_err = param_check(module, connection)
    try:
        if is_vdom_enable(connection) and param_pass:
            connection.change_auth_for_vdom(module.params['vdom'])
    except Exception as e:
        error_msg = f"Checking VDOM failed. {e}"
        result['changed'] = False
        result['failed'] = True
        result['err_msg'] = error_msg   
        module.exit_json(**result)

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
