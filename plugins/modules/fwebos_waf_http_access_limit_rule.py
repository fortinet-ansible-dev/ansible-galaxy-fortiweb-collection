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
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}


DOCUMENTATION = """
---
module: fwebos_waf_http_access_limit_rule
short_description: Config FortiWeb HTTP Access Limit Rule
description:
  - Config FortiWeb HTTP Access Limit Rule
version_added: "7.0.0"
author:
  - Joseph Chen
requirements:
    - ansible>=2.11
options:
    name:
        description:
            - The name of the HTTP access limit rule.
        type: string
    access_limit_standalone_ip:
        description:
            - Access limit for a standalone IP address.
        type: integer
    access_limit_share_ip:
        description:
            - Access limit for a shared IP address.
        type: integer
    access_action:
        description:
            - Action.
        type: string
        choices:
            - 'alert'
            - 'alert_deny'
            - 'deny_no_log'
            - 'block-period'
    block_period:
        description:
            - Block period.
        type: integer
    severity:
        description:
            - Severity.
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    trigger_policy:
        description:
            - Trigger policy name.
        type: string
    exception:
        description:
            - Exception policy name.
        type: string
    bot_confirmation:
        description:
            - Enable or disable bot confirmation.
        type: string
        choices:
            - 'enable'
            - 'disable'
    bot_recognition:
        description:
            - Browser verification method.
        type: string
        choices:
            - 'disabled'
            - 'real-browser-enforcement'
            - 'captcha-enforcement'
            - 'captcha-puzzle-enforcement'
            - 'recaptcha-enforcement'
            - 'recaptcha-v3-enforcement'
    validation_timeout:
        description:
            - Validation timeout.
        type: integer
    max_attempt_times:
        description:
            - Maximum attempt times.
        type: integer
    recaptcha_server:
        description:
            - reCAPTCHA server.
        type: string
    mobile_app_identification:
        description:
            - Mobile app verification method.
        type: string
        choices:
            - 'disabled'
            - 'mobile-token-validation'
"""

EXAMPLES = """
    - name: add an HTTP access limit rule
      fwebos_waf_http_access_limit_rule:
       action: add
       name: htl1
       access_limit_standalone_ip: 31413
       access_limit_share_ip: 3333
       access_action: alert_deny
       block_period: 600
       severity: Medium
       trigger_policy: trigger_policy1
       exception: exception_policy1
       bot_confirmation: disable
       bot_recognition: disabled
       validation_timeout: 20
       max_attempt_times: 3
       mobile_app_identification: disabled

    - name: edit an HTTP access limit rule
      fwebos_waf_http_access_limit_rule:
       action: edit
       name: htl1
       access_limit_standalone_ip: 500
       access_limit_share_ip: 1000
       access_action: block-period
       block_period: 600
       severity: High

    - name: get an HTTP access limit rule
      fwebos_waf_http_access_limit_rule:
       action: get
       name: htl1

    - name: delete an HTTP access limit rule
      fwebos_waf_http_access_limit_rule:
       action: delete
       name: htl1
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

obj_url = '/api/v2.0/cmdb/waf/layer4-access-limit-rule'


rep_dict = {
    'access_limit_standalone_ip': 'access-limit-standalone-ip',
    'access_limit_share_ip': 'access-limit-share-ip',
    'access_action': 'action',
    'block_period': 'block-period',
    'trigger_policy': 'trigger-policy',
    'exception_policy': 'exception',
    'bot_confirmation': 'bot-confirmation',
    'bot_recognition': 'bot-recognition',
    'validation_timeout': 'validation-timeout',
    'max_attempt_times': 'max-attempt-times',
    'recaptcha_server': 'recaptcha-server',
    'mobile_app_identification': 'mobile-app-identification',
}


def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)


def build_data(module):
    data = {}
    for key, value in module.params.items():
        if key not in ['action', 'vdom'] and value is not None:
            data[key] = value
    replace_key(data, rep_dict)
    return data


def result_data(data, name=None):
    if data is None or 'results' not in data:
        return None
    results = data['results']
    if isinstance(results, dict):
        return results
    if isinstance(results, list):
        if name is None:
            return results
        for item in results:
            if isinstance(item, dict) and item.get('name') == name:
                return item
    return None


def data_for_check_mode(data, name=None):
    item = result_data(data, name)
    if isinstance(item, dict):
        return {'results': item}
    return {'results': []}


def add_obj(module, connection):
    payload1 = {}
    payload1['data'] = build_data(module)
    code, response = connection.send_request(obj_url, payload1)

    return code, response, payload1['data']


def edit_obj(module, payload, connection):
    name = module.params['name']
    url = obj_url + '?mkey=' + name
    payload1 = {}
    payload1['data'] = payload
    code, response = connection.send_request(url, payload1, 'PUT')

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


def compare_value(key, old_value, new_value):
    if isinstance(old_value, str) and isinstance(new_value, str):
        return old_value.rstrip() == new_value.rstrip()
    return old_value == new_value


def combine_dict(src_dict, dst_dict):
    changed = False
    for key in dst_dict:
        if key in src_dict and src_dict[key] is not None and not compare_value(key, dst_dict[key], src_dict[key]):
            dst_dict[key] = src_dict[key]
            changed = True

    return changed


def needs_update(module, data):
    payload1 = {}
    payload1['data'] = build_data(module)
    res = combine_dict(payload1['data'], data)

    return res, data


def value_check(params, key_name, good_values):
    msg = ''
    res = True
    if params[key_name] is not None:
        value_is_good = False
        for v in good_values:
            if params[key_name] == v:
                value_is_good = True
                return res, msg
        if value_is_good == False:
            res = False
            msg = 'The value of \'' + key_name + '\' should be'
            if len(good_values) == 1:
                msg += f" '{good_values[0]}'."
            else:
                quoted_good_values = [f"'{val}'" for val in good_values]
                msg += f" {', '.join(quoted_good_values[:-1])}, or {quoted_good_values[-1]}."

    return res, msg


def range_check(params, key_name, min_value, max_value):
    msg = ''
    res = True
    if params[key_name] is not None and (params[key_name] < min_value or params[key_name] > max_value):
        msg = 'The value of \'' + key_name + '\' should be between ' + str(min_value) + ' and ' + str(max_value)
        res = False

    return res, msg


def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = ''

    if action not in ['add', 'edit', 'get', 'delete']:
        err_msg = 'error action: ' + action
        res = False
    if res and (action == 'add' or action == 'edit' or action == 'delete') and module.params['name'] is None:
        err_msg = 'name need to set'
        res = False
    if res:
        res, err_msg = value_check(module.params, 'access_action', ['alert', 'alert_deny', 'deny_no_log', 'block-period'])
    if res:
        res, err_msg = value_check(module.params, 'severity', ['High', 'Medium', 'Low', 'Info'])
    if res:
        res, err_msg = value_check(module.params, 'bot_confirmation', ['enable', 'disable'])
    if res:
        res, err_msg = value_check(module.params, 'bot_recognition', ['disabled', 'real-browser-enforcement', 'captcha-enforcement', 'captcha-puzzle-enforcement', 'recaptcha-enforcement', 'recaptcha-v3-enforcement'])
    if res:
        res, err_msg = value_check(module.params, 'mobile_app_identification', ['disabled', 'mobile-token-validation'])
    if res:
        res, err_msg = range_check(module.params, 'access_limit_standalone_ip', 0, 65536)
    if res:
        res, err_msg = range_check(module.params, 'access_limit_share_ip', 0, 65536)
    if res:
        res, err_msg = range_check(module.params, 'block_period', 1, 10000)
    if res:
        res, err_msg = range_check(module.params, 'validation_timeout', 5, 120)
    if res:
        res, err_msg = range_check(module.params, 'max_attempt_times', 1, 5)

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
        access_limit_standalone_ip=dict(type='int'),
        access_limit_share_ip=dict(type='int'),
        access_action=dict(type='str'),
        block_period=dict(type='int'),
        severity=dict(type='str'),
        trigger_policy=dict(type='str'),
        exception_policy=dict(type='str'),
        bot_confirmation=dict(type='str'),
        bot_recognition=dict(type='str'),
        validation_timeout=dict(type='int'),
        max_attempt_times=dict(type='int'),
        recaptcha_server=dict(type='str'),
        mobile_app_identification=dict(type='str'),
        vdom=dict(type='str'),
    )
    argument_spec.update(fwebos_argument_spec)

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)
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
        module.exit_json(**result)

    code, data = get_obj(module, connection)
    if action == 'get':
        result = check_mode_process(module, data, rep_dict)
    else:
        result = check_mode_process(module, data_for_check_mode(data, module.params['name']), rep_dict)
    if module.check_mode:
      module.exit_json(**result)

    if action == 'add':
        code, response, out_data = add_obj(module, connection)
        result['res'] = response
        result['changed'] = True
    elif action == 'get':
        code, response = get_obj(module, connection)
        result['res'] = response
    elif action == 'edit':
        code, data = get_obj(module, connection)
        existing_data = result_data(data, module.params['name'])
        if existing_data is None or 'errcode' in str(existing_data):
            result['err_msg'] = 'Entry not found'
        else:
            res, new_data = needs_update(module, existing_data)
            if res:
                code, response = edit_obj(module, new_data, connection)
                result['new_data'] = new_data
                result['res'] = response
                result['changed'] = True
    elif action == 'delete':
        code, data = get_obj(module, connection)
        existing_data = result_data(data, module.params['name'])
        if existing_data is None or 'errcode' in str(existing_data):
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
        if 'res' in result and 'results' in result['res'] and result['res']['results']['errcode'] in [-3, -5]:
            result['failed'] = False

    module.exit_json(**result)


if __name__ == '__main__':
    main()
