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
module: fwebos_waf_custom_rule
description:
  - Config FortiWeb Advanced Protection Custom Policy Rule
version_added: "7.0.0"
authors:
  - Joseph Chen
requirements:
    - ansible>=2.11
options:
    name:
        description:
            - A unique name that can be referenced in other parts of the configuration.
        type: string
    security_action:
        description:
            - Select which action the FortiWeb appliance will take when it detects a violation of the rule.
        type: string
        choices:
            - 'alert'
            - 'redirect'
            - 'deny_no_log'
            - 'block-period'
            - 'client-id-block-period'
    severity:
        description:
            - Select which severity level the FortiWeb appliance will use when it logs a violation of the rule.
        type: string
        choices:
            - 'Info'
            - 'Low'
            - 'Medium'
            - 'High'
    trigger:
        description:
            - Select which trigger, if any, that the FortiWeb appliance will use when it logs and/or sends an alert email about a violation of the rule.
        type: string
    bot_confirmation:
        description:
            - Enable to confirm if the client is indeed a bot.
        type: string
        choices:
            - 'enable'
            - 'disable'
    bot_recognition:
        description:
            - Select what type of bots the client is.
        type: string
        choices:
            - 'enable'
            - 'real-browser-enforcement'
            - 'captcha-enforcement'
    mobile_app_identification:
        description:
            - Available only when Mobile Application Identification is enabled.
        type: string
        choices:
            - 'enable'
            - 'disable'
"""

EXAMPLES = """
    - name: add a rule
      fwebos_waf_custom_rule:
       action: add
       name: test1
       security_action: alert
       severity: Medium
       block_period: 500
       bot_confirmation: enable
       bot_recognition: real-browser-enforcement
       mobile_app_identification: disabled
       validation_timeout: 30
       trigger: tp1

    - name: get a rule
      fwebos_waf_custom_rule:
       action: get
       name: test1

    - name: edit a rule
      fwebos_waf_custom_rule:
       action: edit
       name: test1
       severity: High
       security_action: client-id-block-period
       block_period: 400
       bot_confirmation: disable

    - name: delete a rule
      fwebos_waf_custom_rule:
       action: delete
       name: test1

    - name: delete a rule
      fwebos_waf_custom_rule:
       action: delete
       name: test1

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

obj_url = '/api/v2.0/cmdb/waf/custom-access.rule'


rep_dict = {
  "block_period": "block-period",
  "bot_confirmation": "bot-confirmation",
  "bot_recognition": "bot-recognition",
  "mobile_app_identification": "mobile-app-identification",
  "validation_timeout": "validation-timeout",
  "max_attempt_times": "max-attempt-times",
  "security_action": "action",
}


def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)

def add_obj(module, connection):
    payload1 = {}
    payload1['data'] = module.params
    replace_key(payload1['data'], rep_dict)
    # if payload1['data']['security_action'] is not None:
    #     payload1['data']['action'] = payload1['data']['security_action'],
    code, response = connection.send_request(obj_url, payload1)
    # # response['sent'] = payload1['data']
    return code, response

def delete_obj(module, connection):
    name = module.params['name']
    payload = {}
    url = obj_url + '?mkey=' + name
    code, response = connection.send_request(url, payload, 'DELETE')

    return code, response


def get_obj(module, connection):
    name = module.params['name']
    payload = {}
    url = obj_url + '?mkey=' + name
    code, response = connection.send_request(url, payload, 'GET')
    # raise Exception(response)
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
    replace_key(payload1['data'], rep_dict)

    res = combine_dict(payload1['data'], data)

    return res, data

def edit_obj(module, payload, connection):
    name = module.params['name']
    url = obj_url + '?mkey=' + name
    payload1 = {}
    payload1['data'] = payload
    code, response = connection.send_request(url, payload1, 'PUT')
    return code, response

def value_check(params, key_name, good_values):
    msg = ''
    res = True
    if params[key_name] is not None:
        value_is_good = False
        for v in good_values:
            if params[key_name]==v:
                value_is_good = True
                return res, msg
        if value_is_good == False:
            # generate error message.
            res = False
            msg = 'The value of \''+ key_name + '\' should be'
            if len(good_values) == 1:
                msg+= f" '{good_values[0]}'."
            else:
                quoted_good_values = [f"'{val}'" for val in good_values]
                msg+= f" {', '.join(quoted_good_values[:-1])}, or {quoted_good_values[-1]}."

    return res, msg

def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = ''
    res, err_msg = value_check(module.params, 'severity', ['Info', 'Low', 'Medium', 'High'])
    if res == False:
        return res, err_msg
    res, err_msg = value_check(module.params, 'security_action', ['alert', 'redirect', 'deny_no_log', 'block-period', 'client-id-block-period'])
    if res == False:
        return res, err_msg
    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
        block_period=dict(type='str'),
        bot_confirmation=dict(type='str'),
        bot_recognition=dict(type='str'),
        mobile_app_identification=dict(type='str'),
        validation_timeout=dict(type='str'),
        max_attempt_times=dict(type='str'),
        security_action=dict(type='str'),
        severity=dict(type='str'),
        trigger=dict(type='str'),
        vdom=dict(type='str'),
    )
    argument_spec.update(fwebos_argument_spec)

    module = AnsibleModule(argument_spec=argument_spec)
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
            result['err_msg'] = 'Entry not found'
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
        if result['res']['results']['errcode'] == -3 or result['res']['results']['errcode'] == -5:
            result['failed'] = False
    module.exit_json(**result)


if __name__ == '__main__':
    main()
