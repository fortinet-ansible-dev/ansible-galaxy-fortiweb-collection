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
module: fwebos_waf_site_publish_policy
description:
  - Config FortiWeb Published Site Policy
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
    account_lockout:
        description:
            - Enable or disable Account Lockout.
        type: string
        choices:
            - 'enable'
            - 'disable'
    max_login_failures:
        description:
            - Max Login Failures. Only available when 'account_lockout' is enabled. (range: 1-30)
        type: integer
    within:
        description:
            - The number of minutes allowing max login login failures. Only available when 'account_lockout' is enabled. (range: 1-30)
        type: integer
    account_block_period:
        description:
            - Account Block Period. Only available when 'account_lockout' is enabled. (range: 1-3600)
        type: integer
    limit_users:
        description:
            - Enable or disable Limit Concurrent Users Per Account.
        type: string
        choices:
            - 'enable'
            - 'disable'
    maximum_users:
        description:
            - Maximum Concurrent Users. Only available when 'limit_users' is enabled. (range: 1-128)
        type: integer
    session_idle_timeout:
        description:
            - Session Idle Timeout (Unit: minute). Only available when 'limit_users' is enabled. (range: 1-1440)
        type: integer
    credential_stuffing_online_query:
        description:
            - Enable or disable Credential Stuffing Defense.
        type: string
        choices:
            - 'enable'
            - 'disable'
    credential_stuffing_protection:
        description:
            - Enable or disable Credential Stuffing Online Check.
        type: string
        choices:
            - 'enable'
            - 'disable'
    match_type:
        description:
            - Select Match type.
        type: string
        choices:
            - 'any'
            - 'all'
    security_action:
        description:
            - Select Match type.
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    block_period:
        description:
            - Block Period.  Only available when 'security_action' is 'block-period'. (range: 1-30)
        type: integer
    security:
        description:
            - Select security level.
        type: string
        choices:
            - 'Info'
            - 'Low'
            - 'Medium'
            - 'High'
    trigger:
        description:
            - Select the trigger policy, if any, that FortiWeb carries out when it logs and/or sends an alert email about a violation.
        type: string
"""

EXAMPLES = """
    - name: add a site_publish policy
      fwebos_waf_site_publish_policy:
        action: add
        name: pp1
        account_block_period: 600
        account_lockout: enable
        security_action: alert_deny
        credential_stuffing_online_query: enable
        credential_stuffing_protection: enable
        limit_users: enable
        max_login_failures: 5
        maximum_users: 1
        session_idle_timeout: 30
        severity: Medium
        trigger: tp1
        within: 3

    - name: get a site_publish policy
      fwebos_waf_site_publish_policy:
        action: get
        name: pp1

    - name: edit a dlp dictionary
      fwebos_waf_site_publish_policy:
        action: edit
        name: pp1
        account_lockout: disable
        security_action: alert

    - name: delete a site_publish
      fwebos_waf_site_publish_policy:
        action: delete
        name: pp1


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

obj_url = '/api/v2.0/cmdb/waf/site-publish-helper.policy'


rep_dict = {
    "security_action": "action",
    "account_block_period": "account-block-period",
    "account_lockout": "account-lockout",
    "credential_stuffing_online_query": "credential-stuffing-online-query",
    "credential_stuffing_online_query_val": "credential-stuffing-online-query_val",
    "credential_stuffing_protection": "credential-stuffing-protection",
    "credential_stuffing_protection_val": "credential-stuffing-protection_val",
    "limit_users": "limit-users",
    "limit_users_val": "limit-users_val",
    "max_login_failures": "max-login-failures",
    "maximum_users": "maximum-users",
    "session_idle_timeout": "session-idle-timeout"
}

def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)

def add_obj(module, connection):

    name = module.params['name']

    url = obj_url

    payload1 = {}
    payload1['data'] = module.params
    payload1['data'].pop('action')
    replace_key(payload1['data'], rep_dict)

    code, response = connection.send_request(url, payload1)
    # response['sent'] = payload1['data']

    return code, response, payload1['data']


def edit_obj(module, payload, connection):
    name = module.params['name']
    url = obj_url + '?mkey=' + name
    if 'id' in module.params:
        url += '&sub_mkey=' + module.params['id']
    payload1 = {}
    payload1['data'] = payload
    code, response = connection.send_request(url, payload1, 'PUT')

    return code, response


def get_obj(module, connection):
    payload = {}        
    url = obj_url
    if 'name' in module.params:
        url = obj_url + '?mkey=' + module.params['name']
    if 'id' in module.params:
        url += '&sub_mkey=' + module.params['id']
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_obj(module, connection):
    name = module.params['name']
    url = obj_url + '?mkey=' + name
    if 'id' in module.params:
        url += '&sub_mkey=' + module.params['id']
    payload = {}
    code, response = connection.send_request(url, payload, 'DELETE')

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

def combine_dict(src_dict, dst_dict):
    changed = False
    for key in dst_dict:
        if key in src_dict and src_dict[key] is not None and dst_dict[key] != src_dict[key]:
            dst_dict[key] = src_dict[key]
            changed = True

    return changed

def needs_update(module, data):
    payload1 = {}
    payload1['data'] = module.params
    replace_key(payload1['data'], rep_dict)
    payload1['data'].pop('action')

    res = combine_dict(payload1['data'], data)
    return res, data

def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = ''

    if (action == 'add' or action == 'edit' or action == 'delete') and module.params['name'] is None:
        err_msg = 'name need to set'
        res = False
    res, err_msg = value_check(module.params, 'account_lockout', ['enable', 'disable'])
    if res == False:
        return res, err_msg
    res, err_msg = value_check(module.params, 'security_action', ['alert', 'alert_deny', 'deny_no_log', 'block-period', 'client-id-block-period'])
    if res == False:
        return res, err_msg
    res, err_msg = value_check(module.params, 'credential_stuffing_online_query', ['enable', 'disable'])
    if res == False:
        return res, err_msg
    res, err_msg = value_check(module.params, 'credential_stuffing_protection', ['enable', 'disable'])
    if res == False:
        return res, err_msg
    res, err_msg = value_check(module.params, 'limit_users', ['enable', 'disable'])
    if res == False:
        return res, err_msg
    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
        vdom=dict(type='str'),
        account_block_period=dict(type='str'),
        account_lockout=dict(type='str'),
        security_action=dict(type='str'),
        credential_stuffing_online_query=dict(type='str'),
        credential_stuffing_protection=dict(type='str'),
        limit_users=dict(type='str'),
        limit_users_val=dict(type='str'),
        max_login_failures=dict(type='str'),
        maximum_users=dict(type='str'),
        q_type=dict(type='str'),
        session_idle_timeout=dict(type='str'),
        severity=dict(type='str'),
        sz_rule=dict(type='str'),
        trigger=dict(type='str'),
        within=dict(type='str'),
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
        code, response, out_data = add_obj(module, connection)
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
        if 'results' in data.keys() and data['results'] and type(data['results']) is not int:
            code, response = delete_obj(module, connection)
            result['res'] = response
            result['changed'] = True
        else:
            result['err_msg'] = 'Entry not found'
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

            