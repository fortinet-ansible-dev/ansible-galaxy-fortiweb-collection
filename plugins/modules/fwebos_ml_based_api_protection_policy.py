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
module: fwebos_ml_based_api_protection_policy
description:
  - Config FortiWeb ML Based API Protection Policy
version_added: "7.0.0"
authors:
  - Joseph Chen
requirements:
    - ansible>=2.11
options:
    policy_id:
        description:
            - The numerical policy ID of the Server Policy. It is the same one as used in CLI.
        type: string
    action_mlapi:
        description:
            - Schema Protection action.
        type: string
        choices:
            - 'alert'
            - 'alert_deny'
            - 'standby'
            - 'block-period'
    block_period_mlapi:
        description:
            - Block Period for Schema Protection.
        type: string
    severity_mlapi:
        description:
            - Severity for Schema Protection.
        type: string
        choices:
            - 'Info'
            - 'Low'
            - 'Medium'
            - 'High'
    trigger_mlapi:
        description:
            - Name of the Trigger Policy for Schema Protection.
        type: string
    action_anomaly:
        description:
            - Threat Detection action.
        type: string
        choices:
            - 'alert'
            - 'alert_deny'
            - 'disable'
            - 'block-period'
    block_period_anomaly:
        description:
            - Block Period for Threat Detection.
        type: string
    severity_anomaly:
        description:
            - Severity for Threat Detection.
        type: string
        choices:
            - 'Info'
            - 'Low'
            - 'Medium'
            - 'High'
    trigger_anomaly:
        description:
            - Name of the Trigger Policy for Threat Detection.
        type: string
    url_replacer_policy:
        description:
            - Name of the URL Replacer Policy.
        type: string
    ip_list_type:
        description:
            - Severity for Schema Protection.
        type: string
        choices:
            - 'Block'
            - 'Trust'
"""

EXAMPLES = """
    - name: add a ML Based API protection policy
      fwebos_ml_based_api_protection_policy:
        action: add
        policy_id: 11987745072721173265
        rule_domain:
          - ddccd
          - aadddc
        rule_ip:
          - 1.2.3.4
          - 10.2.41.34

    - name: get a ML Based API protection policy
      fwebos_ml_based_api_protection_policy:
        action: get
        id: 1

    - name: edit a ML Based API protection policy
      fwebos_ml_based_api_protection_policy:
        action: edit
        id: 1
        action_mlapi: block-period
        block_period_mlapi: 567
        severity_mlapi: High

    - name: delete a ML Based API protection policy
      fwebos_ml_based_api_protection_policy:
        action: delete
        id: 1

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

add_url = '/api/v2.0/machine_learning/api_learning_policy.create_policy_rule'
obj_url = '/api/v2.0/cmdb/waf/api-learning-policy'

rep_dict = {
    "action_mlapi": "action-mlapi",
    "block_period_mlapi": "block-period-mlapi",
    "severity_mlapi": "severity-mlapi",
    "action_anomaly": "action-anomaly",
    "block_period_anomaly": "block-period-anomaly",
    "severity_anomaly": "severity-anomaly",
    "ip_list_type": "ip-list-type",
    "trigger_mlapi": "trigger-mlapi",
    "trigger_anomaly": "trigger-anomaly",
    "url_replacer_policy": "url-replacer-policy"
}

def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)

def add_obj(module, connection):

    url = add_url
    payload1 = {}
    payload1['data'] = {
        'policy_id': module.params['policy_id'],
        'rule_domain': module.params['rule_domain'],
        'rule_ip': module.params['rule_ip']
    }
    replace_key(payload1['data'], rep_dict)

    code, response = connection.send_request(url, payload1)
    # # response['sent'] = payload1['data']

    return code, response, payload1['data']


def edit_obj(module, payload, connection):
    id = module.params['id']
    if id:
        url = obj_url + '?mkey=' + id
    payload1 = {}
    payload1['data'] = payload
    code, response = connection.send_request(url, payload1, 'PUT')

    return code, response


def get_obj(module, connection):
    payload = {}
    id = module.params['id']
    if id:
        url = obj_url + '?mkey=' + id
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_obj(module, connection):
    id = module.params['id']
    if id:
        url = obj_url + '?mkey=' + id
    payload = {}
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
    payload1 = {}
    payload1['data'] = module.params
    replace_key(payload1['data'], rep_dict)

    res = combine_dict(payload1['data'], data)
    return res, data

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

    if (action == 'get' or action == 'edit' or action == 'delete') and module.params['id'] is None:
        err_msg = 'id cannnot be empty'
        res = False

    res, err_msg = value_check(module.params, 'action_mlapi', ['alert', 'alert_deny', 'standby', 'block-period'])
    if res == False:
      return res, err_msg  
    res, err_msg = value_check(module.params, 'action_anomaly', ['alert', 'alert_deny', 'disable', 'block-period'])
    if res == False:
      return res, err_msg 
    res, err_msg = value_check(module.params, 'severity_mlapi', ['Info', 'Low', 'High', 'Medium'])
    if res == False:
      return res, err_msg  
    res, err_msg = value_check(module.params, 'severity_anomaly', ['Info', 'Low', 'High', 'Medium'])
    if res == False:
      return res, err_msg 
    res, err_msg = value_check(module.params, 'ip_list_type', ['Block', 'Trust'])
    if res == False:
      return res, err_msg 
    
    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        vdom=dict(type='str'),
        id=dict(type='str'),
        policy_id=dict(type='str'),
        rule_domain=dict(type='list'),
        rule_ip=dict(type='list'),
        action_mlapi=dict(type='str'),
        block_period_mlapi=dict(type='str'),
        severity_mlapi=dict(type='str'),
        action_anomaly=dict(type='str'),
        block_period_anomaly=dict(type='str'),
        severity_anomaly=dict(type='str'),
        ip_list_type=dict(type='str'),
        trigger_mlapi=dict(type='str'),
        trigger_anomaly=dict(type='str'),
        url_replacer_policy=dict(type='str')
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
            result['changed'] = False
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
            result['err_msg'] = 'Entry not found'
            result['changed'] = False
        else:
            code, response = delete_obj(module, connection)
            result['res'] = response
            result['changed'] = True
    else:
        result['err_msg'] = 'error action: ' + action
        result['failed'] = True

    # if 'errcode' in str(result):
    #     result['changed'] = False
    #     result['failed'] = True
    #     result['err_msg'] = 'Please check error code'
    #     if result['res']['results']['errcode'] == -3 or result['res']['results']['errcode'] == -5:
    #         result['failed'] = False

    module.exit_json(**result)


if __name__ == '__main__':
    main()
