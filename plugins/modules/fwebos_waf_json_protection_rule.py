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
module: fwebos_waf_json_protection_rule
description:
  - Config FortiWeb JSON Protection Rule
version_added: "7.0.0"
authors:
  - Joseph Chen
requirements:
    - ansible>=2.11
options:
    name:
        description:
            - name of the JSON protection rule
        type: string
    host_status:
        description:
            - Enable to compare the JSON rule to the Host.
        type: string
        choices:
            - 'enable'
            - 'disable'
    host:
        description:
            - Select the IP address or FQDN of a protected host.
        type: string
    request_type:
        description:
            - URL Type. Simple string ('plain') or regular expression ('regular').
        type: string
        choices:
            - 'plain'
            - 'regular'
    request_url:
        description:
            - Post URL.
        type: string
    json_limits:
        description:
            - Enable to define limits for data size, key, and value, etc.
        type: string
        choices:
            - 'enable'
            - 'disable'
    json_data_size:
        description:
            - Total Size of JSON Data. (range: 1-10240)
        type: integer
    key_size:
        description:
            - Key Size. (range: 1-10240)
        type: integer
    key_number:
        description:
            - Total Key Number. (range: 1-2147483647)
        type: integer
    value_size:
        description:
            - Enter the value size of each key. (range: 1-10240)
        type: integer
    value_number_in_array:
        description:
            - Enter the total value number of each JSON file. (range: 1-10240)
        type: integer
    object_depth:
        description:
            - Enter the number of the nested objects. (range: 1-2147483647)
        type: integer
    schema_type:
        description:
            - URL Type. Simple string ('plain') or regular expression ('regular').
        type: string
        choices:
            - 'schema-group'
            - 'single-schema'
    schema_file:
        description:
            - According to your selection in Schema Type, enter the name of either the schema file.
        type: string
    schema_group:
        description:
            - According to your selection in Schema Type, enter the name of either the schema group.
        type: string
    security_action:
        description:
            - Select which action FortiWeb takes when it detects a JSON protection rule violation.
        type: string
        choices:
            - 'alert'
            - 'redirect'
            - 'alert_deny'
            - 'deny_no_log'
            - 'block-period'
            - 'send_403_forbidden'
            - 'client-id-block-period'
    block_period:
        description:
            - Enter the amount of time (in seconds) that you want to block subsequent requests from a client after FortiWeb detects a rule violation. (range: 1-3600)
        type: integer
    severity:
        description:
            - Select which severity level FortiWeb uses when it logs a CSRF attack.
        type: string
        choices:
            - 'Info'
            - 'Low'
            - 'Medium'
            - 'High'
"""

EXAMPLES = """
    - name: add a json protection rule
      fwebos_waf_json_protection_rule:
        action: add
        name: jspr1
        severity: High
        host_status: enable
        host: myhost2
        request_type: plain
        request_file: /folder1/f2
        security_action: alert
        block_period: 600
        severity: Low
        trigger: tp1
        schema_type: single-schema
        schema_file: js1
        json_limits: disable


    - name: get a json protection rule
      fwebos_waf_json_protection_rule:
        action: get
        name: jspr1

    - name: edit a json protection rule
      fwebos_waf_json_protection_rule:
        action: edit
        name: jspr1
        severity: Low
        json_limits: enable
        json_data_size: 1034
        key_size: 69
        key_number: 300
        value_size: 128
        value_number: 256
        value_number_in_array: 256
        object_depth: 32
        schema_type: schema-group
        schema_group: jsg1

    - name: delete a json protection rule
      fwebos_waf_json_protection_rule:
        action: delete
        name: jspr1


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

obj_url = '/api/v2.0/cmdb/waf/json-validation.rule'


rep_dict = {
    "security_action": "action",
    "host_status": "host-status",
    "request_type": "request-type",
    "request_url": "request-file",
    "block_period": "block-period",
    "schema_type": "schema-type",
    "schema_type_val": "schema-type_val",
    "schema_file": "schema-file",
    "schema_file_val": "schema-file_val",
    "schema_group": "schema-group",
    "schema_group_val": "schema-group_val",
    "json_limits": "json-limits",
    "json_data_size": "json-data-size",
    "key_size": "key-size",
    "key_number": "key-number",
    "value_size": "value-size",
    "value_number": "value-number",
    "value_number_in_array": "value-number-in-array",
    "object_depth": "object-depth"
}

def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)

def add_obj(module, connection):
    url = obj_url
    payload1 = {}
    payload1['data'] = module.params
    payload1['data'].pop('action')
    payload1['data'].pop('vdom')
    replace_key(payload1['data'], rep_dict)

    code, response = connection.send_request(url, payload1)
    # response['sent'] = payload1['data']

    return code, response, payload1['data']


def edit_obj(module, payload, connection):
    name = module.params['name']
    url = obj_url + '?mkey=' + name
    if 'id' in module.params and module.params['id'] is not None:
        url += '&sub_mkey=' + module.params['id']
    payload1 = {}
    payload1['data'] = payload
    code, response = connection.send_request(url, payload1, 'PUT')

    return code, response


def get_obj(module, connection):
    name = module.params['name']
    payload = {}
    url = obj_url + '?mkey=' + name
    if 'id' in module.params and module.params['id'] is not None:
        url += '&sub_mkey=' + module.params['id']
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_obj(module, connection):
    name = module.params['name']
    url = obj_url + '?mkey=' + name
    if 'id' in module.params and module.params['id'] is not None:
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
    res, err_msg = value_check(module.params, 'host_status', ['enable', 'disable'])
    if res == False:
        return res, err_msg 
    res, err_msg = value_check(module.params, 'schema_type', ['schema-group', 'single-schema'])
    if res == False:
        return res, err_msg      
    res, err_msg = value_check(module.params, 'severity', ['Info', 'Low', 'Medium', 'High'])
    if res == False:
        return res, err_msg 
    res, err_msg = value_check(module.params, 'security_action', ['alert', 'redirect', 'alert_deny', 'deny_no_log', 'block-period', 'send_403_forbidden', 'client-id-block-period'])
    if res == False:
        return res, err_msg    
    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
        vdom=dict(type='str'),
        host_status=dict(type='str'),
        host=dict(type='str'),
        request_type=dict(type='str'),
        request_url=dict(type='str'),
        security_action=dict(type='str'),
        block_period=dict(type='str'),
        severity=dict(type='str'),
        trigger=dict(type='str'),
        schema_type=dict(type='str'),
        schema_file=dict(type='str'),
        schema_group=dict(type='str'),
        json_limits=dict(type='str'),
        json_data_size=dict(type='str'),
        key_size=dict(type='str'),
        key_number=dict(type='str'),
        value_size=dict(type='str'),
        value_number=dict(type='str'),
        value_number_in_array=dict(type='str'),
        object_depth=dict(type='str'),
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
