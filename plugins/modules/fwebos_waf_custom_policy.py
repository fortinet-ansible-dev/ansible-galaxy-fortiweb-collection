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
module: fwebos_waf_custom_policy
description:
  - Config FortiWeb Advanced Protection Custom Policy
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
    threat_weight:
        description:
            - Enable to apply this rule only to HTTP requests for specific web hosts. Disable to match the rule based on the URL and any parameter filter only.
        type: string
        choices:
            - 'informational'
            - 'low'
            - 'moderate'
            - 'severe'
"""

EXAMPLES = """
    - name: add a rule
      fwebos_waf_custom_policy:
       action: add
       name: test1
       threat_weight: moderate

    - name: edit a rule
      fwebos_waf_custom_policy:
       action: edit
       name: test1
       threat_weight: low

    - name: get a rule
      fwebos_waf_custom_policy:
       action: get
       name: test1

    - name: delete a rule
      fwebos_waf_custom_policy:
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

obj_url = '/api/v2.0/cmdb/waf/custom-access.policy'


rep_dict = {
  "threat_weight": "threat-weight",
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
    payload1['data'].pop('action')
    if payload1['data']['threat-weight'] is None:
        payload1['data']['threat-weight'] = "moderate",
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

def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = ''
    if module.params['threat_weight'] is not None:
        if module.params['threat_weight']!='informational' and module.params['threat_weight']!='severe' and module.params['threat_weight']!='moderate' and module.params['threat_weight']!='low':
            err_msg = 'The value of \'threat_weight\' should be \'informational\', \'low\', \'moderate\', or \'severe\''
            res = False
    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
        threat_weight=dict(type='str'), 
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
