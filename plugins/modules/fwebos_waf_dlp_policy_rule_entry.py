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
module: fwebos_waf_dlp_policy_rule_entry
description:
  - Config FortiWeb Data Loss Preventation Rule in a Data Loss Preventation Policy
version_added: "7.0.0"
authors:
  - Joseph Chen
requirements:
    - ansible>=2.11
options:
    name:
        description:
            - The name of Data Loss Preventation Policy.
        type: string
    rule:
        description:
            - The name of Data Loss Preventation Rule to be added/replaced/removed.
        type: string
"""

EXAMPLES = """
    - name: add a policy
      fwebos_waf_dlp_policy:
       action: add
       name: aaa

    - name: add a rule under this newly added policy
      fwebos_waf_dlp_policy_rule_entry:
       action: add
       name: aaa
       rule: dlp3

    - name: get a rule under
      fwebos_waf_dlp_policy_rule_entry:
       action: get
       name: aaa
       id: 1

    - name: edit a policy's rule
      fwebos_waf_dlp_policy_rule_entry:
       action: edit
       name: aaa
       id: 1
       rule: dlp2

    - name: delete a policy's rule
      fwebos_waf_dlp_policy_rule_entry:
       action: delete
       name: aaa


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

obj_url = '/api/v2.0/cmdb/waf/dlp.policy/dlp-rules'


rep_dict = {
}


def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)

def add_obj(module, connection):
    payload1 = {}
    payload1['data'] = module.params
    name = module.params['name']
    url = obj_url + '?mkey=' + name
    payload1['data'].pop('action')
    payload1['data'].pop('name')
    code, response = connection.send_request(url, payload1)
    # response['sent'] = payload1['data']
    return code, response

def delete_obj(module, connection):
    name = module.params['name']
    payload = {}
    url = obj_url + '?mkey=' + name
    if 'id' in module.params:
        url += '&sub_mkey=' + module.params['id']
    code, response = connection.send_request(url, payload, 'DELETE')
    return code, response


def get_obj(module, connection):
    payload = {}
    name = module.params['name']
    url = obj_url + '?mkey=' + name
    if 'id' in module.params:
        url += '&sub_mkey=' + module.params['id']
    code, response = connection.send_request(url, payload, 'GET')

    # raise Exception(response)
    return code, response

def edit_obj(module, payload, connection):
    name = module.params['name']
    url = obj_url + '?mkey=' + name
    if 'id' in module.params:
        url += '&sub_mkey=' + module.params['id']
    payload1 = {}
    payload1['data'] = payload
    code, response = connection.send_request(url, payload1, 'PUT')

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
    if module.params['name'] is None:
        err_msg = 'name cannot be empty'
        res = False
    
    if (action == 'edit' or action == 'delete') and module.params['id'] is None:
        err_msg = 'ID of rule entry cannot be empty'
        res = False
    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
        id=dict(type='str'),
        rule=dict(type='str'),
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
