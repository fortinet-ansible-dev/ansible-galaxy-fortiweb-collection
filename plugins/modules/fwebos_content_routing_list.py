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
module: fwebos_content_routing_list
description:
  - Config FortiWeb Content Routing Policy List
version_added: "7.0.0"
authors:
  - Jie Li
  - Brad Zhang
requirements:
    - ansible>=2.11
options:
    status:
        description:
            - enable or disable to routing policy.
        type: string
        choices:
            - 'enable'
            - 'disable'
    profile_inherit:
        description:
            - If disabled, choose the web protection profile to be applied to this contect routing policy. If enabled, the web protection profile from the server policy will be automatically applid.
        type: string
        choices:
            - 'enable'
            - 'disable'
    is_default:
        description:
            - choose to use default option
        type: string
        choices:
            - 'yes'
            - 'no'
"""

EXAMPLES = """
     - name: Create a routing list
       fwebos_content_routing_list:
        action: add
        name: P1
        content_routing_policy_name: myhp
        is_default: "no"
        profile_inherit: enable
        status: enable

     - name: edit
       fwebos_content_routing_list:
        action: edit
        name: P1
        id: 4
        profile_inherit: disable
        web_protection_profile: "Inline Extended Protection"
        is_default: "yes"

     - name: delete an entry
       fwebos_content_routing_list:
        action: delete
        name: P1
        id: 2

     - name: delete all entry under the policy
       fwebos_content_routing_list:
        action: delete
        name: P1

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

obj_url = '/api/v2.0/cmdb/server-policy/policy/http-content-routing-list'



rep_dict = {
    'content_routing_policy_name': "content-routing-policy-name",
    'is_default': "is-default",
    'profile_inherit': "profile-inherit",
    'web_protection_profile': "web-protection-profile",
}

def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)

def add_obj(module, connection):
    name = module.params['name']
    payload1 = {}
    payload1['data'] = module.params
    payload1['data'].pop('action')
    payload1['data'].pop('id')
    replace_key(payload1['data'], rep_dict)
    url = obj_url + '?mkey=' + name 
    code, response = connection.send_request(url, payload1)

    return code, response


def edit_obj(module, payload, connection):
    name = module.params['name']
    id = module.params['id']
    payload.pop('id')
    url = obj_url + '?mkey=' + name + '&sub_mkey=' + id
    payload1 = {}
    payload1['data'] = payload
    code, response = connection.send_request(url, payload1, 'PUT')
    return code, response


def get_obj(module, connection):
    name = module.params['name']
    id = module.params['id']
    payload = {}
    url = obj_url
    if name:
        url += '?mkey=' + name
    if id:
        url +=  '&sub_mkey=' + id
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_obj(module, connection):
    name = module.params['name']
    id = module.params['id']
    payload = {}
    url = obj_url + '?mkey=' + name
    if id:
        url +=  '&sub_mkey=' + id
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
    replace_key(payload1['data'], rep_dict)
    payload1['data'].pop('action')

    res = combine_dict(payload1['data'], data)

    return res, data


def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = ''
    if module.params['name'] is None:
        err_msg = 'name need to set'
        res = False
    if action == 'edit' and module.params['id'] is None:
        err_msg = 'id need to set'
        res = False
    if is_vdom_enable(connection) and module.params['vdom'] is None:
        err_msg = 'vdom enable, vdom need to set'
        res = False

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
        id=dict(type='str'),
        content_routing_policy_name=dict(type='str'),
        is_default=dict(type='str'),
        web_protection_profile=dict(type='str'),
        profile_inherit=dict(type='str'),
        status=dict(type='str'),
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
        if result['res']['results']['errcode'] == -3 or result['res']['results']['errcode'] == -5 or result['res']['results']['errcode'] == -1:
            result['failed'] = False

    result['name'] = module.params['name']
    module.exit_json(**result)


if __name__ == '__main__':
    main()
