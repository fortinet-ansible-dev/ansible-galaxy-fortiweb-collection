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
module: fwebos_ml_based_api_protection_policy_domain_path_list
description:
  - Config the Restrict Learning Paths in FortiWeb ML Based API Protection Policy Domain
version_added: "7.0.0"
authors:
  - Joseph Chen
requirements:
    - ansible>=2.11
options:
    domain_id:
        description:
            - The index of API Protection Domain.
        type: string
    path_id:
        description:
            - The index of path in the domain.
        type: string
    api_path_type:
        description:
            - The type of Restricted API Learning Path.
        type: string
        choices:
            - 'plain'
            - 'regular'
    api_path:
        description:
            - The expression Restricted API Learning Path.
        type: string
"""

EXAMPLES = """
    - name: add a bot detection policy
      fwebos_ml_based_api_protection_policy_domain_path_list:
        action: add
        domain_id: 1
        api_path_type: plain
        api_path: /avcd

    - name: get a bot detection policy
      fwebos_ml_based_api_protection_policy_domain_path_list:
        action: get
        domain_id: 1
        path_id: 1

    - name: delete a bot detection policy
      fwebos_ml_based_api_protection_policy_domain_path_list:
        action: delete
        domain_id: 1
        path_id: 1

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

obj_url = '/api/v2.0/cmdb/waf/api-learning-rule/api-path-list'


rep_dict = {
    "api_path_type": "api-path-type",
    "api_path": "api-path"
}

def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)

def add_obj(module, connection):
    domain_id = module.params['domain_id']
    url = obj_url + '?mkey=' + domain_id
    payload1 = {}
    payload1['data'] = module.params
    payload1['data'].pop('action')
    payload1['data'].pop('vdom')
    replace_key(payload1['data'], rep_dict)

    code, response = connection.send_request(url, payload1)
    # # response['sent'] = payload1['data']

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
    domain_id = module.params['domain_id']
    url = obj_url + '?mkey=' + domain_id
    payload = {}
    if 'path_id' in module.params and module.params['path_id'] is not None:
        url += '&sub_mkey=' + module.params['path_id']
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_obj(module, connection):
    domain_id = module.params['domain_id']
    url = obj_url + '?mkey=' + domain_id
    if 'path_id' in module.params and module.params['path_id'] is not None:
        url += '&sub_mkey=' + module.params['path_id']
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
    if module.params['domain_id'] is None:
        err_msg = '\'domain_id\' need to set'
        res = False

    if action == 'delete' and module.params['path_id'] is None:
        err_msg = '\'path_id\' need to set for action \'delete\'.'
        res = False
    res, err_msg = value_check(module.params, 'api_path_type', ['regular', 'plain'])
    if res == False:
      return res, err_msg          

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        vdom=dict(type='str'),
        domain_id=dict(type='str'),
        path_id=dict(type='str'),
        api_path_type=dict(type='str'),
        api_path=dict(type='str')
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
    # elif action == 'edit':
    #     code, data = get_obj(module, connection)
    #     if 'errcode' in str(data):
    #         result['err_msg'] = 'Entry not found'
    #     else:
    #         res, new_data = needs_update(module, data['results'])
    #         if res:
    #             code, response = edit_obj(module, new_data, connection)
    #             result['new_data'] = new_data
    #             result['res'] = response
    #             result['changed'] = True
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
