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
module: fwebos_ml_based_api_protection_policy_domain
description:
  - Config FortiWeb ML Based API Protection Policy Domain
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
    domain_name:
        description:
            - Domain name.
        type: string
    domain_id:
        description:
            - The index of API Protection Domain.
        type: string
    id:
        description:
            - The index of Server Policy with ML Based Server Policy.
        type: string
"""

EXAMPLES = """
    - name: add a ML Based API protection policy domain
      fwebos_ml_based_api_protection_policy_domain:
        action: add
        id: 1
        policy_id: 11987745072721173265
        domain_name: domain1

    - name: get all ML Based API protection policy domain
      fwebos_ml_based_api_protection_policy_domain:
        action: get

    - name: get a ML Based API protection policy domain
      fwebos_ml_based_api_protection_policy_domain:
        action: get
        domain_id: 1

    - name: retrain a ML Based API protection policy domain
      fwebos_ml_based_api_protection_policy_domain:
        action: retrain
        domain_id: 1

    - name: delete a ML Based API protection policy domain
      fwebos_ml_based_api_protection_policy_domain:
        action: delete
        domain_id: 1

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

add_url = '/api/v2.0/cmdb/waf/api-learning-rule'
obj_url = '/api/v2.0/cmdb/waf/api-learning-rule'
get_url = '/api/v2.0/machine_learning/api_learning_policy.get_policy_rules'
retrain_url = '/api/v2.0/machine_learning/api_learning_policy.refreshdomain?rule_id=1'

rep_dict = {
    "policy_id": "policy-id",
    "domain_name": "domain-name"
}

def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)

def add_obj(module, connection):
    url = add_url + '?mkey=' + module.params['id']
    payload1 = {}
    payload1['data'] = {
        'policy-id': module.params['policy_id'],
        'domain-name': module.params['domain_name'],
    }
    code, response = connection.send_request(url, payload1)
    # # response['sent'] = payload1['data']

    return code, response, payload1['data']

def retrain_obj(module, connection):
    url = retrain_url + '?rule_id=' + module.params['domain_id']
    payload1 = {}
    code, response = connection.send_request(url, payload1)    
    return code, response

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
    url = get_url
    if 'domain_id' in module.params and module.params['domain_id'] is not None:
        url = obj_url + '?mkey=' + module.params['domain_id'] 
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_obj(module, connection):
    url = obj_url + '?mkey=' + module.params['domain_id']
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

def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = ''

    if (action == 'add') and module.params['id'] is None:
        err_msg = '\'id\' cannnot be empty for \'add\' action.'
        res = False

    if (action == 'delete') and module.params['domain_id'] is None:
        err_msg = '\'domain_id\' cannnot be empty for \'delete\' action.'
        res = False
            
    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        vdom=dict(type='str'),
        id=dict(type='str'),
        policy_id=dict(type='str'),
        domain_name=dict(type='str'),
        domain_id=dict(type='str')
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
    elif action == 'retrain':
        code, response = retrain_obj(module, connection)
        result['res'] = response
        result['changed'] = True
    elif action == 'delete':
        code, response = delete_obj(module, connection)
        result['res'] = response
        result['changed'] = True
    else:
        result['err_msg'] = 'error action: ' + action
        result['failed'] = True

    if 'errcode' in str(result):
        result['changed'] = False
    #     result['failed'] = True
    #     result['err_msg'] = 'Please check error code'
    #     if result['res']['results']['errcode'] == -3 or result['res']['results']['errcode'] == -5:
    #         result['failed'] = False

    module.exit_json(**result)


if __name__ == '__main__':
    main()
