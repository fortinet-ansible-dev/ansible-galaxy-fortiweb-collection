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
module: fwebos_waf_ip_members
description:
  - Configure FortiWeb devices via RESTful APIs
"""

EXAMPLES = """
"""

RETURN = """
"""

obj_url = '/api/v2.0/cmdb/waf/http-header-security/http-header-security-list'


rep_dict = {
  "allow_from_source": "allow-from-source",
  "request_type": "request-type",
  "request_type_val": "request-type_val",
  "request_file": "request-file",
  "request_status": "request-status",
  "request_status_val": "request-status_val",
  "referrer_policy_value": "referrer-policy-value",
  "referrer_policy_value_val": "referrer-policy-value_val",
  "protection_mode": "value",
  "header_value": "custom-value",
}

def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)

def add_obj(module, connection):

    name = module.params['name']
    secure_header_type = module.params['secure_header_type']
    url = obj_url + '?mkey=' + name

    payload1 = {}
    payload1['data'] = module.params
    payload1['data'].pop('action')
    payload1['data']['name'] = secure_header_type #API uses 'name' to store what means to be secure_header_type. 
    replace_key(payload1['data'], rep_dict)

    code, response = connection.send_request(url, payload1)
    response['sent'] = payload1['data']

    return code, response, payload1['data']


def edit_obj(module, payload, connection):
    id = module.params['id']
    name = module.params['name']
    url = obj_url + '?mkey=' + name + '&sub_mkey=' + id
    secure_header_type = module.params['secure_header_type']
    payload1 = {}
    payload1['data'] = payload
    payload1['data']['name'] = secure_header_type 
    code, response = connection.send_request(url, payload1, 'PUT')

    return code, response


def get_obj(module, connection):
    name = module.params['name']
    id = module.params['id']
    payload = {}
    url = obj_url + '?mkey=' + name
    if id:
        url += '&sub_mkey=' + id
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_obj(module, connection):
    id = module.params['id']
    name = module.params['name']
    url = obj_url + '?mkey=' + name + '&sub_mkey=' + id
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
    
    if "secure_header_type" in module.params:
        type = module.params['secure_header_type']
        if type == 'x-frame-options':
            if module.params['protection_mode'] is None:
                err_msg = "protection_mode needs to set for Secure Header Type " + type
                res = False
            if module.params['protection_mode'] == 'allow-from' and module.params['allow_from_source'] is None:
                err_msg = "\'allow_from_source\' needs to set for Secure Header Type " + type +" and \'allow-from\' mode"
                res = False
        if type == 'x-content-type-options' or type == 'x-xss-protection' :
            if module.params['protection_mode'] is None:
                err_msg = "protection_mode needs to set for Secure Header Type " + type
                res = False
        
        if type == 'content-security-policy' or type == 'feature-policy' or type == 'permissions-policy':
            if module.params['header_value'] is None:
                err_msg = "header_value needs to set for Secure Header Type " + type
                res = False
        
        if type == 'referrer-policy':
            if module.params['referrer_policy_value'] is None:
                err_msg = "referrer_policy_value needs to set for Secure Header Type " + type
                res = False
        
    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
        protection_mode=dict(type='str'),
        id=dict(type='str'),
        secure_header_type=dict(type='str'),
        exception=dict(type='str'),
        allow_from_source=dict(type='str'),
        request_type=dict(type='str'),
        request_type_val=dict(type='str'),
        request_file=dict(type='str'),
        request_status=dict(type='str'),
        request_status_val=dict(type='str'),
        referrer_policy_value=dict(type='str'),
        referrer_policy_value_val=dict(type='str'),
        header_value=dict(type='str'),
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

    if is_vdom_enable(connection) and param_pass:
        connection.change_auth_for_vdom(module.params['vdom'])

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
