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
module: fwebos_waf_http_header_security_policy_exception_item
description:
  - Config FortiWeb HTTP Header Security Policy Exception Item
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
    client_ip_status:
        description:
            - Click to enable or disable Client IP exception.
        type: string
        choices:
            - 'enable'
            - 'disable'
    request_url_type:
        description:
            - Select 'plain' (Simple String) to match the URL of requests with a literal URL specified in Request URL. Select 'regular' (Regular Expression) to match the URL of requests with a regular expression specified in Request URL.
        type: string
        choices:
            - 'plain'
            - 'regular'
    request_url_pattern:
        description:
            - Request URL.
        type: string
"""

EXAMPLES = """
    - name: add a New Secure Header Exception Item
      fwebos_waf_http_header_security_policy_exception_item:
       action: add
       name: e1
       client_ip_status: enable
       client_ip: 10.2.3.4-10.2.3.55
       request_url_type: plain
       request_url_pattern: /www.test.com

    - name: add a New Secure Header Exception Item
      fwebos_waf_http_header_security_policy_exception_item:
       action: add
       name: e1
       request_url_pattern: /www.334455.com

    - name: edit a New Secure Header Exception Item
      fwebos_waf_http_header_security_policy_exception_item:
       action: edit
       name: e1
       id: 3
       client_ip_status: enable
       client_ip: 10.2.3.4-10.2.3.55
       request_url_type: regular
       request_url_pattern: aa11bb

    - name: edit a New Secure Header Exception Item
      fwebos_waf_http_header_security_policy_exception_item:
       action: edit
       name: e1
       id: 3
       client_ip_status: enable
       client_ip: 10.2.3.4-10.2.3.55
       request_url_type: regular
       request_url_pattern: aa11bb

    - name: delete a Secure Header Exception Item
      fwebos_waf_http_header_security_policy_exception_item:
       action: delete
       name: e1
       id: 4

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

obj_url = '/api/v2.0/cmdb/waf/http-header-security-exception/list'


rep_dict = {
  "client_ip_status": "client-ip-status",
  "client_ip": "client-ip",
  "request_url_type": "request-url-type",
  "request_url_pattern": "request-url-pattern"
}

def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)

def add_obj(module, connection):

    name = module.params['name']
    url = obj_url + '?mkey=' + name

    payload1 = {}
    payload1['data'] = module.params
    replace_key(payload1['data'], rep_dict)
    payload1['data'].pop('action')

    code, response = connection.send_request(url, payload1)
    # response['sent'] = payload1['data']

    return code, response, payload1['data']


def edit_obj(module, payload, connection):
    id = module.params['id']
    name = module.params['name']
    url = obj_url + '?mkey=' + name + '&sub_mkey=' + id
    payload1 = {}
    payload1['data'] = payload
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
    
    if action == 'add' and module.params['client_ip'] is None:
        module.params['client_ip_status'] = 'disable'
    if action == 'add' and module.params['request_url_type'] is None:
        module.params['request_url_type'] = 'plain'
        
    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
        id=dict(type='str'),
        client_ip_status=dict(type='str'),
        client_ip=dict(type='str'),
        request_url_type=dict(type='str'),
        request_url_pattern=dict(type='str'),
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
        if action == 'delete' and result['res']['results']['errcode'] == -1:
            result['failed'] = False
            
    module.exit_json(**result)


if __name__ == '__main__':
    main()
