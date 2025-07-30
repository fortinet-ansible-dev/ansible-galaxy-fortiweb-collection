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
module: fwebos_waf_http_header_security_policy_rule
description:
  - Config FortiWeb HTTP Header Security Policy Rules
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
    request_status:
        description:
            - Click to enable or disable request filter. It is also named URL filter. Enable it so that responses to the request will be processed with the security headers only if the URL of a request matches the specified Request URL.
        type: string
        choices:
            - 'enable'
            - 'disable'
    request_type:
        description:
            - Select 'plain' (Simple String) to match the URL of requests with a literal URL specified in Request URL. Select 'regular' (Regular Expression) to match the URL of requests with a regular expression specified in Request URL.
        type: string
        choices:
            - 'plain'
            - 'regular'
    request_file:
        description:
            - The Request URL.
        type: string
    secure_header_type:
        description:
            - FortiWeb security headers Types.
        type: string
        choices:
            - 'x-xss-protection'
            - 'x-frame-options'
            - 'x-content-type-options'
            - 'content-security-policy'
            - 'feature-policy'
            - 'permissions-policy'
            - 'referrer-policy'
    exception:
        description:
            - The name of HTTP Header Security Policy Exception.
        type: string
    referrer_policy_value:
        description:
            - The referrer policy options. Only available when 'secure_header_type' is 'referrer-policy'.
        type: string
        choices:
            - 'no-referrer'
            - 'no-referrer-when-downgrade'
            - 'same-origin'
            - 'origin'
            - 'strict-origin'
            - 'origin-when-cross-origin'
            - 'strict-origin-when-cross-origin'
            - 'unsafe-url'
    protection_mode:
        description:
            - Used to direct the browers to stop loading pages when reflected XSS attackes are detected.
        type: string
        choices:
            - 'deny  (when 'secure_header_type' is 'x-frame-options')'
            - 'sameorigin  (when 'secure_header_type' is 'x-frame-options')'
            - 'allow-from (when 'secure_header_type' is 'x-frame-options')'
            - 'nosniff (when 'secure_header_type' is 'x-content-type-options')'
            - 'sanitizing-mode (when 'secure_header_type' is 'x-xss-protection')'
            - 'block-mode (when 'secure_header_type' is 'x-xss-protection')'
    header_value:
        description:
            - Used to reduce XSS risk and data injection attacks on browers.
        type: string
    allow_from_source:
        description:
            - Allowed From URI. Only available when 'protection_mode' is 'allow-from'.
        type: string
"""

EXAMPLES = """
    - name: add a New Secure Header Rule
      fwebos_waf_http_header_security_policy_rule:
       action: add
       name: HP
       request_status: disable
       request_type: plain
       protection_mode: sanitizing-mode
       secure_header_type: x-xss-protection

    - name: edit a Secure Header Rule
      fwebos_waf_http_header_security_policy_rule:
       action: edit
       name: HP
       id: 1
       secure_header_type: x-frame-options
       protection_mode: allow-from
       allow_from_source: "http://www.google.com"
       exception: hse1

    - name: edit a Secure Header Rule
      fwebos_waf_http_header_security_policy_rule:
       action: edit
       name: HP
       id: 1
       secure_header_type: content-security-policy
       header_value: "http://www.amazon.ca"
       exception: hse1

    - name: edit a Secure Header Rule
      fwebos_waf_http_header_security_policy_rule:
       action: edit
       name: HP
       id: 1
       secure_header_type: referrer-policy
       referrer_policy_value: no-referrer
       exception: ""

    - name: get a Secure Header Rule
      fwebos_waf_http_header_security_policy_rule:
       action: get
       name: HP
       id: 1

    - name: delete a Secure Header Rule
      fwebos_waf_http_header_security_policy_rule:
       action: delete
       name: HP
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
    # response['sent'] = payload1['data']

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
