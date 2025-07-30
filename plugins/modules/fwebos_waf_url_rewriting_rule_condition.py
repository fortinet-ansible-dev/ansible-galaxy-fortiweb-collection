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
module: fwebos_waf_url_rewriting_rule_condition
description:
  - Config FortiWeb URL Rewriting Rule Condition
version_added: "7.6.0"
authors:
  - Joseph Chen
requirements:
    - ansible>=2.11
options:
    name:
        description:
            - The name of rewriting rule.
        type: string
    object:
        description:
            - Select which part of the HTTP request will be tested for a match.
        type: string
        choices:
            - 'http-host'
            - 'http-url'
            - 'http-location'
    reg_exp:
        description:
            - A regular Expression that defines either all matching or all non-matching objects..
        type: string
    protocol_filter:
        description:
            - Protocol Filter.
        type: string
        choices:
            - 'enable'
            - 'disable'
    http_protocol:
        description:
            - Select which protocol will match this condition, either HTTP or HTTPS..
        type: string
        choices:
            - 'http'
            - 'https'
    reverse_match:
        description:
            - Indicate how to use Regular Expression when determining whether or not this URL rewriting condition is met.
        type: string
        choices:
            - '"yes" (Object does not match the regular expression)'
            - '"no" (Object matches the regular expressionn)'
"""

EXAMPLES = """
- name: add a URL rewriting rule condition
  fwebos_waf_url_rewriting_rule_condition:
  action: add
  name: aa2
  object: http-refer
  is_referer_essential: "yes"
  reg_exp: tttttt
  reverse_match: "no"
  content_type_filter: enable

- name: get a URL rewriting rule condition
  fwebos_waf_url_rewriting_rule_condition:
  action: get
  name: aa2
  id: 1

- name: edit a URL rewriting rule condition
  fwebos_waf_url_rewriting_rule_condition:
  action: edit
  name: aa2
  id: 3
  object: http-host
  protocol_filter: enable
  http_protocol: https
  reg_exp: abcd

- name: delete a URL rewriting rule condition
  fwebos_waf_url_rewriting_rule_condition:
  action: delete
  name: aa2
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

obj_url = '/api/v2.0/cmdb/waf/url-rewrite.url-rewrite-rule/match-condition'


rep_dict = {
    "reg_exp": "reg-exp",
    "reverse_match": "reverse-match",
    "reverse_match_val": "reverse-match_val",
    "protocol_filter": "protocol-filter",
    "protocol_filter_val": "protocol-filter_val",
    "http_protocol": "HTTP-protocol",
    "HTTP_protocol_val": "HTTP-protocol_val",
    "content_type_filter": "content-type-filter",
    "content_type_set": "content-type-set",
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
    payload1['data'].pop('action')
    replace_key(payload1['data'], rep_dict)

    code, response = connection.send_request(url, payload1)
    # response['sent'] = payload1['data']

    return code, response, payload1['data']


def edit_obj(module, payload, connection):
    name = module.params['name']
    url = obj_url + '?mkey=' + name
    if 'id' in module.params:
        url += '&sub_mkey=' + module.params['id']
    payload1 = {}
    payload1['data'] = payload
    code, response = connection.send_request(url, payload1, 'PUT')

    return code, response


def get_obj(module, connection):
    name = module.params['name']
    payload = {}
    url = obj_url + '?mkey=' + name
    if 'id' in module.params:
        url += '&sub_mkey=' + module.params['id']
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_obj(module, connection):
    name = module.params['name']
    url = obj_url + '?mkey=' + name
    if 'id' in module.params:
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
            
    res, err_msg = value_check(module.params, 'object', ['http-host', 'http-url', 'http-location'])
    if res == False:
        return res, err_msg
    res, err_msg = value_check(module.params, 'reverse_match', ['yes', 'no'])
    if res == False:
        return res, err_msg    
    res, err_msg = value_check(module.params, 'protocol_filter', ['enable', 'disable'])
    if res == False:
        return res, err_msg    
    res, err_msg = value_check(module.params, 'http_protocol', ['http', 'https'])
    if res == False:
        return res, err_msg     
    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
        vdom=dict(type='str'),
        id=dict(type='str'),
        object=dict(type='str'),
        reg_exp=dict(type='str'),
        reverse_match=dict(type='str'),  # Meet this condition if 
        protocol_filter=dict(type='str'),
        http_protocol=dict(type='str'),
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
            result['err_msg'] = 'The entry is not found.'
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
            result['err_msg'] = 'The entry is not found.'
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
        result['err_msg'] = 'Please check error code'
        if result['res']['results']['errcode'] == -3 or result['res']['results']['errcode'] == -5 or result['res']['results']['errcode'] == -551:
            result['failed'] = False

    module.exit_json(**result)


if __name__ == '__main__':
    main()

            