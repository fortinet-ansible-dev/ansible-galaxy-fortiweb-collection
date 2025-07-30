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
module: fwebos_waf_csrf_page_rule
description:
  - Config FortiWeb CSRF Page Rule
version_added: "7.0.0"
authors:
  - Joseph Chen
requirements:
    - ansible>=2.11
options:
    name:
        description:
            - name of the CSRF page rule
        type: string
    host_status:
        description:
            - Enable to apply this rule only to HTTP requests for specific web hosts. Disable to match the rule based on the URL and any parameter filter only.
        type: string
        choices:
            - 'enable'
            - 'disable'
    host:
        description:
            - Select a protected host names entry (either a web host name or IP address).
        type: string
    request_type:
        description:
            - Select whether Full URL contains a literal URL (Simple String), or a regular expression designed to match multiple URLs (Regular Expression).
        type: string
        choices:
            - 'plain'
            - 'regular'
    request_url:
        description:
            - a literal URL or regular expression.
        type: string
    parameter_filter:
        description:
            - Select to specify a parameter name and value to match. The parameter can be located in either the URL or the HTTP body of a request.
        type: string
        choices:
            - 'enable'
            - 'disable'
    parameter_name:
        description:
            - Enter the parameter name to match.
        type: string
    parameter_value:
        description:
            - Enter either a literal URL or regular expression.
        type: string
"""

EXAMPLES = """
    - name: add a rule
      fwebos_waf_csrf_page_rule:
       action: add
       name: c1
       request_type: plain
       parameter_value_type: regular
       host_status: enable
       host: myhost
       request_url: /abc.com
       parameter_filter: enable
       parameter_name: p1
       parameter_value: a1b2

    - name: edit a rule
      fwebos_waf_csrf_page_rule:
       action: edit
       name: c1
       id: 1
       request_type: regular
       parameter_value_type: regular
       host_status: enable
       host: ftnt
       request_url: zzzxxx
       parameter_filter: enable
       parameter_name: test
       parameter_value: a1b2

    - name: get a rule
      fwebos_waf_csrf_page_rule:
       action: get
       name: c1
       id: 1

    - name: delete a rule
      fwebos_waf_csrf_page_rule:
       action: delete
       name: c1
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

obj_url = '/api/v2.0/cmdb/waf/csrf-protection/csrf-page-list'


rep_dict = {
  "host_status": "host-status",
  "request_type": "request-type",
  "parameter_value_type": "parameter-value-type",
  "request_url": "request-url",
  "parameter_filter": "parameter-filter",
  "parameter_name": "parameter-name",
  "parameter_value": "parameter-value",
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
    # # response['sent'] = payload1['data']
    return code, response

def delete_obj(module, connection):
    name = module.params['name']
    id = module.params['id']
    payload = {}
    url = obj_url + '?mkey=' + name + '&sub_mkey=' + id
    code, response = connection.send_request(url, payload, 'DELETE')

    return code, response


def get_obj(module, connection):
    name = module.params['name']
    payload = {}
    url = obj_url + '?mkey=' + name
    if module.params['id'] is not None:
        url = url + '&sub_mkey=' + module.params['id']
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
    payload1['data'].pop('action')

    res = combine_dict(payload1['data'], data)

    return res, data

def edit_obj(module, payload, connection):
    name = module.params['name']
    url = obj_url + '?mkey=' + name + '&sub_mkey=' + module.params['id']
    payload1 = {}
    payload1['data'] = payload
    code, response = connection.send_request(url, payload1, 'PUT')
    return code, response

def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = ''
    if (action == 'edit' or action == 'delete') and module.params['id'] is None:
            err_msg =  'The action \''+ action + '\' needs an valid \'id\''
            res = False  
    if module.params['host_status'] == 'enable' and module.params['host'] is None:
            err_msg =  '\'host\' cannot be empty when \'host_status\' is enabled'
            res = False
    if module.params['parameter_filter'] == 'enable':
        if module.params['parameter_name'] is None or module.params['parameter_value_type'] is None or module.params['parameter_value'] is None:
            err_msg = '\'parameter_name\', \'parameter_value_type\', and \'parameter_value\' should not be empty when \'parameter_filter\' is enabled'
            res = False
    if module.params['request_type'] is not None:
        if module.params['request_type']!='plain' and module.params['request_type']!='regular':
            err_msg = 'The value of \'request_type\' should be \'plain\', or \'regular\''
            res = False
    if module.params['parameter_value_type'] is not None:
        if module.params['parameter_value_type']!='plain' and module.params['parameter_value_type']!='regular':
            err_msg = 'The value of \'parameter_value_type\' should be \'plain\', or \'regular\''
            res = False
    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
        id=dict(type='str'),
        host=dict(type='str'),
        host_status=dict(type='str'),
        request_type=dict(type='str'),
        parameter_value_type=dict(type='str'),
        request_url=dict(type='str'),
        parameter_filter=dict(type='str'),
        parameter_name=dict(type='str'),
        parameter_value=dict(type='str'),
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
