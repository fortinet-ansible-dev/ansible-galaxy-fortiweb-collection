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
module: fwebos_waf_url_rewriting_rule
description:
  - Configure FortiWeb URL Rewriting Rules
version_added: "7.0.0"
authors:
  - Jie Li
  - Brad Zhang
requirements:
    - ansible>=2.11
options:
    name:
        description:
            - The name of  URL Rewriting Rule.
        type: string
    action_type:
        description:
            - Action Type.
        type: string
        choices:
            - 'redirect'
            - '403-forbidden'
            - 'http-header-rewrite'
            - 'http-response-body-rewrite'
            - 'http-response-header-rewrite'
            - 'redirect-301'
            - 'http-request-body-rewrite'
    status_code_status:
        description:
            - Status of Replacement Status Code.
        type: string
        choices:
            - 'enable'
            - 'disable'
    status_code:
        description:
            - Number of Replacement Status Code. (range: 100-599)
        type: integer
    location_status:
        description:
            - Status of Replacement String.
        type: string
        choices:
            - 'enable'
            - 'disable'
    location_replace:
        description:
            - Value of Replacement String.
        type: string
    body_replace:
        description:
            - The string that will replace content in the body of HTTP responses..
        type: string
    response_replace_existing_headers:
        description:
            - Only available when 'action_type' is 'http-response-header-rewrite'. Enable or Disable Replace Existing Headers which overwrites the value of the existing header with your specified header value.  On the other hand, if this option is disabled, the system will insert the header directly without checking if there is an existing header with the same header name.
        type: string
        choices:
            - 'enable'
            - 'disable'
    request_replace_existing_headers:
        description:
            - Only available when 'action_type' is 'http-header-rewrite'. Enable or Disable Replace Existing Headers which overwrites the value of the existing header with your specified header value.  On the other hand, if this option is disabled, the system will insert the header directly without checking if there is an existing header with the same header name.
        type: string
        choices:
            - 'enable'
            - 'disable'
    response_remove_duplicate_headers:
        description:
            - Only available when 'action_type' is 'http-response-header-rewrite'. Enabling this option will remove all multiple items that match your specified header name. However, if this option is disabled, only the first matching item will be removed.
        type: string
        choices:
            - 'enable'
            - 'disable'
    request_remove_duplicate_headers:
        description:
            - Only available when 'action_type' is 'http-header-rewrite'. Enabling this option will remove all multiple items that match your specified header name. However, if this option is disabled, only the first matching item will be removed.
        type: string
        choices:
            - 'enable'
            - 'disable'
    request_replace_existing_cookies:
        description:
            - Only available when 'action_type' is 'http-header-rewrite'. If there is already a cookie with the same name existing in the request, enabling this option will overwrite the value of the existing cookie with your specified cookie value.
        type: string
        choices:
            - 'enable'
            - 'disable'
    request_remove_duplicate_cookies:
        description:
            - Only available when 'action_type' is 'http-header-rewrite'. If the system finds multiple items that match your specified cookie name, enabling this option will remove all of them. However, if this option is disabled, only the first matching item will be removed.
        type: string
        choices:
            - 'enable'
            - 'disable'
"""

EXAMPLES = """
    - name: add a URL rewriting policy
      fwebos_waf_url_rewriting_rule:
        action: add
        name: test1
        action_type: http-response-header-rewrite
        host_status: disable
        url_status: disable
        referer_status: disable
        location_replace:
        location_status: disable
        http_method_status: disable
        http_method: get
        status_code_status: disable
        status_code: 404
        request_replace_existing_headers: disable
        response_replace_existing_headers: disable
        request_remove_duplicate_headers: enable
        response_remove_duplicate_headers: enable
        request_remove_duplicate_cookies: disable
        request_replace_existing_cookies: disable
        response_removal_list:
         - { "response-removal-header-name": "to-remove5"}
         - { "response-removal-header-name": "to-remove4"}
        response_insert_list:
         - { "response-header-name": "to-insert", "response-header-value": "inserted" }
        flag_operation: 0

    - name: get a URL rewriting policy
      fwebos_waf_url_rewriting_rule:
        action: get
        name: test1

    - name: add a URL rewriting policy
      fwebos_waf_url_rewriting_rule:
        action: add
        name: test2
        action_type: http-header-rewrite
        host_status: enable
        host_use_pserver: enable
        host: FORTIWEB_PSERVER
        url_status: enable
        url: www.url1.com
        referer_status: enable
        referer_use_pserver: enable
        referer: http://FORTIWEB_PSERVER/
        location_replace:
        location_status: disable
        http_method_status: enable
        http_method: get
        status_code_status: enable
        status_code: 404
        request_replace_existing_headers: enable
        response_replace_existing_headers: disable
        request_remove_duplicate_headers: enable
        response_remove_duplicate_headers: enable
        request_remove_duplicate_cookies: enable
        request_replace_existing_cookies: enable


    - name: edit a URL rewriting policy
      fwebos_waf_url_rewriting_rule:
        action: edit
        name: test1
        action_type: http-response-header-rewrite
        request_remove_duplicate_headers: enable
        response_remove_duplicate_headers: enable
        response_removal_list:
         - { "response-removal-header-name": "r1"}
         - { "response-removal-header-name": "r2"}
         - { "response-removal-header-name": "r3"}
         - { "response-removal-header-name": "r4"}
        response_insert_list:
         - { "response-header-name": "i1", "response-header-value": "iv1" }
         - { "response-header-name": "i2", "response-header-value": "iv2" }
         - { "response-header-name": "i3", "response-header-value": "iv3" }

    - name: edit a URL rewriting policy
      fwebos_waf_url_rewriting_rule:
        action: edit
        name: test2
        action_type: http-request-body-rewrite
        body_replace: replacement301

    - name: delete a URL rewriting policy
      fwebos_waf_url_rewriting_rule:
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

obj_url = '/api/v2.0/waf/urlrewrite.responseheaderremoval'
entry_url = '/api/v2.0/cmdb/waf/url-rewrite.url-rewrite-rule'

rep_dict = {
    "action_type": "action",
    "host_status": "host-status",
    "host_use_pserver": "host-use-pserver",
    "url_status": "url-status",
    "referer_status": "referer-status",
    "referer_use_pserver": "referer-use-pserver",
    "location_status": "location-status",
    "location_status_val": "location-status_val",
    "http_method_status": "http-method-status",
    "http_method": "http-method",
    "status_code_status": "status-code-status",
    "status_code": "status-code",
    "request_replace_existing_headers": "request-replace-existing-headers",
    "response_replace_existing_headers": "response-replace-existing-headers",
    "request_remove_duplicate_headers": "request-remove-duplicate-headers",
    "response_remove_duplicate_headers": "response-remove-duplicate-headers",
    "request_remove_duplicate_cookies": "request-remove-duplicate-cookies",
    "request_replace_existing_cookies": "request-replace-existing-cookies"
}

action_type_to_val = {
    'redirect':'3',
    '403-forbidden':'4',
    'http-header-rewrite':'5',
    'http-response-body-rewrite':'6',
    'http-response-header-rewrite':'7',
    'redirect-301':'8',
    'http-request-body-rewrite':'9'
}

def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)

def add_obj(module, connection):
    url = obj_url
    if 'action_type' in module.params:
        if module.params['action_type'] == 'http-request-body-rewrite' or module.params['action_type'] == 'http-response-body-rewrite': #or module.params['action_type'] == 'http-header-rewrite':
            url = entry_url
        else:
            url = obj_url
    payload1 = {}
    payload1['data'] = module.params
    payload1['data'].pop('action')
    replace_key(payload1['data'], rep_dict)
    if payload1['data']['action'] is not None:
        payload1['data']['action_val'] = action_type_to_val[payload1['data']['action']]
    code, response = connection.send_request(url, payload1)
    # response['sent'] = payload1['data']

    return code, response, payload1['data']


def edit_obj(module, payload, connection):
    name = module.params['name']
    url1 = obj_url + '?mkey=' + name
    url2 = entry_url + '?mkey=' + name
    if 'id' in module.params and module.params['id'] is not None:
        url1 += '&sub_mkey=' + module.params['id']
        url2 += '&sub_mkey=' + module.params['id']
    payload1 = {}
    payload1['data'] = payload
    if payload1['data']['action'] is not None:
        payload1['data']['action_val'] = action_type_to_val[payload1['data']['action']]
    code, response = connection.send_request(url1, payload1, 'PUT')
    code, response = connection.send_request(url2, payload1, 'PUT')
    # # response['url'] = url
    return code, response


def get_obj(module, connection):
    name = module.params['name']
    payload = {}
    url = entry_url + '?mkey=' + name
    if 'id' in module.params and module.params['id'] is not None:
        url += '&sub_mkey=' + module.params['id']
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_obj(module, connection):
    name = module.params['name']
    url = entry_url + '?mkey=' + name
    if 'id' in module.params and module.params['id'] is not None:
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

    for key in ['response_removal_list', 'response_insert_list', 'insert_list', 'cookie_insert_list', 'removal_list','cookie_removal_list']:
        if src_dict[key] is not None:
            dst_dict[key] = src_dict[key]
            changed = True

    return changed

def needs_update(module, data):
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

    if (action == 'add' or action == 'edit' or action == 'delete') and module.params['name'] is None:
        err_msg = 'name need to set'
        res = False
    res, err_msg = value_check(module.params, 'action_type', ['redirect', '403-forbidden', 'http-header-rewrite', 'http-response-body-rewrite', 'http-response-header-rewrite', 'redirect-301', 'http-request-body-rewrite'])
    if res == False:
        return res, err_msg
    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
        vdom=dict(type='str'),
        action_type=dict(type='str'),
        host_status=dict(type='str'),
        host_use_pserver=dict(type='str'),
        host=dict(type='str'),
        url_status=dict(type='str'),
        url=dict(type='str'),
        referer_status=dict(type='str'),
        referer_use_pserver=dict(type='str'),
        referer=dict(type='str'),
        location_replace=dict(type='str'),
        location_status=dict(type='str'),
        http_method_status=dict(type='str'),
        http_method=dict(type='str'),
        status_code_status=dict(type='str'),
        status_code=dict(type='str'),
        request_replace_existing_headers=dict(type='str'),
        response_replace_existing_headers=dict(type='str'),
        request_remove_duplicate_headers=dict(type='str'),
        response_remove_duplicate_headers=dict(type='str'),
        request_remove_duplicate_cookies=dict(type='str'),
        request_replace_existing_cookies=dict(type='str'),
        flag_operation=dict(type='str'),
        body_replace=dict(type='str'),
        insert_list=dict(type='list'),
        cookie_insert_list=dict(type='list'),
        removal_list=dict(type='list'),
        cookie_removal_list=dict(type='list'),
        response_removal_list=dict(type='list'),
        response_insert_list=dict(type='list'),
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

    if 'res' in result and 'result' in result['res'] and result['res']['results']['pingResult'] == -5:
        result['err_msg'] = 'Duplicated entry found'
        result['changed'] = False

    module.exit_json(**result)


if __name__ == '__main__':
    main()

            