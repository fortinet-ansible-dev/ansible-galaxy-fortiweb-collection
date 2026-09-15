#!/usr/bin/python
#
# This file is part of Ansible
#
#
# updata date:2019/03/12

from __future__ import (absolute_import, division, print_function)
import json
from ansible_collections.fortinet.fortiweb.plugins.module_utils.network.fwebos.fwebos import (fwebos_argument_spec, is_global_admin, is_vdom_enable, check_mode_process)
from ansible.module_utils.connection import Connection
from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}


DOCUMENTATION = """
---
module: fwebos_waf_allow_method_exceptions_list
short_description: Config FortiWeb Web Protection Allow Method Exception List
description:
  - Config FortiWeb Web Protection Allow Method Exception List
version_added: "7.0.0"
author:
  - Joseph Chen
requirements:
    - ansible>=2.11
options:
    name:
        description:
            - The name of the allow method exceptions object.
        type: string
    id:
        description:
            - The ID of the allow method exception list entry.
        type: string
    host:
        description:
            - Host name to match when host_status is enabled.
        type: string
    host_status:
        description:
            - Enable or disable host matching.
        type: string
        choices:
            - 'enable'
            - 'disable'
    request_file:
        description:
            - URL pattern.
        type: string
    request_type:
        description:
            - URL pattern type.
        type: string
        choices:
            - 'plain'
            - 'regular'
    allow_request:
        description:
            - HTTP methods to allow. Use a space-separated string such as C(get post patch).
        type: string
"""

EXAMPLES = """
    - name: add an allow method exception list entry
      fwebos_waf_allow_method_exceptions_list:
       action: add
       name: ae1
       host_status: enable
       host: Host1
       request_type: plain
       request_file: /adafa/cd
       allow_request: patch

    - name: get an allow method exception list entry
      fwebos_waf_allow_method_exceptions_list:
       action: get
       name: ae1
       id: 1

    - name: edit an allow method exception list entry
      fwebos_waf_allow_method_exceptions_list:
       action: edit
       name: ae1
       id: 1
       host_status: disable
       request_type: plain
       request_file: /adafa/cd
       allow_request: get post

    - name: delete an allow method exception list entry
      fwebos_waf_allow_method_exceptions_list:
       action: delete
       name: ae1
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

obj_url = '/api/v2.0/cmdb/waf/allow-method-exceptions/allow-method-exception-list'


rep_dict = {
    'host_status': 'host-status',
    'request_file': 'request-file',
    'request_type': 'request-type',
    'allow_request': 'allow-request',
}


def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)


def normalize_payload(data):
    if data.get('allow-request') is not None:
        data['allow-request'] = ' '.join(data['allow-request'].lower().split())
    if data.get('host-status') == 'disable':
        data['host'] = ''


def build_data(module):
    data = module.params.copy()
    for key in ['action', 'vdom', 'name']:
        if key in data:
            data.pop(key)
    if 'id' in data and data['id'] is None:
        data.pop('id')
    replace_key(data, rep_dict)
    normalize_payload(data)
    return data


def result_data(data, sub_mkey=None):
    if data is None or 'results' not in data:
        return None
    results = data['results']
    if isinstance(results, dict):
        return results
    if isinstance(results, list):
        if sub_mkey is None:
            return results
        for item in results:
            if isinstance(item, dict) and str(item.get('id')) == str(sub_mkey):
                return item
    return None


def data_for_check_mode(data, sub_mkey=None):
    item = result_data(data, sub_mkey)
    if isinstance(item, dict):
        return {'results': item}
    return {'results': []}


def add_obj(module, connection):
    name = module.params['name']
    url = obj_url + '?mkey=' + name
    payload1 = {}
    payload1['data'] = build_data(module)
    code, response = connection.send_request(url, payload1)

    return code, response, payload1['data']


def edit_obj(module, payload, connection):
    name = module.params['name']
    url = obj_url + '?mkey=' + name
    if module.params['id'] is not None:
        url += '&sub_mkey=' + module.params['id']
    payload1 = {}
    payload1['data'] = payload
    code, response = connection.send_request(url, payload1, 'PUT')

    return code, response


def get_obj(module, connection):
    name = module.params['name']
    payload = {}
    url = obj_url + '?mkey=' + name
    if module.params['id'] is not None:
        url += '&sub_mkey=' + module.params['id']
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_obj(module, connection):
    name = module.params['name']
    payload = {}
    url = obj_url + '?mkey=' + name
    if module.params['id'] is not None:
        url += '&sub_mkey=' + module.params['id']
    code, response = connection.send_request(url, payload, 'DELETE')

    return code, response


def compare_value(key, old_value, new_value):
    if isinstance(old_value, str) and isinstance(new_value, str):
        if key == 'allow-request':
            return ' '.join(old_value.lower().split()) == ' '.join(new_value.lower().split())
        return old_value.rstrip() == new_value.rstrip()
    return old_value == new_value


def combine_dict(src_dict, dst_dict):
    changed = False
    for key in dst_dict:
        if key in src_dict and src_dict[key] is not None and not compare_value(key, dst_dict[key], src_dict[key]):
            dst_dict[key] = src_dict[key]
            changed = True

    return changed


def needs_update(module, data):
    payload1 = {}
    payload1['data'] = build_data(module)
    res = combine_dict(payload1['data'], data)

    return res, data


def value_check(params, key_name, good_values):
    msg = ''
    res = True
    if params[key_name] is not None:
        value_is_good = False
        for v in good_values:
            if params[key_name] == v:
                value_is_good = True
                return res, msg
        if value_is_good == False:
            res = False
            msg = 'The value of \'' + key_name + '\' should be'
            if len(good_values) == 1:
                msg += f" '{good_values[0]}'."
            else:
                quoted_good_values = [f"'{val}'" for val in good_values]
                msg += f" {', '.join(quoted_good_values[:-1])}, or {quoted_good_values[-1]}."

    return res, msg


def allow_request_check(params):
    msg = ''
    res = True
    good_values = ['get', 'post', 'head', 'options', 'trace', 'connect', 'delete', 'put', 'patch', 'webdav', 'rpc', 'others']
    if params['allow_request'] is not None:
        params['allow_request'] = ' '.join(params['allow_request'])
        for method in params['allow_request'].lower().split():
            if method not in good_values:
                res = False
                quoted_good_values = [f"'{val}'" for val in good_values]
                msg = 'The value of \'allow_request\' should contain only ' + ', '.join(quoted_good_values[:-1]) + ', or ' + quoted_good_values[-1] + '.'
                return res, msg

    return res, msg


def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = ''

    if action not in ['add', 'edit', 'get', 'delete']:
        err_msg = 'error action: ' + action
        res = False
    if res and module.params['name'] is None:
        err_msg = 'name need to set'
        res = False
    if res and (action == 'edit' or action == 'delete') and module.params['id'] is None:
        err_msg = 'id need to set for action \'' + action + '\''
        res = False
    if res and action == 'add' and module.params['request_file'] is None:
        err_msg = 'request_file need to set'
        res = False
    if res:
        res, err_msg = value_check(module.params, 'host_status', ['enable', 'disable'])
    if res:
        res, err_msg = value_check(module.params, 'request_type', ['plain', 'regular'])
    if res:
        res, err_msg = allow_request_check(module.params)

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
        id=dict(type='str'),
        host=dict(type='str'),
        host_status=dict(type='str'),
        request_file=dict(type='str'),
        request_type=dict(type='str'),
        allow_request=dict(type='list'),
        vdom=dict(type='str'),
    )
    argument_spec.update(fwebos_argument_spec)

    module = AnsibleModule(argument_spec=argument_spec,
                           supports_check_mode=True)
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
        module.exit_json(**result)

    code, data = get_obj(module, connection)
    if action == 'get':
        result = check_mode_process(module, data, rep_dict)
    else:
        result = check_mode_process(module, data_for_check_mode(data, module.params['id']), rep_dict)
    if module.check_mode:
      module.exit_json(**result)

    if action == 'add':
        code, response, out_data = add_obj(module, connection)
        result['res'] = response
        result['changed'] = True
    elif action == 'get':
        code, response = get_obj(module, connection)
        result['res'] = response
    elif action == 'edit':
        code, data = get_obj(module, connection)
        existing_data = result_data(data, module.params['id'])
        if existing_data is None or 'errcode' in str(existing_data):
            result['err_msg'] = 'Entry not found'
        else:
            res, new_data = needs_update(module, existing_data)
            if res:
                code, response = edit_obj(module, new_data, connection)
                result['new_data'] = new_data
                result['res'] = response
                result['changed'] = True
    elif action == 'delete':
        code, data = get_obj(module, connection)
        existing_data = result_data(data, module.params['id'])
        if existing_data is None or 'errcode' in str(existing_data):
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
        if 'res' in result and 'results' in result['res'] and result['res']['results']['errcode'] in [-3, -5]:
            result['failed'] = False

    module.exit_json(**result)


if __name__ == '__main__':
    main()
