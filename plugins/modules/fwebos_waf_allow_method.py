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
module: fwebos_waf_allow_method
short_description: Config FortiWeb Web Protection Allow Method Policy
description:
  - Config FortiWeb Web Protection Allow Method Policy
version_added: "7.0.0"
author:
  - Joseph Chen
requirements:
    - ansible>=2.11
options:
    name:
        description:
            - The name of the allow method policy.
        type: string
    allow_method:
        description:
            - HTTP methods to allow. Use a space-separated string such as C(post head).
        type: string
    override_header:
        description:
            - Enable or disable override header.
        type: string
        choices:
            - 'enable'
            - 'disable'
    override_parameter:
        description:
            - Enable or disable override parameter.
        type: string
        choices:
            - 'enable'
            - 'disable'
    severity:
        description:
            - Severity.
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    triggered_action:
        description:
            - Trigger policy name.
        type: string
    allow_method_exception:
        description:
            - Allow method exception name.
        type: string
"""

EXAMPLES = """
    - name: add an allow method policy
      fwebos_waf_allow_method:
       action: add
       name: allow_1
       allow_method: post
       override_header: enable
       override_parameter: enable
       severity: Medium

    - name: edit an allow method policy
      fwebos_waf_allow_method:
       action: edit
       name: allow_1
       allow_method: post head
       override_header: enable
       override_parameter: disable
       severity: Info
       triggered_action: trigger_policy1

    - name: get an allow method policy
      fwebos_waf_allow_method:
       action: get
       name: allow_1

    - name: delete an allow method policy
      fwebos_waf_allow_method:
       action: delete
       name: allow_1
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

obj_url = '/api/v2.0/cmdb/waf/allow-method-policy'


rep_dict = {
    'allow_method': 'allow-method',
    'override_header': 'override-header',
    'override_parameter': 'override-parameter',
    'triggered_action': 'triggered-action',
    'allow_method_exception': 'allow-method-exception',
}


def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)


def normalize_payload(data):
    if data.get('allow-method') is not None:
        data['allow-method'] = ' '.join(data['allow-method'].lower().split())


def result_data(data, name=None):
    if data is None or 'results' not in data:
        return None
    results = data['results']
    if isinstance(results, dict):
        return results
    if isinstance(results, list):
        if name is None:
            return results
        for item in results:
            if isinstance(item, dict) and item.get('name') == name:
                return item
    return None


def data_for_check_mode(data, name=None):
    item = result_data(data, name)
    if isinstance(item, dict):
        return {'results': item}
    return {'results': []}


def add_obj(module, connection):
    payload1 = {}
    payload1['data'] = module.params
    if 'action' in payload1['data'].keys():
        payload1['data'].pop('action')
    replace_key(payload1['data'], rep_dict)
    normalize_payload(payload1['data'])
    code, response = connection.send_request(obj_url, payload1)

    return code, response


def edit_obj(module, payload, connection):
    name = module.params['name']
    url = obj_url + '?mkey=' + name
    payload1 = {}
    payload1['data'] = payload
    code, response = connection.send_request(url, payload1, 'PUT')

    return code, response


def get_obj(module, connection):
    name = module.params['name']
    payload = {}
    url = obj_url
    if name:
        url += '?mkey=' + name
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_obj(module, connection):
    name = module.params['name']
    payload = {}
    url = obj_url + '?mkey=' + name
    code, response = connection.send_request(url, payload, 'DELETE')

    return code, response


def compare_value(key, old_value, new_value):
    if isinstance(old_value, str) and isinstance(new_value, str):
        if key == 'allow-method':
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
    res = False
    payload1 = {}
    payload1['data'] = module.params
    if 'action' in payload1['data'].keys():
        payload1['data'].pop('action')
    replace_key(payload1['data'], rep_dict)
    normalize_payload(payload1['data'])

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


def allow_method_check(params):
    msg = ''
    res = True
    good_values = ['get', 'post', 'head', 'options', 'trace', 'connect', 'delete', 'put', 'patch', 'webdav', 'rpc', 'others']
    if params['allow_method'] is not None:
        params['allow_method'] = ' '.join(params['allow_method'])
        for method in params['allow_method'].lower().split():
            if method not in good_values:
                res = False
                quoted_good_values = [f"'{val}'" for val in good_values]
                msg = 'The value of \'allow_method\' should contain only ' + ', '.join(quoted_good_values[:-1]) + ', or ' + quoted_good_values[-1] + '.'
                return res, msg

    return res, msg


def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = ''

    if action not in ['add', 'get', 'edit', 'delete']:
        err_msg = 'error action: ' + action
        res = False
    if res and (action == 'add' or action == 'edit' or action == 'delete') and module.params['name'] is None:
        err_msg = 'name need to set'
        res = False
    if res:
        res, err_msg = value_check(module.params, 'override_header', ['enable', 'disable'])
    if res:
        res, err_msg = value_check(module.params, 'override_parameter', ['enable', 'disable'])
    if res:
        res, err_msg = value_check(module.params, 'severity', ['High', 'Medium', 'Low', 'Info'])
    if res:
        res, err_msg = allow_method_check(module.params)

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
        allow_method=dict(type='list'),
        override_header=dict(type='str'),
        override_parameter=dict(type='str'),
        severity=dict(type='str'),
        triggered_action=dict(type='str'),
        allow_method_exception=dict(type='str'),
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
        result = check_mode_process(module, data_for_check_mode(data, module.params['name']), rep_dict)
    if module.check_mode:
      module.exit_json(**result)

    if action == 'add':
        code, response = add_obj(module, connection)
        result['res'] = response
        result['changed'] = True
    elif action == 'get':
        code, response = get_obj(module, connection)
        result['res'] = response
    elif action == 'edit':
        code, data = get_obj(module, connection)
        existing_data = result_data(data, module.params['name'])
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
        existing_data = result_data(data, module.params['name'])
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
