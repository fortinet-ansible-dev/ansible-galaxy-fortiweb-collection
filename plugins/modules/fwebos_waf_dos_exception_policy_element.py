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
module: fwebos_waf_dos_exception_policy_element
short_description: Config FortiWeb DoS Exception Policy Element
description:
  - Config FortiWeb DoS Exception Policy Element
version_added: "7.0.0"
author:
  - Joseph Chen
requirements:
    - ansible>=2.11
options:
    name:
        description:
            - The name of the DoS exception policy.
        type: string
    id:
        description:
            - The ID of the DoS exception policy element.
        type: string
    element_type:
        description:
            - Exception element type.
        type: string
        choices:
            - 'CLIENT_IP'
            - 'IP_GROUP'
    ip:
        description:
            - Client IP address.
        type: string
    ip_group:
        description:
            - IP group name.
        type: string
"""

EXAMPLES = """
    - name: add a DoS exception policy element
      fwebos_waf_dos_exception_policy_element:
       action: add
       name: dos_exception_policy_ansible_test
       element_type: CLIENT_IP
       ip: 2.3.4.5

    - name: get a DoS exception policy element
      fwebos_waf_dos_exception_policy_element:
       action: get
       name: dos_exception_policy_ansible_test
       id: 1

    - name: edit a DoS exception policy element
      fwebos_waf_dos_exception_policy_element:
       action: edit
       name: dos_exception_policy_ansible_test
       id: 1
       element_type: CLIENT_IP
       ip: 2.3.4.6

    - name: delete a DoS exception policy element
      fwebos_waf_dos_exception_policy_element:
       action: delete
       name: dos_exception_policy_ansible_test
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

obj_url = '/api/v2.0/cmdb/waf/dos-prevention-exception/exception-element-list'


rep_dict = {
    'element_type': 'element-type',
    'ip_group': 'ip-group',
}


def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)


def normalize_payload(data):
    if data.get('element-type') == 'CLIENT_IP':
        data['ip-group'] = ''
    if data.get('element-type') == 'IP_GROUP':
        data['ip'] = ''


def build_data(module):
    data = module.params.copy()
    for key in ['action', 'vdom', 'name']:
        if key in data:
            data.pop(key)
    for key in list(data.keys()):
        if data[key] is None:
            data.pop(key)
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
    if res and action == 'add' and module.params['element_type'] is None:
        err_msg = 'element_type need to set'
        res = False
    if res:
        res, err_msg = value_check(module.params, 'element_type', ['CLIENT_IP', 'IP_GROUP'])
    if res and action == 'add' and module.params['element_type'] == 'CLIENT_IP' and module.params['ip'] is None:
        err_msg = 'ip need to set'
        res = False
    if res and action == 'add' and module.params['element_type'] == 'IP_GROUP' and module.params['ip_group'] is None:
        err_msg = 'ip_group need to set'
        res = False

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
        id=dict(type='str'),
        element_type=dict(type='str'),
        ip=dict(type='str'),
        ip_group=dict(type='str'),
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
