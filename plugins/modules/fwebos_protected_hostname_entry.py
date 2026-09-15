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
module: fwebos_protected_hostname_entry
short_description: Config FortiWeb Protected Hostname Entry
description:
  - Config FortiWeb Protected Hostname Entry
version_added: "7.0.0"
author:
  - Joseph Chen
requirements:
    - ansible>=2.11
options:
    name:
        description:
            - The name of the protected hostname object.
        type: string
    id:
        description:
            - The ID of the protected hostname entry.
        type: string
    host:
        description:
            - Hostname.
        type: string
    ignore_port:
        description:
            - Enable or disable ignore port.
        type: string
        choices:
            - 'enable'
            - 'disable'
    include_subdomains:
        description:
            - Enable or disable include subdomains.
        type: string
        choices:
            - 'enable'
            - 'disable'
    override_header:
        description:
            - Enable or disable override header.
        type: string
        choices:
            - 'enable'
            - 'disable'
    host_action:
        description:
            - Action.
        type: string
        choices:
            - 'allow'
            - 'deny_no_log'
            - 'deny'
"""

EXAMPLES = """
    - name: add a protected hostname entry
      fwebos_protected_hostname_entry:
       action: add
       name: test.com
       host: host1
       ignore_port: enable
       include_subdomains: enable
       override_header: enable
       host_action: deny_no_log

    - name: get a protected hostname entry
      fwebos_protected_hostname_entry:
       action: get
       name: test.com
       id: 1

    - name: edit a protected hostname entry
      fwebos_protected_hostname_entry:
       action: edit
       name: test.com
       id: 1
       host: host1
       ignore_port: disable
       include_subdomains: disable
       override_header: disable
       host_action: allow

    - name: delete a protected hostname entry
      fwebos_protected_hostname_entry:
       action: delete
       name: test.com
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

obj_url = '/api/v2.0/cmdb/server-policy/allow-hosts/host-list'


rep_dict = {
    'ignore_port': 'ignore-port',
    'include_subdomains': 'include-subdomains',
    'override_header': 'override-header',
    'host_action': 'action',
}


def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)


def build_data(module):
    data = module.params.copy()
    for key in ['action', 'vdom', 'name']:
        if key in data:
            data.pop(key)
    for key in list(data.keys()):
        if data[key] is None:
            data.pop(key)
    replace_key(data, rep_dict)
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
    if res and action == 'add' and module.params['host'] is None:
        err_msg = 'host need to set'
        res = False
    if res:
        res, err_msg = value_check(module.params, 'ignore_port', ['enable', 'disable'])
    if res:
        res, err_msg = value_check(module.params, 'include_subdomains', ['enable', 'disable'])
    if res:
        res, err_msg = value_check(module.params, 'override_header', ['enable', 'disable'])
    if res:
        res, err_msg = value_check(module.params, 'host_action', ['allow', 'deny_no_log', 'deny'])

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
        id=dict(type='str'),
        host=dict(type='str'),
        ignore_port=dict(type='str'),
        include_subdomains=dict(type='str'),
        override_header=dict(type='str'),
        host_action=dict(type='str'),
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
