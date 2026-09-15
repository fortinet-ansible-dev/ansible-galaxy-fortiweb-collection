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
module: fwebos_waf_dos_exception_policy
short_description: Config FortiWeb IP Group
description:
  - Config FortiWeb IP Group
version_added: "7.0.0"
author:
  - Joseph Chen
requirements:
    - ansible>=2.11
options:
    name:
        description:
            - The name of IP Group.
        type: string
"""

EXAMPLES = """
    - name: add a IP Group
      fwebos_ip_group:
       action: add
       name: ip_group_test1

    - name: get a DoS exception policy
      fwebos_ip_group:
       action: get
       name: ip_group_test1

    - name: delete a DoS exception policy
      fwebos_ip_group:
       action: delete
       name: ip_group_test1
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

obj_url = '/api/v2.0/cmdb/server-policy/ip-group'


rep_dict = {}


def add_obj(module, connection):
    payload = {
        'data':
        {
            'name': module.params['name'],
        },
    }

    code, response = connection.send_request(obj_url, payload)

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


def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = ''

    if action not in ['add', 'get', 'delete']:
        err_msg = 'error action: ' + action
        res = False
    if res and (action == 'add' or action == 'delete') and module.params['name'] is None:
        err_msg = 'name need to set'
        res = False

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
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
