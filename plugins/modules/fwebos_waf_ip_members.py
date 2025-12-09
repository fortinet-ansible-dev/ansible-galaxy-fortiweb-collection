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
module: fwebos_waf_ip_members
short_description: Config FortiWeb IP Protection IP List member
description:
  - Config FortiWeb IP Protection IP List member
version_added: "7.0.0"
author:
  - Jie Li
  - Brad Zhang
requirements:
    - ansible>=2.11
options:
    member_type:
        description:
            - type
        type: str
        choices:
            - 'trust-ip'
            - 'black-ip'
            - 'allow-only-ip'
"""

EXAMPLES = """
     - name: Create
       fwebos_waf_ip_members:
        action: add
        table_name: test4
        member_type: trust-ip
        ip: 5.5.5.5
        vdom: root


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

obj_url = '/api/v2.0/cmdb/waf/ip-list/members'


rep_dict = {}

def add_obj(module, connection):

    table_name = module.params['name']
    name = module.params['name']
    member_type = module.params['member_type']
    ip = module.params['ip']

    payload = {
        'data':
        {
            'type': member_type,
            'ip': ip,
        },
    }

    url = obj_url + '?mkey=' + table_name

    code, response = connection.send_request(url, payload)

    return code, response, payload


def edit_obj(module, payload, connection):
    table_name = module.params['name']
    id = module.params['id']
    url = obj_url + '?mkey=' + table_name + '&sub_mkey=' + id
    code, response = connection.send_request(url, payload, 'PUT')

    return code, response


def get_obj(module, connection):
    table_name = module.params['name']
    id = module.params['id']
    payload = {}
    url = obj_url + '?mkey=' + table_name
    if id:
        url += '&sub_mkey=' + id
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_obj(module, connection):
    table_name = module.params['name']
    id = module.params['id']
    payload = {}
    url = obj_url + '?mkey=' + table_name + '&sub_mkey=' + id
    code, response = connection.send_request(url, payload, 'DELETE')

    return code, response


def needs_update(module, data):
    res = False

    if module.params['member_type'] and module.params['member_type'] != data['type']:
        data['type'] = module.params['member_type']
        res = True
    if module.params['ip'] and module.params['ip'] != data['ip']:
        data['ip'] = module.params['ip']
        res = True

    out_data = {}
    out_data['data'] = data
    return res, out_data


def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = ''

    if (action == 'add' or action == 'edit' or action == 'delete' or action == 'get') and module.params['name'] is None:
        err_msg = '\'name\' cannot be empty.'
        res = False
    if action == 'add' and module.params['ip'] is None:
        err_msg = '\'ip\' cannot be empty for action \''+action+'\'.'
        res = False
    if (action == 'edit' or action == 'delete') and module.params['id'] is None:
        err_msg = '\'id\' cannot be empty for action \''+action+'\'.'
        res = False
    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
        id=dict(type='str'),
        member_type=dict(type='str'),
        ip=dict(type='str'),
        vdom=dict(type='str'),

    )
    argument_spec.update(fwebos_argument_spec)

    required_if = [('name')]
    module = AnsibleModule(argument_spec=argument_spec,
                           required_if=required_if,
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
    result = check_mode_process(module, data, None)
    if module.check_mode:
      if action == 'add':
        if isinstance(data['results'], list) and all(isinstance(item, dict) for item in data['results']):
          for entry in data['results']:
            if entry.get("ip") == module.params['ip']:
                result['changed'] = False
                result['res'] = 'The IP has already existed in the table.'
                break
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
        if result['res']['results']['errcode'] == -3 or result['res']['results']['errcode'] == -6014:
            result['failed'] = False

    module.exit_json(**result)


if __name__ == '__main__':
    main()