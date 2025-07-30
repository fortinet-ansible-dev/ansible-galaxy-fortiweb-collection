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
module: fwebos_waf_geo_block_country
description:
  - Edit Country list in GEO IP Policy
version_added: "7.0.0"
authors:
  - Jie Li
  - Brad Zhang
requirements:
    - ansible>=2.11
"""

EXAMPLES = """
     - name: Create
       fwebos_waf_geo_block_country:
        action: post
        table_name: test4
        add:
                - Armenia
        delete:
                - Bahamas
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

obj_url = '/api/v2.0/waf/geoip.setCountrys'
get_obj_url = '/api/v2.0/cmdb/waf/geo-block-list/country-list'


def add_obj(module, connection):

    table_name = module.params['table_name']
    name = module.params['name']
    add = module.params['add']
    delete = module.params['delete']

    payload = {
        'data':
        {
            'add': add,
            'del': delete,
        },
    }

    url = obj_url + '?mkey=' + table_name

    code, response = connection.send_request(url, payload)

    return code, response, payload


def get_obj(module, connection):
    table_name = module.params['table_name']
    name = module.params['name']
    payload = {}
    url = get_obj_url + '?mkey=' + table_name
    if name:
        url += '&sub_mkey=' + name
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = ''

    if action == 'post' and module.params['table_name'] is None:
        err_msg = 'table_name need to set'
        res = False

    if (action != 'post' and action != 'get'):
        err_msg = 'action only support post and get'
        res = False

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        table_name=dict(type='str'),
        name=dict(type='str'),
        add=dict(type='list'),
        delete=dict(type='list'),
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
    elif action == 'post':
        code, response, out = add_obj(module, connection)
        result['out'] = out
        result['res'] = response
        result['changed'] = True
    elif action == 'get':
        code, response = get_obj(module, connection)
        result['res'] = response
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
