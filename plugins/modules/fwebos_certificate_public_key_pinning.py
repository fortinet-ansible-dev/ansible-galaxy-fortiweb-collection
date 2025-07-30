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
module: fwebos_certificate_public_key_pinning
description:
  - Config FortiWeb server objects Public Key Pinning
version_added: "7.0.0"
authors:
  - Jie Li
  - Brad Zhang
requirements:
    - ansible>=2.11
options:
    name:
        description:
            - hpkp name
        type: string
    pin-sha256:
        description:
            - base64 encoded SPKI fingerprint
        type: string
    max-age:
        description:
            - max age(0 - 31536000 seconds) (range: 0-31536000)
        type: integer
    subdomains:
        description:
            - include subdomains
        type: string
        choices:
            - 'enable'
            - 'disable'
    report-uri:
        description:
            - report URI
        type: string
    report-only:
        description:
            - report only mode
        type: string
        choices:
            - 'enable'
            - 'disable'
"""

EXAMPLES = """
     - name: Create certificate public key pinning
       fwebos_certificate_public_key_pinning:
        action: add
        vdom: root1
        name: aaa
        pin_sha256: 111 aaa
        max_age: 1296000
        subdomains: disable
        subdomains_val: 0
        report_uri: aaa.com
        report_only: enable
        report_only_val: 1

     - name: edit certificate public key pining
       fwebos_certificate_public_key_pinning:
        action: edit
        vdom: root1
        name: aaa
        pin_sha256: 111 aaa
        max_age: 1296011
        subdomains: disable
        subdomains_val: 0
        report_uri: aaa.com
        report_only: enable
        report_only_val: 1

     - name: delete certificate public key pinning
       fwebos_certificate_public_key_pinning:
        action: delete
        vdom: root1
        name: aaa


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

obj_url = '/api/v2.0/cmdb/system/certificate.hpkp'

rep_dict = {
    'pin_sha256': 'pin-sha256',
    'max_age': 'max-age',
    'report_uri': 'report-uri',
    'report_only': 'report-only',
    'report_only_val': 'report-only_val',
}


def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)


def add_obj(module, connection):
    payload1 = {}
    payload1['data'] = module.params
    payload1['data'].pop('action')
    replace_key(payload1['data'], rep_dict)

    code, response = connection.send_request(obj_url, payload1)

    return code, response


def edit_obj(module, payload, connection):
    name = module.params['name']
    url = obj_url + '?mkey=' + name
    code, response = connection.send_request(url, payload, 'PUT')

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

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        vdom=dict(type='str'),
        name=dict(type='str'),
        pin_sha256=dict(type='str'),
        max_age=dict(type='int'),
        subdomains=dict(type='str'),
        subdomains_val=dict(type='str'),
        report_uri=dict(type='str'),
        report_only=dict(type='str'),
        report_only_val=dict(type='str'),
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
        code, response = add_obj(module, connection)
        result['res'] = response
        result['changed'] = True
    elif action == 'get':
        code, response = get_obj(module, connection)
        result['res'] = response
    elif action == 'edit':
        code, data = get_obj(module, connection)
        if 'results' in data.keys() and data['results'] and type(data['results']) is not int:
            res, new_data = needs_update(module, data['results'])
        else:
            res = False
            result['err_msg'] = 'Entry not found'
        if res:
            new_data1 = {}
            new_data1['data'] = new_data
            code, response = edit_obj(module, new_data1, connection)
            result['res'] = response
            result['changed'] = True
    elif action == 'delete':
        code, data = get_obj(module, connection)
        if 'results' in data.keys() and data['results'] and type(data['results']) is not int:
            code, response = delete_obj(module, connection)
            result['res'] = response
            result['changed'] = True
        else:
            res = False
            result['err_msg'] = 'Entry not found'
    else:
        result['err_msg'] = 'error action: ' + action
        result['failed'] = True

    # if 'res' in result.keys() and type(result['res']) is dict\
    #        and type(result['res']['results']) is int and result['res']['results'] < 0:
        # result['err_msg'] = get_err_msg(connection, result['res']['payload'])
    #    result['changed'] = False
    #    result['failed'] = True

    module.exit_json(**result)


if __name__ == '__main__':
    main()
