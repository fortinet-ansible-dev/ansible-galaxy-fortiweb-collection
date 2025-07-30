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
module: fwebos_waf_xff
description:
  - Config FortiWeb X-Forward-For policy
version_added: "7.0.0"
authors:
  - Jie Li
  - Brad Zhang
requirements:
    - ansible>=2.11
options:
    name:
        description:
            - name
        type: string
    x-forwarded-for-support:
        description:
            - x forwarded for support
        type: string
        choices:
            - 'enable'
            - 'disable'
    add-source-port:
        description:
            - add source port in X-Forwarded-For
        type: string
        choices:
            - 'enable'
            - 'disable'
    x-forwarded-port:
        description:
            - X-Forwarded-Port
        type: string
        choices:
            - 'enable'
            - 'disable'
    tracing-original-ip:
        description:
            - tracing original IP
        type: string
        choices:
            - 'enable'
            - 'disable'
    original-ip-header:
        description:
            - original IP header
        type: string
    x-real-ip:
        description:
            - X-Real_IP
        type: string
        choices:
            - 'enable'
            - 'disable'
    x-forwarded-proto:
        description:
            - X-Forwarded-Proto
        type: string
        choices:
            - 'enable'
            - 'disable'
    block-based-on-original-ip:
        description:
            - block-based-on-original-ip
        type: string
        choices:
            - 'enable'
            - 'disable'
    ip-location:
        description:
            - ip-location
        type: string
        choices:
            - 'left'
            - 'right'
    skip-private-original-ip:
        description:
            - skip-private-original-ip
        type: string
        choices:
            - 'enable'
            - 'disable'
    skip-special-original-ip:
        description:
            - skip-special-original-ip
        type: string
        choices:
            - 'enable'
            - 'disable'
    block-based-on-full-scan:
        description:
            - block based on full scan modules
        type: string
        choices:
            - 'ip-reputation'
"""

EXAMPLES = """
     - name: delete xff
       fwebos_waf_xff:
        action: delete
        vdom: root
        name: test

     - name: Create xff
       fwebos_waf_xff:
        action: add
        vdom: root
        x_forwarded_for_support: enable
        add_source_port: disable
        x_forwarded_port: enable
        tracing_original_ip: enable
        x_real_ip: enable
        x_forwarded_proto: enable
        block_based_on_original_ip: enable
        ip_location: left
        original_ip_header: X-FORWARDED-FOR
        block_based_on_full_scan: ip-reputation
        name: test

     - name: edit xff
       fwebos_waf_xff:
        action: edit
        vdom: root
        x_forwarded_for_support: enable
        add_source_port: enable
        x_forwarded_port: enable
        tracing_original_ip: enable
        x_real_ip: enable
        x_forwarded_proto: enable
        block_based_on_original_ip: enable
        ip_location: left
        original_ip_header: X-FORWARDED-FOR
        block_based_on_full_scan: ip-reputation
        name: test


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

obj_url = '/api/v2.0/cmdb/waf/x-forwarded-for'

rep_dict = {
    'x_forwarded_for_support': 'x-forwarded-for-support',
    'add_source_port': 'add-source-port',
    'x_forwarded_port': 'x-forwarded-port',
    'tracing_original_ip': 'tracing-original-ip',
    'x_real_ip': 'x-real-ip',
    'x_forwarded_proto': 'x-forwarded-proto',
    'block_based_on_original_ip': 'block-based-on-original-ip',
    'ip_location': 'ip-location',
    'original_ip_header': 'original-ip-header',
    'block_based_on_full_scan': 'block-based-on-full-scan',
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
        x_forwarded_for_support=dict(type='str'),
        add_source_port=dict(type='str'),
        x_forwarded_port=dict(type='str'),
        tracing_original_ip=dict(type='str'),
        x_real_ip=dict(type='str'),
        x_forwarded_proto=dict(type='str'),
        block_based_on_original_ip=dict(type='str'),
        ip_location=dict(type='str'),
        original_ip_header=dict(type='str'),
        block_based_on_full_scan=dict(type='str'),
        name=dict(type='str'),
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
        if 'errcode' in str(data):
            result['changed'] = False
            result['res'] = data
        else:
            res, new_data = needs_update(module, data['results'])
            if res:
                result['new_data'] = new_data
                code, response = edit_obj(module, new_data, connection)
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
