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
from ansible.module_utils.urls import prepare_multipart
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}


DOCUMENTATION = """
---
module: fwebos_certificate_local_import_certificate
description:
  - Configure FortiWeb devices via RESTful APIs
"""

EXAMPLES = """
"""

RETURN = """
"""

add_url = '/api/v2.0/system/certificate.local.import_certificate'
get_url = '/api/v2.0/cmdb/system/certificate.local'

rep_dict = {
}


def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)


def add_obj_pkcs12_certificate(module, connection):
    payload1 = {}
    payload1['data'] = module.params

    data1 = {
        'type': payload1['data']['type'],
        'password': payload1['data']['password'],
        'certificateWithKeyFile': {
            'filename': payload1['data']['certificateWithKeyFile'],
        },
    }
    content_type, b_data = prepare_multipart(data1)

    headers = {
        'Content-type': content_type,
    }
    code, response = connection.send_url_request(add_url, b_data.decode('ascii'), headers=headers)
    return code, response


def add_obj_certificate(module, connection):
    payload1 = {}
    payload1['data'] = module.params

    data1 = {
        'type': payload1['data']['type'],
        'password': payload1['data']['password'],
        'certificateFile': {
            'filename': payload1['data']['certificateFile'],
        },
        'keyFile': {
            'filename': payload1['data']['keyFile'],
        },
        'hsm': payload1['data']['hsm'],
    }
    content_type, b_data = prepare_multipart(data1)

    headers = {
        'Content-type': content_type,
    }
    code, response = connection.send_url_request(add_url, b_data.decode('ascii'), headers=headers)
    return code, response


def add_obj_local_certificate(module, connection):
    payload1 = {}
    payload1['data'] = module.params

    data1 = {
        'type': payload1['data']['type'],
        'certificateFile': {
            'filename': payload1['data']['certificateFile'],
        },
    }
    content_type, b_data = prepare_multipart(data1)

    headers = {
        'Content-type': content_type,
    }
    code, response = connection.send_url_request(add_url, b_data.decode('ascii'), headers=headers)
    return code, response


def add_obj(module, connection):
    if(module.params['type'] == 'PKCS12Certificate'):
        return add_obj_pkcs12_certificate(module, connection)
    elif(module.params['type'] == 'certificate'):
        return add_obj_certificate(module, connection)
    elif(module.params['type'] == 'localCertificate'):
        return add_obj_local_certificate(module, connection)


def get_obj(module, connection):
    name = module.params['name']
    payload = {}
    url = get_url
    if name:
        url += '?mkey=' + name
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_obj(module, connection):
    name = module.params['name']
    payload = {}
    url = get_url + '?mkey=' + name
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

    if is_vdom_enable(connection) and module.params['vdom'] is None:
        err_msg = 'vdom enable, vdom need to set'
        res = False

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        vdom=dict(type='str'),
        name=dict(type='str'),
        type=dict(type='str'),
        certificateWithKeyFile=dict(type='str'),
        password=dict(type='str'),
        certificateFile=dict(type='str'),
        keyFile=dict(type='str'),
        hsm=dict(type='str'),
    )
    argument_spec.update(fwebos_argument_spec)

    required_if = [('name')]
    module = AnsibleModule(argument_spec=argument_spec,
                           required_if=required_if)
    action = module.params['action']
    result = {}
    connection = Connection(module._socket_path)
    param_pass, param_err = param_check(module, connection)
    if is_vdom_enable(connection) and param_pass:
        connection.change_auth_for_vdom(module.params['vdom'])

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
        if result['res']['results']['errcode'] == -3:
            result['failed'] = False

    module.exit_json(**result)


if __name__ == '__main__':
    main()
