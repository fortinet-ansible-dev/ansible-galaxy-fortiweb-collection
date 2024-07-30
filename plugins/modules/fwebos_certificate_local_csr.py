#!/usr/bin/python
#
# This file is part of Ansible
#
#
# updata date:2019/03/12

from __future__ import (absolute_import, division, print_function)
import json
from urllib.parse import urlencode
from ansible_collections.fortinet.fortiweb.plugins.module_utils.network.fwebos.fwebos import (fwebos_argument_spec, is_global_admin, is_vdom_enable)
from ansible.module_utils.connection import Connection
from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}


DOCUMENTATION = """
---
module: fwebos_certificate_local_csr
description:
  - Configure FortiWeb devices via RESTful APIs
"""

EXAMPLES = """
"""

RETURN = """
"""

obj_url = '/api/v2.0/system/certificate.local.generate_csr'
del_url = '/api/v2.0/cmdb/system/certificate.local'

rep_dict = {
}

URL_HEADERS = {
    'Content-Type': 'application/x-www-form-urlencoded',
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
    payload1['data'].pop('vdom')
    replace_key(payload1['data'], rep_dict)

    # code, response = connection.send_request(obj_url, payload1, headers=URL_HEADERS)#(h, accept=content_type)
    # raise Exception(payload1['data'])
    for key in list(payload1['data'].keys()):
        if not payload1['data'].get(key):
            payload1['data'].pop(key)
    # raise Exception(urlencode(payload1['data']))
    code, response = connection.send_url_request(obj_url, urlencode(payload1['data']), headers=URL_HEADERS)

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
    url = del_url + '?mkey=' + name
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

    if is_vdom_enable(connection) and module.params['vdom'] is None:
        err_msg = 'vdom enable, vdom need to set'
        res = False

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        vdom=dict(type='str'),
        idType=dict(type='str'),
        alt_name_type=dict(type='str'),
        ip=dict(type='str'),
        keySize=dict(type='str'),
        enrollmentMethod=dict(type='str'),
        name=dict(type='str'),
        organization=dict(type='str'),
        localityCity=dict(type='str'),
        stateProvince=dict(type='str'),
        countryRegion=dict(type='str'),
        email=dict(type='str'),
        organizationUnit_1=dict(type='str'),
        organizationUnit_2=dict(type='str'),
        organizationUnit_3=dict(type='str'),
        alt_name_type_1=dict(type='str'),
        alt_name_type_2=dict(type='str'),
        alt_name_type_3=dict(type='str'),
        alt_name_text_1=dict(type='str'),
        alt_name_text_2=dict(type='str'),
        alt_name_text_3=dict(type='str'),
        caServerURL=dict(type='str'),
        challengePassword=dict(type='str'),
        domainName=dict(type='str'),
        subjectEmail=dict(type='str'),
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
        if 'errcode' in str(result) and result['res']['errcode'] == "-5":
            del result['res']['errcode']
    elif action == 'get': #cannot use this method now
        code, response = get_obj(module, connection)
        result['res'] = response
    elif action == 'delete':
        code, response = delete_obj(module, connection)
        if 'results' in response.keys() and type(response['results']) is dict\
            and 'errcode' in response['results'].keys() and type(response['results']['errcode']) is int \
                and response['results']['errcode'] == -3:
            del response['results']['errcode']
        result['res'] = response
    else:
        result['err_msg'] = 'error action: ' + action

    if 'errcode' in str(result):
        result['changed'] = False
        result['failed'] = True
        # if result['res']['errcode'] == -3 or result['res']['errcode'] == "-5":
        #     result['failed'] = False

    # if 'res' in result.keys() and type(result['res']) is dict\
    #        and type(result['res']['results']) is int and result['res']['results'] < 0:
        # result['err_msg'] = get_err_msg(connection, result['res']['payload'])
    #    result['changed'] = False
    #    result['failed'] = True

    module.exit_json(**result)


if __name__ == '__main__':
    main()
