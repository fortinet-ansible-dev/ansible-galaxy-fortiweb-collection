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
module: fwebos_admin_profiles
description:
  - Configure FortiWeb admin profiles
version_added: "7.0.0"
authors:
  - Jie Li
  - Brad Zhang
requirements:
    - ansible>=2.11
options:
    name:
        description:
            - profile name
        type: string
    mntgrp:
        description:
            - Access permission for maintain group policy/profile
        type: string
        choices:
            - 'none'
            - 'r'
            - 'rw'
    admingrp:
        description:
            - Access permission for admin group policy/profile
        type: string
        choices:
            - 'none'
            - 'r'
            - 'rw'
    sysgrp:
        description:
            - Access permission for system group policy/profile
        type: string
        choices:
            - 'none'
            - 'r'
            - 'rw'
    netgrp:
        description:
            - Access permission for network group policy/profile
        type: string
        choices:
            - 'none'
            - 'r'
            - 'rw'
    loggrp:
        description:
            - Access permission for log group policy/profile
        type: string
        choices:
            - 'none'
            - 'r'
            - 'rw'
    authusergrp:
        description:
            - Access permission for auth user group policy/profile
        type: string
        choices:
            - 'none'
            - 'r'
            - 'rw'
    traroutegrp:
        description:
            - Access permission for traffic route group policy/profile
        type: string
        choices:
            - 'none'
            - 'r'
            - 'rw'
    wafgrp:
        description:
            - Access permission for waf group policy/profile
        type: string
        choices:
            - 'none'
            - 'r'
            - 'rw'
    wadgrp:
        description:
            - Access permission for wad group policy/profile
        type: string
        choices:
            - 'none'
            - 'r'
            - 'rw'
    wvsgrp:
        description:
            - Access permission for wvs group policy/profile
        type: string
        choices:
            - 'none'
            - 'r'
            - 'rw'
    mlgrp:
        description:
            - Access permission for ml group policy/profile
        type: string
        choices:
            - 'none'
            - 'r'
            - 'rw'
"""

EXAMPLES = """
     - name: Create profile
       fwebos_admin_profiles:
        action: add
        name: test
        mntgrp: r
        admingrp: rw
        sysgrp: none
        netgrp: none
        loggrp: none
        authusergrp: none
        traroutegrp: none
        wafgrp: none
        wadgrp: none
        wvsgrp: none
        mlgrp: none

     - name: Edit profile
       fwebos_admin_profiles:
        action: edit
        name: test
        mntgrp: rw
        admingrp: r
        sysgrp: none
        netgrp: none
        loggrp: none
        authusergrp: none
        traroutegrp: none
        wafgrp: none
        wadgrp: none
        wvsgrp: none
        mlgrp: none

     - name: delete profile
       fwebos_admin_profiles:
        action: delete
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

obj_url = '/api/v2.0/cmdb/system/accprofile'

rep_dict = {
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
        name=dict(type='str'),
        mntgrp=dict(type='str'),
        admingrp=dict(type='str'),
        sysgrp=dict(type='str'),
        netgrp=dict(type='str'),
        loggrp=dict(type='str'),
        authusergrp=dict(type='str'),
        traroutegrp=dict(type='str'),
        wafgrp=dict(type='str'),
        wadgrp=dict(type='str'),
        wvsgrp=dict(type='str'),
        mlgrp=dict(type='str'),
    )
    argument_spec.update(fwebos_argument_spec)

    required_if = [('name')]
    module = AnsibleModule(argument_spec=argument_spec,
                           required_if=required_if)
    action = module.params['action']
    result = {}
    connection = Connection(module._socket_path)
    param_pass, param_err = param_check(module, connection)

    if not param_pass:
        result['err_msg'] = param_err
        result['failed'] = True
    elif action == 'add':
        code, response = add_obj(module, connection)
        result['changed'] = True
        if 'results' in response.keys() and 'errcode' in response['results'].keys() and  response['results']['errcode'] == -5:
            result['changed'] = False
            del response["results"]['errcode']
        result['res'] = response
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
            result['changed'] = True
            if 'results' in response.keys() and 'errcode' in response['results'].keys() and  response['results']['errcode'] == -3:
                result['changed'] = False
                del response["results"]['errcode']
                del response["results"]['message']
            result['res'] = response
        else:
            res = False
    else:
        result['err_msg'] = 'error action: ' + action
        result['failed'] = True

    if 'errcode' in str(result):
        result['changed'] = False
        result['failed'] = True

    module.exit_json(**result)


if __name__ == '__main__':
    main()
