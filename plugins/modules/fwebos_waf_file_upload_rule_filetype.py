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
module: fwebos_waf_file_upload_rule_filetype
description:
  - Configure FortiWeb devices via RESTful APIs
"""

EXAMPLES = """
"""

RETURN = """
"""

obj_url = '/api/v2.0/waf/filesecurity.filetypes'
get_obj_url = '/api/v2.0/cmdb/waf/file-upload-restriction-rule/file-types'
get_all_type = '/api/v2.0/waf/filesecurity.filetypes'


def get_all_filetype(connection):
    payload = {}
    code, response = connection.send_request(get_all_type, payload, 'GET')
    return response['results']


def find_type_value(all_filetype, data):

    for i in all_filetype:
        if i['group'] == data['group'] and i['file-type-name'] == data['file-type-name']:
            return i['file-type-value']

    return -1


def add_obj(module, connection):

    table_name = module.params['table_name']
    name = module.params['name']
    video_files = module.params['video_files']
    compressed_file = module.params['compressed_file']
    whole_suffixes_files = module.params['whole_suffixes_files']
    text_files = module.params['text_files']
    picture_files = module.params['picture_files']
    audio_files = module.params['audio_files']

    all_filetype = get_all_filetype(connection)

    data = []

    if video_files:
        for i in video_files:
            entry = {}
            entry['group'] = "Video Files"
            entry['file-type-name'] = i
            entry['file-type-value'] = find_type_value(all_filetype, entry)
            data.append(entry)

    if compressed_file:
        for i in compressed_file:
            entry = {}
            entry['group'] = "Compressed File"
            entry['file-type-name'] = i
            entry['file-type-value'] = find_type_value(all_filetype, entry)
            data.append(entry)

    if whole_suffixes_files:
        for i in whole_suffixes_files:
            entry = {}
            entry['group'] = "Whole Suffixes Files"
            entry['file-type-name'] = i
            entry['file-type-value'] = find_type_value(all_filetype, entry)
            data.append(entry)

    if text_files:
        for i in text_files:
            entry = {}
            entry['group'] = "Text Files"
            entry['file-type-name'] = i
            entry['file-type-value'] = find_type_value(all_filetype, entry)
            data.append(entry)

    if picture_files:
        for i in picture_files:
            entry = {}
            entry['group'] = "Picture Files"
            entry['file-type-name'] = i
            entry['file-type-value'] = find_type_value(all_filetype, entry)
            data.append(entry)

    if audio_files:
        for i in audio_files:
            entry = {}
            entry['group'] = "Audio Files"
            entry['file-type-name'] = i
            entry['file-type-value'] = find_type_value(all_filetype, entry)
            data.append(entry)

    payload = {
        'data': data,
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


def delete_all_obj(module, connection):
    table_name = module.params['table_name']
    payload = {}
    url = get_obj_url + '?mkey=' + table_name
    code, response = connection.send_request(url, payload, 'DELETE')

    return code, response


def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = ''

    if action == 'post' and module.params['table_name'] is None:
        err_msg = 'table_name need to set'
        res = False

    if (action != 'post' and action != 'get'):
        err_msg = 'action only support post and get, data is ' + action
        res = False

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        table_name=dict(type='str'),
        name=dict(type='str'),
        video_files=dict(type='list'),
        compressed_file=dict(type='list'),
        whole_suffixes_files=dict(type='list'),
        text_files=dict(type='list'),
        picture_files=dict(type='list'),
        audio_files=dict(type='list'),
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

    if is_vdom_enable(connection) and param_pass:
        connection.change_auth_for_vdom(module.params['vdom'])

    if not param_pass:
        result['err_msg'] = param_err
        result['failed'] = True
    elif action == 'post':
        code, response = delete_all_obj(module, connection)
        code, response, out = add_obj(module, connection)
        result['out'] = out
        result['res'] = response
        result['changed'] = True
    elif action == 'get':
        code, response = get_obj(module, connection)
        result['res'] = response
    else:
        result['err_msg'] = 'error action: ' + action

    if 'errcode' in str(result):
        result['changed'] = False
        result['failed'] = True
        result['err_msg'] = 'Please check error code'
        if result['res']['results']['errcode'] == -3 or result['res']['results']['errcode'] == -5:
            result['failed'] = False

    module.exit_json(**result)


if __name__ == '__main__':
    main()
