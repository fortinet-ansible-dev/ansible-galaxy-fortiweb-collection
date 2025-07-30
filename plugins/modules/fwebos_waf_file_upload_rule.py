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
module: fwebos_waf_file_upload_rule
description:
  - Config FortiWeb Input Validation File Security Rule
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
    host-status:
        description:
            - enable/disable
        type: string
        choices:
            - 'enable'
            - 'disable'
    host:
        description:
            - host
        type: string
    request-type:
        description:
            - simple string or regular expression
        type: string
        choices:
            - 'plain'
            - 'regular'
    request-file:
        description:
            - URL
        type: string
    type:
        description:
            - Allow/Block file types
        type: string
        choices:
            - 'Allow'
            - 'Block'
    file-uncompress:
        description:
            - enable/disable
        type: string
        choices:
            - 'enable'
            - 'disable'
    uncompress-nest-limit:
        description:
            - maximum uncompress nest level that can be checked(1-100) (range: 1-100)
        type: integer
    json-file-support:
        description:
            - enable/disable
        type: string
        choices:
            - 'enable'
            - 'disable'
    json-key-for-filename:
        description:
            - enable/disable
        type: string
    json-key-field:
        description:
            - enable/disable
        type: string
    enable_base64_decode:
        description:
            - enable/disable
        type: string
        choices:
            - 'enable'
            - 'disable'
    octet-stream-filename-headers:
        description:
            - Specify HTTP headers to get the file name of octet-stream.e.g.X-Filename;X-Name
        type: string
"""

EXAMPLES = """
     - name: delete
       fwebos_waf_file_upload_rule:
        action: delete
        name: 123
        vdom: root

     - name: Create
       fwebos_waf_file_upload_rule:
        action: add
        json_key_for_filename: key
        name: test4
        host_status: enable
        request_type: regular
        json_key_field: key
        request_file: test
        host: 192.168.1.1
        octet_stream_filename_headers: filename
        file_size_limit: 0
        type: Allow
        json_file_support: enable
        vdom: root

     - name: edit
       fwebos_waf_file_upload_rule:
        action: edit
        json_key_for_filename: key
        name: test4
        host_status: enable
        request_type: regular
        json_key_field: key
        request_file: test
        host: 192.168.1.2
        octet_stream_filename_headers: filename
        file_size_limit: 0
        type: Allow
        json_file_support: enable
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

obj_url = '/api/v2.0/cmdb/waf/file-upload-restriction-rule'


rep_dict = {
    'json_key_for_filename': 'json-key-for-filename',
    'host_status': 'host-status',
    'request_type': 'request-type',
    'json_key_field': 'json-key-field',
    'request_file': 'request-file',
    'octet_stream_filename_headers': 'octet-stream-filename-headers',
    'file_size_limit': 'file-size-limit',
    'json_file_support': 'json-file-support',
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
        json_key_for_filename=dict(type='str'),
        name=dict(type='str'),
        host_status=dict(type='str'),
        request_type=dict(type='str'),
        json_key_field=dict(type='str'),
        request_file=dict(type='str'),
        host=dict(type='str'),
        octet_stream_filename_headers=dict(type='str'),
        file_size_limit=dict(type='int'),
        type=dict(type='str'),
        json_file_support=dict(type='str'),
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
                new_data1 = {}
                new_data1['data'] = new_data
                code, response = edit_obj(module, new_data1, connection)
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
        result['err_msg'] = 'Please check error code'
        if result['res']['results']['errcode'] == -3 or result['res']['results']['errcode'] == -5:
            result['failed'] = False

    module.exit_json(**result)


if __name__ == '__main__':
    main()
