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
module: fwebos_waf_json_schema
description:
  - Config FortiWeb JSON Schema
version_added: "7.0.0"
authors:
  - Joseph Chen
requirements:
    - ansible>=2.11
options:
    name:
        description:
            - The name of JSON schema.
        type: string
    jsonfile:
        description:
            - The name of upload file.
        type: string
    json_schema_version:
        description:
            - Enable or disable Advanced Mode.
        type: string
        choices:
            - 'auto-identify'
            - 'draft-3'
            - 'draft-4'
            - 'draft-6'
            - 'draft-7'
            - 'draft-201909'
            - 'draft-202012'
"""

EXAMPLES = """
    - name: add a json protection schema
      fwebos_waf_json_schema:
        action: add
        name: json_schema
        json_schema_version: auto-identify
        jsonfile: json_scheme1.txt

    - name: add a json protection schema with same name again
      fwebos_waf_json_schema:
        action: add
        name: json_schema
        json_schema_version: auto-identify
        jsonfile: json_scheme1.txt

    - name: get a json protection schema
      fwebos_waf_json_schema:
        action: get
        name: json_schema

    - name: delete a json protection schema
      fwebos_waf_json_schema:
        action: delete
        name: json_schema


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

obj_url = '/api/v2.0/cmdb/waf/json-schema.file'
post_url = '/api/v2.0/waf/jsonprotection.jsonschemafile'

rep_dict = {
    "json_schema_version":"json-schema-version"
}


def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)

def add_obj(module, connection):
    payload1 = {}
    payload1['data'] = module.params

    data1 = {
        'json-schema-version': payload1['data']['json_schema_version'],
        'name': payload1['data']['name'],
        'jsonfile': {
            'filename': payload1['data']['jsonfile'],
        },
    }
    content_type, b_data = prepare_multipart(data1)

    headers = {
        'Content-type': content_type,
    }
    code, response = connection.send_url_request(post_url, b_data.decode('ascii'), headers=headers)
    return code, response

def delete_obj(module, connection):
    name = module.params['name']
    payload = {}
    url = obj_url + '?mkey=' + name
    code, response = connection.send_request(url, payload, 'DELETE')

    return code, response



def get_obj(module, connection):
    payload = {}
    url = obj_url
    if 'name' in module.params and module.params['name'] is not None:
        url = obj_url + '?mkey=' + module.params['name']
    code, response = connection.send_request(url, payload, 'GET')

    # raise Exception(response)
    return code, response


def combine_dict(src_dict, dst_dict):
    changed = False
    for key in dst_dict:
        if key in src_dict and src_dict[key] is not None and dst_dict[key] != src_dict[key]:
            dst_dict[key] = src_dict[key]
            changed = True

    return changed



def value_check(params, key_name, good_values):
    msg = ''
    res = True
    if params[key_name] is not None:
        value_is_good = False
        for v in good_values:
            if params[key_name]==v:
                value_is_good = True
                return res, msg
        if value_is_good == False:
            # generate error message.
            res = False
            msg = 'The value of \''+ key_name + '\' should be'
            if len(good_values) == 1:
                msg+= f" '{good_values[0]}'."
            else:
                quoted_good_values = [f"'{val}'" for val in good_values]
                msg+= f" {', '.join(quoted_good_values[:-1])}, or {quoted_good_values[-1]}."

    return res, msg

def param_check(module, connection):
    res = True
    action = module.params['action']
    if (action == 'add' or action == 'delete') and module.params['name'] is None:
        err_msg = 'name need to set'
        res = False
    err_msg = ''
    res, err_msg = value_check(module.params, 'json_schema_version', ['auto-identify', 'draft-3', 'draft-4', 'draft-6', 'draft-7', 'draft-201909', 'draft-202012'])
    if res == False:
        return res, err_msg

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
        vdom=dict(type='str'),
        json_schema_version=dict(type='str'),
        jsonfile=dict(type='str')
    )
    argument_spec.update(fwebos_argument_spec)

    module = AnsibleModule(argument_spec=argument_spec)
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

    module.exit_json(**result)


if __name__ == '__main__':
    main()
