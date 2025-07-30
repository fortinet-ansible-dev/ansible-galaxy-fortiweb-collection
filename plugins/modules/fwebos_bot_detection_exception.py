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
module: fwebos_bot_detection_exception
description:
  - Config FortiWeb Bot Detection Policy Exceptions
version_added: "7.0.0"
authors:
  - Joseph Chen
requirements:
    - ansible>=2.11
options:
    id:
        description:
            - The numerical ID of Limit Sample Collections From IPs.
        type: string
    policy_id:
        description:
            - The numerical ID of Server Policy.
        type: string
    host_status:
        description:
            - Host Status.
        type: string
        choices:
            - 'enable'
            - 'disable'
    url_type:
        description:
            - Sample Count.
        type: string
        choices:
            - 'regular'
            - 'plain'
    url_pattern:
        description:
            - URL Pattern.
        type: string
"""

EXAMPLES = """
    - name: add a bot detection policy exception
      fwebos_bot_detection_exception:
        action: add
        policy_id: 2
        host_status: enable
        url_type: plain
        host: a_host
        url_pattern: /url_1/url_2/

    - name: edit a bot detection policy exception
      fwebos_bot_detection_exception:
        action: edit
        policy_id: 2
        id: 1
        host_status: enable
        url_type: regular
        host: a_host_1
        url_pattern: /url_1/url_2/abc/

    - name: get a bot detection policy exception
      fwebos_bot_detection_exception:
        action: get
        policy_id: 2
        id: 1

    - name: delete a bot detection policy exception
      fwebos_bot_detection_exception:
        action: delete
        policy_id: 2
        id: 1

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

obj_url = '/api/v2.0/cmdb/waf/bot-detection-policy/bot-detection-exception-list'


rep_dict = {
    "host_status": "host-status",
    "url_type": "url-type",
    "url_pattern": "url-pattern"
}


def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)

def add_obj(module, connection):
    policy_id = module.params['policy_id']
    url = obj_url + '?mkey=' + policy_id
    payload1 = {}
    payload1['data'] = module.params
    payload1['data'].pop('action')
    replace_key(payload1['data'], rep_dict)

    code, response = connection.send_request(url, payload1)
    # response['sent'] = payload1['data']

    return code, response, payload1['data']

def edit_obj(module, connection):
    policy_id = module.params['policy_id']
    url = obj_url + '?mkey=' + policy_id
    if 'id' in module.params and module.params['id'] is not None:
        url += '&sub_mkey=' + module.params['id']
    payload1 = {}
    payload1['data'] = module.params
    payload1['data'].pop('action')
    replace_key(payload1['data'], rep_dict)

    code, response = connection.send_request(url, payload1, 'PUT')

    # response['sent'] = payload1['data']
    # response['url'] = url
    return code, response, payload1['data']


def get_obj(module, connection):
    payload = {}
    policy_id = module.params['policy_id']
    url = obj_url + '?mkey=' + policy_id
    if 'id' in module.params and module.params['id'] is not None:
        url += '&sub_mkey=' + module.params['id']
    code, response = connection.send_request(url, payload, 'GET')
    return code, response

def delete_obj(module, connection):
    policy_id = module.params['policy_id']
    url = obj_url + '?mkey=' + policy_id
    if 'id' in module.params and module.params['id'] is not None:
        url += '&sub_mkey=' + module.params['id']
    payload = {}
    code, response = connection.send_request(url, payload, 'DELETE')
    return code, response

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

def combine_dict(src_dict, dst_dict):
    changed = False
    for key in dst_dict:
        if key in src_dict and src_dict[key] is not None and dst_dict[key] != src_dict[key]:
            dst_dict[key] = src_dict[key]
            changed = True

    return changed

def needs_update(module, data):
    payload1 = {}
    payload1['data'] = module.params
    replace_key(payload1['data'], rep_dict)
    payload1['data'].pop('action')

    res = combine_dict(payload1['data'], data)
    return res, data

def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = ''

    if (action == 'add' or action == 'edit' or action == 'delete') and module.params['policy_id'] is None:
        err_msg = '\'policy_id\' cannot be empty.'
        res = False
    if (action == 'edit' or action == 'delete') and module.params['id'] is None:
        err_msg = '\'id\' cannot be empty for action \'edit\' and \'delete\'.'
        res = False    

    res, err_msg = value_check(module.params, 'host_status', ['enable', 'disable'])
    if res == False:
        return res, err_msg
    res, err_msg = value_check(module.params, 'url_type', ['regular', 'plain'])
    if res == False:
        return res, err_msg

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        vdom=dict(type='str'),
        host_status=dict(type='str'),
        url_type=dict(type='str'),
        host=dict(type='str'),
        url_pattern=dict(type='str'),
        policy_id=dict(type='str'),
        id=dict(type='str')
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
        code, response, out_data = add_obj(module, connection)
        result['res'] = response
        result['changed'] = True
    elif action == 'get':
        code, response = get_obj(module, connection)
        result['res'] = response
    elif action == 'edit':
        code, response, out_data = edit_obj(module, connection)
        result['res'] = response
        result['changed'] = True
    elif action == 'delete':
        code, data = get_obj(module, connection)
        if 'results' in data.keys() and data['results'] and type(data['results']) is not int and 'The entry is not found' not in str(data['results']):
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
        if result['res']['results']['errcode'] == -3 or result['res']['results']['errcode'] == -5:
            result['failed'] = False

    module.exit_json(**result)


if __name__ == '__main__':
    main()

            