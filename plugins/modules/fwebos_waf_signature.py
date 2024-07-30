#!/usr/bin/python
#
# This file is part of Ansible
#
#
# updata date:2019/03/12

from __future__ import (absolute_import, division, print_function)
import json
from ansible_collections.fortinet.fortiweb.plugins.module_utils.network.fwebos.fwebos import (fwebos_argument_spec, is_global_admin, is_vdom_enable)
# from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fwebos.fwebos import get_err_msg
# from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fwebos.fwebos import list_to_str
# from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fwebos.fwebos import list_need_update
# from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fwebos.fwebos import is_vdom_enable
# from ansible_collections.fortinet.fortiadc.plugins.module_utils.network.fwebos.fwebos import is_user_in_vdom
from ansible.module_utils.connection import Connection
from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}


DOCUMENTATION = """
module: fwebos_waf_signature
description:
  - Configure FortiWeb devices via RESTful APIs
"""

EXAMPLES = """
"""

RETURN = """
"""

obj_url = '/api/v2.0/waf/signatures'
obj_delete_url = '/api/v2.0/cmdb/waf/signature'

main_class_list = [
    {
        "action": "alert_deny",
        "block-period": 600,
        "fpm-status": "disable",
        "id": "010000000",
        "main_class_id": "010000000",
        "name": "Cross Site Scripting",
        "severity": "High",
        "status": "enable",
        "trigger": ""
    },
    {
        "action": "alert",
        "block-period": 600,
        "fpm-status": "disable",
        "id": "020000000",
        "main_class_id": "020000000",
        "name": "Cross Site Scripting (Extended)",
        "severity": "Medium",
        "status": "disable",
        "trigger": ""
    },
    {
        "action": "alert_deny",
        "block-period": 600,
        "fpm-status": "enable",
        "id": "030000000",
        "main_class_id": "030000000",
        "name": "SQL Injection",
        "severity": "High",
        "status": "enable",
        "trigger": ""
    },
    {
        "action": "alert",
        "block-period": 600,
        "fpm-status": "disable",
        "id": "040000000",
        "main_class_id": "040000000",
        "name": "SQL Injection (Extended)",
        "severity": "Medium",
        "status": "disable",
        "trigger": ""
    },
    {
        "action": "alert_deny",
        "block-period": 600,
        "fpm-status": "disable",
        "id": "050000000",
        "main_class_id": "050000000",
        "name": "Generic Attacks",
        "severity": "High",
        "status": "enable",
        "trigger": ""
    },
    {
        "action": "alert",
        "block-period": 600,
        "fpm-status": "disable",
        "id": "060000000",
        "main_class_id": "060000000",
        "name": "Generic Attacks(Extended)",
        "severity": "Medium",
        "status": "disable",
        "trigger": ""
    },
    {
        "action": "alert_deny",
        "block-period": 600,
        "fpm-status": "disable",
        "id": "090000000",
        "main_class_id": "090000000",
        "name": "Known Exploits",
        "severity": "High",
        "status": "enable",
        "trigger": ""
    },
    {
        "action": "alert",
        "block-period": 600,
        "fpm-status": "disable",
        "id": "070000000",
        "main_class_id": "070000000",
        "name": "Trojans",
        "severity": "Medium",
        "status": "enable",
        "trigger": ""
    },
    {
        "action": "alert",
        "block-period": 600,
        "fpm-status": "disable",
        "id": "080000000",
        "main_class_id": "080000000",
        "name": "Information Disclosure",
        "severity": "Low",
        "status": "enable",
        "trigger": ""
    },
    {
        "action": "alert",
        "block-period": 600,
        "fpm-status": "disable",
        "id": "100000000",
        "main_class_id": "100000000",
        "name": "Personally Identifiable Information",
        "severity": "High",
        "status": "disable",
        "trigger": ""
    }
]


def add_obj(module, connection):
    name = module.params['name']
    customSignatureGroup = module.params['customSignatureGroup']
    comment = module.params['comment']
    creditCardDetectionThreshold = module.params['creditCardDetectionThreshold']

    payload = {
        'data':
        {
            'name': name,
            'customSignatureGroup': customSignatureGroup,
            'comment': comment,
            'creditCardDetectionThreshold': creditCardDetectionThreshold,
            'main_class_list': main_class_list,
        },
    }

    code, response = connection.send_request(obj_url, payload)

    return code, response, payload


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
    url = obj_delete_url + '?mkey=' + name
    code, response = connection.send_request(url, payload, 'DELETE')

    return code, response


def needs_update(module, data):
    res = False
    if module.params['customSignatureGroup'] and module.params['customSignatureGroup'] != data['customSignatureGroup']:
        data['customSignatureGroup'] = module.params['customSignatureGroup']
        res = True
    if module.params['comment'] and module.params['comment'] != data['comment']:
        data['comment'] = module.params['comment']
        res = True
    if module.params['creditCardDetectionThreshold'] and module.params['creditCardDetectionThreshold'] != data['creditCardDetectionThreshold']:
        data['creditCardDetectionThreshold'] = module.params['creditCardDetectionThreshold']
        res = True

    out_data = {}
    out_data['data'] = data
    return res, out_data


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
        name=dict(type='str'),
        customSignatureGroup=dict(type='str'),
        comment=dict(type='str'),
        creditCardDetectionThreshold=dict(type='str'),
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
    elif action == 'add':
        code, response, out = add_obj(module, connection)
        # result['out'] = json.dumps(out)
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
            code, response = edit_obj(module, new_data, connection)
            result['new_data'] = new_data
            result['res'] = response
            result['changed'] = True
    elif action == 'delete':
        code, data = get_obj(module, connection)
        if 'results' in data.keys() and data['results'] and type(data['results']) is not int:
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
        if result['res']['errcode'] == '-5':
            result['failed'] = False

    result['name'] = module.params['name']
    module.exit_json(**result)


if __name__ == '__main__':
    main()
