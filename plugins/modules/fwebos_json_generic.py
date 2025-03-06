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
import ast
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}


DOCUMENTATION = """
module: fwebos_content_routing_policy
description:
  - Configure FortiWeb devices via RESTful APIs
"""

EXAMPLES = """
"""

RETURN = """
"""

def param_check(module, connection):
    res = True
    err_msg = ''

    if is_vdom_enable(connection) and module.params['vdom'] is None:
        err_msg = 'vdom enable, vdom need to set'
        res = False

    return res, err_msg

def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)

def add_obj(module, connection):
    json = ast.literal_eval(module.params['json_generic'])
    code = 0
    payload = {}
    payload['data'] = json['jsonbody']
    url = json['path']
    method = json['method']
    code, response = connection.send_request(url, payload, method)    
    response['sent'] = payload['data']
    response['url'] = url
    response['method'] = method
    return code, response


def main():
    argument_spec = dict(
        json_generic=dict(type='str', required=True),
        vdom=dict(type='str'),
    )
    argument_spec.update(fwebos_argument_spec)

    required_if = [('json_generic')]
    module = AnsibleModule(argument_spec=argument_spec)
    result = {}
    connection = Connection(module._socket_path)
    param_pass, param_err = param_check(module, connection)
    if is_vdom_enable(connection) and param_pass:
        connection.change_auth_for_vdom(module.params['vdom'])


    code, response = add_obj(module, connection)
    result['res'] = response
    result['changed'] = True

    if 'errcode' in str(result):
        result['changed'] = False

    module.exit_json(**result)


if __name__ == '__main__':
    main()
