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
---
module: fwebos_json_generic
description:
  - FortiWeb All REST API Requests Sender/Receiver
version_added: "7.0.0"
authors:
  - Jie Li
  - Brad Zhang
requirements:
    - ansible>=2.11
options:
    vdom:
        description:
            - Specify the Virtual Domain(s) from which results are returned or changes are applied to. If this parameter is not provided, the management VDOM will be used. If the admin does not have access to the VDOM, a permission error will be returned. The URL parameter is one of: vdom=root (Single VDOM) vdom=vdom1,vdom2 (Multiple VDOMs) vdom=* (All VDOMs)
        type: array
"""

EXAMPLES = """
    - name: Test create server pool
      fwebos_json_generic:
       vdom: root
       json_generic:
        method: POST
        path: /api/v2.0/cmdb/server-policy/server-pool
        jsonbody: {
          comment: "999",
          hlck-sip: "3.3.3.0/24",
          hlck-sip6: "::/0",
          lb-algo: "round-robin",
          name: "sp3",
          server-balance: "disable",
          type: "reverse-proxy"
        }


    - name: Test get server pool
      fwebos_json_generic:
       vdom: root
       json_generic:
        method: GET
        path: /api/v2.0/cmdb/server-policy/server-pool?mkey=sp3
        jsonbody: {
        }


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
    # # response['sent'] = payload['data']
    # # response['url'] = url
    # response['method'] = method
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
    try:
        if is_vdom_enable(connection) and param_pass:
            connection.change_auth_for_vdom(module.params['vdom'])
    except Exception as e:
        error_msg = f"Checking VDOM failed. {e}"
        result['changed'] = False
        result['failed'] = True
        result['err_msg'] = error_msg   
        module.exit_json(**result)


    code, response = add_obj(module, connection)
    result['res'] = response
    result['changed'] = True

    if 'errcode' in str(result):
        result['changed'] = False

    module.exit_json(**result)


if __name__ == '__main__':
    main()
