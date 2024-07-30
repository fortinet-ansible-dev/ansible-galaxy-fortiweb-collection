#!/usr/bin/python
#
# This file is part of Ansible
#
#
# updata date:2019/03/12

from __future__ import (absolute_import, division, print_function)
import json
from ansible_collections.fortinet.fortiweb.plugins.module_utils.network.fwebos.fwebos import (fwebos_argument_spec, is_global_admin)
from ansible.module_utils.connection import Connection
from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}


DOCUMENTATION = """
---
module: fwebos_backup_download
description:
  - Configure FortiWeb devices via RESTful APIs
"""

EXAMPLES = """
"""

RETURN = """
"""

obj_url = '/api/v2.0/system/maintenance.backupconfiguration'

rep_dict = {
}


def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)


def get_obj(module, connection):
    ml_backup = module.params['ml_backup']
    password = module.params['password']
    backup_type = module.params['type']

    url = obj_url + '?ml_backup='
    if ml_backup is not None:
        url = url + ml_backup

    url = url + '&password='
    if password is not None:
        url = url + password

    url = url + '&type=' + backup_type
    filename = connection.download_file(url, module.params['filename'])

    return filename


def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = ''

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        type=dict(type='str'),
        ml_backup=dict(type='str'),
        password=dict(type='str'),
        filename=dict(type='str'),
    )
    argument_spec.update(fwebos_argument_spec)

    required_if = [('type')]
    module = AnsibleModule(argument_spec=argument_spec,
                           required_if=required_if)
    action = module.params['action']
    result = {}
    connection = Connection(module._socket_path)
    param_pass, param_err = param_check(module, connection)
    if not param_pass:
        result['err_msg'] = param_err
        result['failed'] = True
    elif action == 'get':
        response = get_obj(module, connection)
        result['res'] = response
    else:
        result['err_msg'] = 'error action: ' + action
        result['failed'] = True

    if 'errcode' in str(result):
        result['changed'] = False
        result['failed'] = True

    module.exit_json(**result)


if __name__ == '__main__':
    main()
