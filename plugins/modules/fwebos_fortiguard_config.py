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
module: fwebos_fortiguard_config
description:
  - Configure FortiWeb devices via RESTful APIs
"""

EXAMPLES = """

"""

RETURN = """
"""

obj_url = '/api/v2.0/system/config.fortiguard'


rep_dict = {
}


def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)


def edit_obj(module, payload, connection):
    url = obj_url
    code, response = connection.send_request(url, payload['data'], 'PUT')
    return code, response


def get_obj(module, connection):
    payload = {}
    url = obj_url
    code, response = connection.send_request(url, payload, 'GET')

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

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        registration=dict(
            label=dict(type='str'),
            label_key=dict(type='str'),
            url=dict(type='str'),
            text=dict(type='str'),
            is_registered=dict(type='bool'),
        ),
        securityService=dict(
            expired=dict(type='str'),
            is_valid=dict(type='bool'),
            lastUpdateTime=dict(type='str'),
            lastUpdateMethod=dict(type='str'),
            update_url=dict(type='str'),
            update_text=dict(type='str'),
            buildNumber=dict(type='str'),
            label_key=dict(type='str'),
        ),
        antivirusService=dict(
            expired=dict(type='str'),
            is_valid=dict(type='bool'),
            lastUpdateTime=dict(type='str'),
            lastUpdateMethod=dict(type='str'),
            engineLastUpdateTime=dict(type='str'),
            engineLastUpdateMethod=dict(type='str'),
            anti_update_url=dict(type='str'),
            anti_update_text=dict(type='str'),
            regularVirusDatabaseVersion=dict(type='str'),
            exVirusDatabaseVersion=dict(type='str'),
            label_key=dict(type='str'),
            antivirusEnginVersion=dict(type='str'),
        ),
        reputationService=dict(
            expired=dict(type='str'),
            is_valid=dict(type='bool'),
            lastUpdateTime=dict(type='str'),
            lastUpdateMethod=dict(type='str'),
            reputation_update_url=dict(type='str'),
            reputation_update_text=dict(type='str'),
            reputationBuildNumber=dict(type='str'),
            label_key=dict(type='str'),
        ),
        credentialStuffingDefense=dict(
            expired=dict(type='str'),
            is_valid=dict(type='bool'),
            lastUpdateTime=dict(type='str'),
            lastUpdateMethod=dict(type='str'),
            databaseVersion=dict(type='str'),
            label_key=dict(type='str'),
        ),
        sbclService=dict(
            expired=dict(type='str'),
            is_valid=dict(type='bool'),
            lastUpdateTime=dict(type='str'),
            lastUpdateMethod=dict(type='str'),
            label_key=dict(type='str'),
            sandboxCloudVersion=dict(type='str'),
        ),
        geodbService=dict(
            expired=dict(type='str'),
            is_valid=dict(type='bool'),
            lastUpdateTime=dict(type='str'),
            lastUpdateMethod=dict(type='str'),
            label_key=dict(type='str'),
            geodbVersion=dict(type='str'),
        ),
        updateStatus=dict(type='str'),
        startedAt=dict(type='str'),
        updateDone=dict(type='bool'),
        stop=dict(type='bool'),
        override=dict(type='bool'),
        scheduled=dict(type='bool'),
        isUpdating=dict(type='bool'),
        updateControl=dict(type='list'),
        address=dict(type='str'),
        scheduleType=dict(type='str'),
        everySelect=dict(type='int'),
        dailySelect=dict(type='int'),
        weeklyDaySelect=dict(type='int'),
        weeklyHourSelect=dict(type='int'),
        dbVersionType=dict(type='int'),
        regularVersion=dict(type='str'),
        regularIncludedSignatures=dict(type='int'),
        regularIncludedGrayware=dict(type='int'),
        regularDescription=dict(type='str'),
        extendedVersion=dict(type='str'),
        extendedIncludedSignatures=dict(type='int'),
        extendedIncludedGrayware=dict(type='int'),
        extendedDescription=dict(type='str'),
        bufferSize=dict(type='int'),
        bufferSizeMax=dict(type='int'),
        useFSD=dict(type='int'),
        useFSDVersion=dict(type='str'),
        useFSDDescription=dict(type='str'),
        _id=dict(type='str'),
    )
    argument_spec.update(fwebos_argument_spec)

    module = AnsibleModule(argument_spec=argument_spec)
    action = module.params['action']
    result = {}
    connection = Connection(module._socket_path)
    param_pass, param_err = param_check(module, connection)

    if not param_pass:
        result['err_msg'] = param_err
        result['failed'] = True
    elif action == 'get':
        code, response = get_obj(module, connection)
        result['res'] = response
    elif action == 'edit':
        code, data = get_obj(module, connection)
        if 'results' in data.keys() and data['results'] and type(data['results']) is not int:
            res, new_data = needs_update(module, data['results'])
        else:
            result['failed'] = True
            res = False
            result['err_msg'] = 'Entry not found'
        if res:
            new_data1 = {}
            new_data1['data'] = new_data
            code, response = edit_obj(module, new_data1, connection)
            result['res'] = response
            result['changed'] = True
    else:
        result['err_msg'] = 'error action: ' + action
        result['failed'] = True

    if 'errcode' in str(result):
        result['changed'] = False
        result['failed'] = True

    # if 'res' in result.keys() and type(result['res']) is dict\
    #        and type(result['res']['results']) is int and result['res']['results'] < 0:
        # result['err_msg'] = get_err_msg(connection, result['res']['payload'])
    #    result['changed'] = False
    #    result['failed'] = True
    if 'errcode' in str(result):
        result['changed'] = False
        result['failed'] = True

    module.exit_json(**result)


if __name__ == '__main__':
    main()
