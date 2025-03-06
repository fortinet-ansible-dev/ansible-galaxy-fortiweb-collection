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
module: fwebos_content_routing_policy
description:
  - Configure FortiWeb devices via RESTful APIs
"""

EXAMPLES = """
"""

RETURN = """
"""

obj_url = '/api/v2.0/server/httpcontentrouting.matchlist'
list_url = '/api/v2.0/cmdb/server-policy/http-content-routing-policy/content-routing-match-list'



rep_dict = {
    'server_pool': 'server-pool',
    'match_object': 'match-object',
    'match_condition': 'match-condition',
    'match_condition_val': 'match-condition_val',
    'x509_subject_name': 'x509-subject-name',
    'x509_subject_name_val': 'x509-subject-name_val',
    'match_expression': 'match-expression',
    'ztna_ems_tag': 'ztna-ems-tag', 
    'ztna_ems_tag_combine': 'ztna-ems-tag-combine',
    'ztna_ems_tag_combine_val': 'ztna-ems-tag-combine_val',
    'parameter_name_match_condition': 'name-match-condition',
    'parameter_value_match_condition': 'value-match-condition:',
    'parameter_name_match_condition_val': 'name',
    'parameter_value_match_condition_val': 'value',
    'name_match_condition_val': 'name-match-condition_val',
    'value_match_condition_val': 'value-match-condition_val',
    'country_list': 'country-list',
    'ip_list':'ip-list',
    'ip_list_file': 'ip-list-file',
    'ip_range':'ip-range',

}

def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)

def add_obj(module, connection):
    payload1 = {}
    payload1['data'] = module.params
    name = module.params['policy_name']
    payload1['data'].pop('action')
    replace_key(payload1['data'], rep_dict)
    # payload1['data']['country-list'] =["Angola", "Brazil"] #Thi is an example of accepted input
    url = obj_url + '?mkey=' + name 
    code, response = connection.send_request(url, payload1)    
    response['sent'] = payload1['data']
    return code, response


def edit_obj(module, payload, connection):
    name = module.params['policy_name']
    id = module.params['id']
    url = obj_url + '?mkey=' + name + '&sub_mkey=' + id
    payload1 = {}
    # payload.pop('name')
    payload1['data'] = payload
    code, response = connection.send_request(url, payload1, 'POST')
    response['url'] = url
    return code, response


def get_obj(module, connection):
    name = module.params['policy_name']
    id = module.params['id']
    payload = {}
    url = list_url
    if name:
        url += '?mkey=' + name
    if id:
        url += '&sub_mkey=' + id
    code, response = connection.send_request(url, payload, 'GET')
    # response['url'] = url
    return code, response


def delete_obj(module, connection):
    name = module.params['policy_name']
    id = module.params['id']
    payload = {}
    url = list_url + '?mkey=' + name + '&sub_mkey=' + id
    code, response = connection.send_request(url, payload, 'DELETE')
    response['url'] = url
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
    # payload1['data'].pop('name')
    replace_key(payload1['data'], rep_dict)  

    res = combine_dict(payload1['data'], data)

    return res, data


def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = ''

    if (action == 'add' or action == 'edit' or action == 'delete') and module.params['policy_name'] is None:
        err_msg = 'policy_name need to set'
        res = False
    if (action == 'edit' or action == 'delete') and module.params['id'] is None:
        err_msg = 'policy_name need to set for \'edit\' and \'delete\' actions'
        res = False
    if is_vdom_enable(connection) and module.params['vdom'] is None:
        err_msg = 'vdom enable, vdom need to set'
        res = False
        
    if action == 'add' and module.params['match_object'] is None:
        err_msg = '\'match_object\' needs to set for creating new matching objects'
        res = False

    if module.params['match_object'] == 'http-host' or module.params['match_object'] == 'http-request' or module.params['match_object'] =='source-ip' or module.params['match_object'] =='https-sni' or module.params['match_object'] =='source-ip' =='http-referer':
        if module.params['match_condition'] is None or module.params['match_expression'] is None:
            err_msg = '\'match_condition\' and \'match_expression\' needs to set when \'match_object\' is '+ module.params['match_object']
            res = False

    if module.params['match_object'] == 'url-parameter':
        if module.params['parameter_name_match_condition'] is None or module.params['parameter_value_match_condition'] is None or module.params['parameter_name_match_condition_val'] is None or module.params['parameter_value_match_condition_val'] is None:
            err_msg = '\'parameter_name_match_condition\', \'parameter_value_match_condition\', \'parameter_name_match_condition_val\', and \'parameter_value_match_condition_val\' needs to set when \'match_object\' is '+ module.params['match_object']
            res = False


    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        policy_name=dict(type='str', required=True),
        id=dict(type='str'),
        match_object=dict(type='str'),
        match_object_val=dict(type='str', default='1'),
        match_condition=dict(type='str'),
        match_condition_val=dict(type='str', default='1'),
        parameter_name_match_condition=dict(type='str'),
        parameter_value_match_condition=dict(type='str'),
        parameter_name_match_condition_val=dict(type='str'),
        parameter_value_match_condition_val=dict(type='str'),
        name_match_condition_val=dict(type='str', default='1'),
        value_match_condition_val=dict(type='str', default='1'),
        x509_subject_name=dict(type='str', default='E'),
        x509_subject_name_val=dict(type='str', default='1'),
        match_expression=dict(type='str'),
        value=dict(type='str'),
        concatenate=dict(type='str'),
        concatenate_val=dict(type='str', default='2'),
        start_ip=dict(type='str'),
        end_ip=dict(type='str'),
        reverse=dict(type='str'),
        reverse_val=dict(type='str', default='0'),
        country_list=dict(type='list'),
        ip_list=dict(type='str'),
        ip_range=dict(type='str'),
        ip_list_file=dict(type='str'),
        ztna_ems_tag=dict(type='str'),
        ztna_ems_tag_combine=dict(type='str', default='or'),
        ztna_ems_tag_combine_val=dict(type='str', default='3'),
        vdom=dict(type='str'),
    )
    argument_spec.update(fwebos_argument_spec)

    required_if = [('policy_name')]
    module = AnsibleModule(argument_spec=argument_spec)
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
        code, response = add_obj(module, connection)
        result['res'] = response
        result['changed'] = True
    elif action == 'get':
        code, response = get_obj(module, connection)
        result['res'] = response
    elif action == 'edit':
        code, data = get_obj(module, connection)
        if 'errcode' in str(data):
            result['err_msg'] = 'Entry not found'
        else:
            res, new_data = needs_update(module, data['results'])
            if res:
                code, response = edit_obj(module, new_data, connection)
                result['new_data'] = new_data
                result['old_data'] = data['results']
                result['res'] = response
                result['changed'] = True
    elif action == 'delete':
        code, data = get_obj(module, connection)
        if 'errcode' in str(data):
            result['err_msg'] = 'Entry not found'
        else:
            code, response = delete_obj(module, connection)
            result['res'] = response
            result['changed'] = True
    else:
        result['err_msg'] = 'error action: ' + action
        result['failed'] = True

    if 'errcode' in str(result):
        result['changed'] = False
        result['err_msg'] = 'Please check error code'
        result['failed'] = False

    result['policy_name'] = module.params['policy_name']
    module.exit_json(**result)


if __name__ == '__main__':
    main()
