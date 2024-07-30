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
module: fwebos_waf_url_access_rule_condition
description:
  - Configure FortiWeb devices via RESTful APIs
"""

EXAMPLES = """
"""

RETURN = """
"""

obj_url = '/api/v2.0/cmdb/waf/url-access.url-access-rule/match-condition'


def add_obj(module, connection):

    table_name = module.params['table_name']
    name = module.params['name']
    url_type = module.params['url_type']
    reg_exp = module.params['reg_exp']
    reverse_match = module.params['reverse_match']
    sip_address_check = module.params['sip_address_check']
    sip_address_type = module.params['sip_address_type']
    sip_address_value = module.params['sip_address_value']
    sdomain_type = module.params['sdomain_type']
    sip_address_domain = module.params['sip_address_domain']
    source_domain_type = module.params['source_domain_type']
    source_domain = module.params['source_domain']

    payload = {
        'data':
        {
            'type': url_type,
            'reg-exp': reg_exp,
            'reverse-match': reverse_match,
            'sip-address-check': sip_address_check,
            'sip-address-type': sip_address_type,
            'sip-address-value': sip_address_value,
            'sdomain-type': sdomain_type,
            'sip-address-domain': sip_address_domain,
            'source-domain-type': source_domain_type,
            'source-domain': source_domain,
        },
    }

    url = obj_url + '?mkey=' + table_name

    code, response = connection.send_request(url, payload)

    return code, response, payload


def edit_obj(module, payload, connection):
    table_name = module.params['table_name']
    name = module.params['name']
    url = obj_url + '?mkey=' + table_name + '&sub_mkey=' + name
    code, response = connection.send_request(url, payload, 'PUT')

    return code, response


def get_obj(module, connection):
    table_name = module.params['table_name']
    name = module.params['name']
    payload = {}
    url = obj_url + '?mkey=' + table_name
    if name:
        url += '&sub_mkey=' + name
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_obj(module, connection):
    table_name = module.params['table_name']
    name = module.params['name']
    payload = {}
    url = obj_url + '?mkey=' + table_name + '&sub_mkey=' + name
    code, response = connection.send_request(url, payload, 'DELETE')

    return code, response


def needs_update(module, data):
    res = False

    if module.params['url_type'] and module.params['url_type'] != data['type']:
        data['type'] = module.params['url_type']
        res = True
    if module.params['reg_exp'] and module.params['reg_exp'] != data['reg-exp']:
        data['reg-exp'] = module.params['reg_exp']
        res = True
    if module.params['reverse_match'] and module.params['reverse_match'] != data['reverse-match']:
        data['reverse-match'] = module.params['reverse_match']
        res = True
    if module.params['sip_address_check'] and module.params['sip_address_check'] != data['sip-address-check']:
        data['sip-address-check'] = module.params['sip_address_check']
        res = True
    if module.params['sip_address_type'] and module.params['sip_address_type'] != data['sip-address-type']:
        data['sip-address-type'] = module.params['sip_address_type']
        res = True
    if module.params['sip_address_value'] and module.params['sip_address_value'] != data['sip-address-value']:
        data['sip-address-value'] = module.params['sip_address_value']
        res = True
    if module.params['sdomain_type'] and module.params['sdomain_type'] != data['sdomain-type']:
        data['sdomain-type'] = module.params['sdomain_type']
        res = True
    if module.params['sip_address_domain'] and module.params['sip_address_domain'] != data['sip-address-domain']:
        data['sip-address-domain'] = module.params['sip_address_domain']
        res = True
    if module.params['source_domain_type'] and module.params['source_domain_type'] != data['source-domain-type']:
        data['source-domain-type'] = module.params['source_domain_type']
        res = True
    if module.params['source_domain_type'] and module.params['source_domain_type'] != data['source-domain-type']:
        data['source-domain-type'] = module.params['source_domain_type']
        res = True
    if module.params['source_domain'] and module.params['source_domain'] != data['source-domain']:
        data['source-domain'] = module.params['source_domain']
        res = True

    out_data = {}
    out_data['data'] = data
    return res, out_data


def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = ''

    if (action == 'add' or action == 'edit' or action == 'delete') and module.params['table_name'] is None:
        err_msg = 'table_name need to set'
        res = False
    if (action == 'add' or action == 'edit'):
        if module.params['reg_exp'] is None:
            err_msg = 'reg-exp is url pattrern need to set'
            res = False
        if module.params['sip_address_check'] == 'enable' and (module.params['sip_address_type'] is None):
            err_msg = 'sip_address_type(sip/sdomain/source-domin) need to set when sip-address-check is enable'
            res = False
        if module.params['sip_address_type'] == 'sip' and (module.params['sip_address_value'] is None):
            err_msg = 'sip-address-value need to set the ip range when sip_address_type is sip'
            res = False
        if module.params['sip_address_type'] == 'sdomain' and (module.params['sdomain_type'] is None or module.params['sip_address_domain'] is None):
            err_msg = 'sdomain_type(ipv4/ipv6) and sip-address-domain need to set the ip range when sip_address_type is sdomain'
            res = False
        if module.params['sip_address_type'] == 'source-domin' and (module.params['source_domain_type'] is None or module.params['source_domain'] is None):
            err_msg = 'sdomain_type(source-domain/regex-expression) and source-domain need to set the ip range when sip_address_type is source-domin'
            res = False

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        table_name=dict(type='str'),
        name=dict(type='str'),
        url_type=dict(type='str'),
        reg_exp=dict(type='str'),
        reverse_match=dict(type='str'),
        sip_address_check=dict(type='str', default='disable'),
        sip_address_type=dict(type='str'),
        sip_address_value=dict(type='str'),
        sdomain_type=dict(type='str'),
        sip_address_domain=dict(type='str'),
        source_domain_type=dict(type='str'),
        source_domain=dict(type='str'),
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
        code, response, out_data = add_obj(module, connection)
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
                result['new'] = new_data
                code, response = edit_obj(module, new_data, connection)
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
        if result['res']['results']['errcode'] == -3 or result['res']['results']['errcode'] == -5:
            result['failed'] = False        

    module.exit_json(**result)


if __name__ == '__main__':
    main()
