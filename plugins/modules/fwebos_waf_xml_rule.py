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
module: fwebos_waf_xml_rule
description:
  - Configure FortiWeb devices via RESTful APIs
"""

EXAMPLES = """
"""

RETURN = """
"""

obj_url = '/api/v2.0/cmdb/waf/xml-validation.rule'

rep_dict = {
    'xml_limit_attrvalue_len': 'xml-limit-attrvalue-len',
    'soap_attachment': 'soap-attachment',
    'xml_limit_element_depth': 'xml-limit-element-depth',
    'xml_limit_element_name_len': 'xml-limit-element-name-len',
    'ws_i_basic_profile_wsdl_assertion': 'ws-i-basic-profile-wsdl-assertion',
    'validate_soapaction_val': 'validate-soapaction_val',
    'expansion_entity_check': 'expansion-entity-check',
    'schema_location_exempted_urls': 'schema-location-exempted-urls',
    'xml_limit_attrname_len': 'xml-limit-attrname-len',
    'wsdl_file': 'wsdl-file',
    'validate_soap_body': 'validate-soap-body',
    'x_include_check': 'x-include-check',
    'xml_limit_attr_num': 'xml-limit-attr-num',
    'data_format': 'data-format',
    'request_type': 'request-type',
    'ws_security': 'ws-security',
    'external_entity_check': 'external-entity-check',
    'allow_additional_soap_headers': 'allow-additional-soap-headers',
    'validate_soapaction': 'validate-soapaction',
    'schema_location_check': 'schema-location-check',
    'validate_soap_headers_val': 'validate-soap-headers_val',
    'block_period': 'block-period',
    'xml_limit_cdata_len': 'xml-limit-cdata-len',
    'host_status': 'host-status',
    'allow_additional_soap_headers_val': 'allow-additional-soap-headers_val',
    'request_file': 'request-file',
    'xml_limit_check': 'xml-limit-check',
    'validate_soap_headers': 'validate-soap-headers',
    'schema_file': 'schema-file',
    'xml_attributes_check': 'xml-attributes-check',
    'ws_i_basic_profile_assertion': 'ws-i-basic-profile-assertion',
    'xml_action': 'action',
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
        xml_limit_attrvalue_len=dict(type='int'),
        soap_attachment=dict(type='str'),
        xml_limit_element_depth=dict(type='int'),
        xml_limit_element_name_len=dict(type='int'),
        ws_i_basic_profile_wsdl_assertion=dict(type='str'),
        validate_soapaction_val=dict(type='str'),
        severity=dict(type='str'),
        expansion_entity_check=dict(type='str'),
        schema_location_exempted_urls=dict(type='str'),
        xml_limit_attrname_len=dict(type='int'),
        wsdl_file=dict(type='str'),
        trigger=dict(type='str'),
        validate_soap_body=dict(type='str'),
        x_include_check=dict(type='str'),
        xml_limit_attr_num=dict(type='int'),
        data_format=dict(type='str'),
        request_type=dict(type='str'),
        ws_security=dict(type='str'),
        external_entity_check=dict(type='str'),
        host=dict(type='str'),
        allow_additional_soap_headers=dict(type='str'),
        validate_soapaction=dict(type='str'),
        schema_location_check=dict(type='str'),
        validate_soap_headers_val=dict(type='str'),
        block_period=dict(type='int'),
        xml_limit_cdata_len=dict(type='int'),
        name=dict(type='str'),
        host_status=dict(type='str'),
        allow_additional_soap_headers_val=dict(type='str'),
        request_file=dict(type='str'),
        xml_limit_check=dict(type='str'),
        trigger_val=dict(type='str'),
        validate_soap_headers=dict(type='str'),
        schema_file=dict(type='str'),
        xml_action=dict(type='str'),
        xml_attributes_check=dict(type='str'),
        ws_i_basic_profile_assertion=dict(type='str'),
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
