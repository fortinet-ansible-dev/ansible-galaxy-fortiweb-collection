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
module: fwebos_waf_http_constraints_exceptions_list
description:
  - Configure FortiWeb devices via RESTful APIs
"""

EXAMPLES = """
"""

RETURN = """
"""

obj_url = '/api/v2.0/cmdb/waf/http-constraints-exceptions/http_constraints-exception-list'

rep_dict = {
    'max_http_body_parameter_length_val': 'max-http-body-parameter-length_val',
    'url_param_name_check': 'url-param-name-check',
    'number_of_ranges_in_range_header_val': 'number-of-ranges-in-range-header_val',
    'Post_request_ctype_check': 'Post-request-ctype-check',
    'Illegal_host_name_check': 'Illegal-host-name-check',
    'max_http_content_length': 'max-http-content-length',
    'max_http_body_length_val': 'max-http-body-length_val',
    'web_socket_protocol_check_val': 'web-socket-protocol-check_val',
    'Illegal_host_name_check_val': 'Illegal-host-name-check_val',
    'Illegal_http_request_method_check': 'Illegal-http-request-method-check',
    'source_ip_status': 'source-ip-status',
    'http2_max_requests': 'http2-max-requests',
    'max_http_body_parameter_length': 'max-http-body-parameter-length',
    'max_url_parameter_val': 'max-url-parameter_val',
    'block_malformed_request_val': 'block-malformed-request_val',
    'max_http_request_length': 'max-http-request-length',
    'number_of_ranges_in_range_header': 'number-of-ranges-in-range-header',
    'redundant_header_check': 'redundant-header-check',
    'max_url_parameter_length_val': 'max-url-parameter-length_val',
    'Illegal_content_type_check_val': 'Illegal-content-type-check_val',
    'max_url_param_name_len_val': 'max-url-param-name-len_val',
    'Illegal_content_length_check': 'Illegal-content-length-check',
    'max_http_header_length': 'max-http-header-length',
    'Illegal_byte_in_url_check_val': 'Illegal-byte-in-url-check_val',
    'Internal_resource_limits_check_val': 'Internal-resource-limits-check_val',
    'source_ip': 'source-ip',
    'max_http_request_length_val': 'max-http-request-length_val',
    'url_param_name_check_val': 'url-param-name-check_val',
    'rpc_protocol_check': 'rpc-protocol-check',
    'duplicate_paramname_check_val': 'duplicate-paramname-check_val',
    'max_http_body_length': 'max-http-body-length',
    'web_socket_protocol_check': 'web-socket-protocol-check',
    'parameter_name_check': 'parameter-name-check',
    'max_url_parameter_length': 'max-url-parameter-length',
    'Illegal_header_name_check': 'Illegal-header-name-check',
    'url_param_value_check': 'url-param-value-check',
    'duplicate_paramname_check': 'duplicate-paramname-check',
    'parameter_name_check_val': 'parameter-name-check_val',
    'source_ip_status_val': 'source-ip-status_val',
    'http2_max_requests_val': 'http2-max-requests_val',
    'Illegal_content_length_check_val': 'Illegal-content-length-check_val',
    'request_type': 'request-type',
    'max_url_param_name_len': 'max-url-param-name-len',
    'max_url_param_value_len_val': 'max-url-param-value-len_val',
    'max_header_line_request_val': 'max-header-line-request_val',
    'odd_and_even_space_attack_check_val': 'odd-and-even-space-attack-check_val',
    'parameter_value_check_val': 'parameter-value-check_val',
    'max_http_header_value_length': 'max-http-header-value-length',
    'max_url_parameter': 'max-url-parameter',
    'max_http_header_name_length': 'max-http-header-name-length',
    'odd_and_even_space_attack_check': 'odd-and-even-space-attack-check',
    'max_http_content_length_val': 'max-http-content-length_val',
    'request_type_val': 'request-type_val',
    'Illegal_http_request_method_check_val': 'Illegal-http-request-method-check_val',
    'max_cookie_in_request_val': 'max-cookie-in-request_val',
    'rpc_protocol_check_val': 'rpc-protocol-check_val',
    'Illegal_header_value_check': 'Illegal-header-value-check',
    'parameter_value_check': 'parameter-value-check',
    'max_header_line_request': 'max-header-line-request',
    'max_http_header_value_length_val': 'max-http-header-value-length_val',
    'null_byte_in_url_check': 'null-byte-in-url-check',
    'host_status': 'host-status',
    'max_http_header_length_val': 'max-http-header-length_val',
    'null_byte_in_url_check_val': 'null-byte-in-url-check_val',
    'block_malformed_request': 'block-malformed-request',
    'Internal_resource_limits_check': 'Internal-resource-limits-check',
    'request_file': 'request-file',
    'redundant_header_check_val': 'redundant-header-check_val',
    'Illegal_header_name_check_val': 'Illegal-header-name-check_val',
    'url_param_value_check_val': 'url-param-value-check_val',
    'max_http_header_name_length_val': 'max-http-header-name-length_val',
    'Post_request_ctype_check_val': 'Post-request-ctype-check_val',
    'host_status_val': 'host-status_val',
    'max_http_request_filename_length': 'max-http-request-filename-length',
    'Illegal_header_value_check_val': 'Illegal-header-value-check_val',
    'max_url_param_value_len': 'max-url-param-value-len',
    'max_http_request_filename_length_val': 'max-http-request-filename-length_val',
    'Illegal_content_type_check': 'Illegal-content-type-check',
    'max_cookie_in_request': 'max-cookie-in-request',
    'Illegal_byte_in_url_check': 'Illegal-byte-in-url-check',
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

    table_name = module.params['table_name']
    url = obj_url + '?mkey=' + table_name

    code, response = connection.send_request(url, payload1)

    return code, response


def edit_obj(module, payload, connection):
    name = module.params['name']
    table_name = module.params['table_name']
    url = obj_url + '?mkey=' + table_name + '&sub_mkey=' + name
    code, response = connection.send_request(url, payload, 'PUT')

    return code, response


def get_obj(module, connection):
    name = module.params['name']
    table_name = module.params['table_name']
    payload = {}
    url = obj_url + '?mkey=' + table_name
    if name:
        url += '&sub_mkey=' + name
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_obj(module, connection):
    name = module.params['name']
    table_name = module.params['table_name']
    payload = {}
    url = obj_url + '?mkey=' + table_name + '&sub_mkey=' + name
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

    if (action == 'edit' or action == 'delete') and module.params['name'] is None:
        err_msg = 'name need to set'
        res = False

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        table_name=dict(type='str'),
        name=dict(type='str'),
        max_http_body_parameter_length_val=dict(type='str'),
        url_param_name_check=dict(type='str'),
        number_of_ranges_in_range_header_val=dict(type='str'),
        Post_request_ctype_check=dict(type='str'),
        Illegal_host_name_check=dict(type='str'),
        max_http_content_length=dict(type='str'),
        max_http_body_length_val=dict(type='str'),
        web_socket_protocol_check_val=dict(type='str'),
        Illegal_host_name_check_val=dict(type='str'),
        Illegal_http_request_method_check=dict(type='str'),
        source_ip_status=dict(type='str'),
        http2_max_requests=dict(type='str'),
        max_http_body_parameter_length=dict(type='str'),
        max_url_parameter_val=dict(type='str'),
        block_malformed_request_val=dict(type='str'),
        max_http_request_length=dict(type='str'),
        number_of_ranges_in_range_header=dict(type='str'),
        id=dict(type='str'),
        redundant_header_check=dict(type='str'),
        max_url_parameter_length_val=dict(type='str'),
        Illegal_content_type_check_val=dict(type='str'),
        max_url_param_name_len_val=dict(type='str'),
        Illegal_content_length_check=dict(type='str'),
        max_http_header_length=dict(type='str'),
        Illegal_byte_in_url_check_val=dict(type='str'),
        Internal_resource_limits_check_val=dict(type='str'),
        source_ip=dict(type='str'),
        max_http_request_length_val=dict(type='str'),
        url_param_name_check_val=dict(type='str'),
        rpc_protocol_check=dict(type='str'),
        duplicate_paramname_check_val=dict(type='str'),
        max_http_body_length=dict(type='str'),
        web_socket_protocol_check=dict(type='str'),
        parameter_name_check=dict(type='str'),
        max_url_parameter_length=dict(type='str'),
        Illegal_header_name_check=dict(type='str'),
        url_param_value_check=dict(type='str'),
        duplicate_paramname_check=dict(type='str'),
        parameter_name_check_val=dict(type='str'),
        source_ip_status_val=dict(type='str'),
        http2_max_requests_val=dict(type='str'),
        Illegal_content_length_check_val=dict(type='str'),
        request_type=dict(type='str'),
        max_url_param_name_len=dict(type='str'),
        max_url_param_value_len_val=dict(type='str'),
        max_header_line_request_val=dict(type='str'),
        odd_and_even_space_attack_check_val=dict(type='str'),
        parameter_value_check_val=dict(type='str'),
        max_http_header_value_length=dict(type='str'),
        max_url_parameter=dict(type='str'),
        host=dict(type='str'),
        max_http_header_name_length=dict(type='str'),
        odd_and_even_space_attack_check=dict(type='str'),
        max_http_content_length_val=dict(type='str'),
        request_type_val=dict(type='str'),
        Illegal_http_request_method_check_val=dict(type='str'),
        max_cookie_in_request_val=dict(type='str'),
        rpc_protocol_check_val=dict(type='str'),
        Illegal_header_value_check=dict(type='str'),
        parameter_value_check=dict(type='str'),
        max_header_line_request=dict(type='str'),
        max_http_header_value_length_val=dict(type='str'),
        q_type=dict(type='int'),
        null_byte_in_url_check=dict(type='str'),
        host_status=dict(type='str'),
        max_http_header_length_val=dict(type='str'),
        null_byte_in_url_check_val=dict(type='str'),
        block_malformed_request=dict(type='str'),
        Internal_resource_limits_check=dict(type='str'),
        request_file=dict(type='str'),
        redundant_header_check_val=dict(type='str'),
        Illegal_header_name_check_val=dict(type='str'),
        url_param_value_check_val=dict(type='str'),
        max_http_header_name_length_val=dict(type='str'),
        Post_request_ctype_check_val=dict(type='str'),
        host_status_val=dict(type='str'),
        max_http_request_filename_length=dict(type='str'),
        Illegal_header_value_check_val=dict(type='str'),
        max_url_param_value_len=dict(type='str'),
        max_http_request_filename_length_val=dict(type='str'),
        Illegal_content_type_check=dict(type='str'),
        max_cookie_in_request=dict(type='str'),
        Illegal_byte_in_url_check=dict(type='str'),
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
