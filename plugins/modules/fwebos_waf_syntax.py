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
module: fwebos_waf_syntax
description:
  - Configure FortiWeb devices via RESTful APIs
"""

EXAMPLES = """
"""

RETURN = """
"""

obj_url = '/api/v2.0/cmdb/waf/syntax-based-attack-detection'

rep_dict = {
    'sql_arithmetic_operation_block_period': 'sql-arithmetic-operation-block-period',
    'sql_stacked_queries_threat_weight': 'sql-stacked-queries-threat-weight',
    'sql_embeded_queries_block_period': 'sql-embeded-queries-block-period',
    'sql_arithmetic_operation_status': 'sql-arithmetic-operation-status',
    'sql_condition_based_severity': 'sql-condition-based-severity',
    'xss_html_attribute_based_block_period': 'xss-html-attribute-based-block-period',
    'xss_html_tag_based_trigger': 'xss-html-tag-based-trigger',
    'sql_condition_based_threat_weight_value': 'sql-condition-based-threat-weight-value',
    'sql_function_based_severity': 'sql-function-based-severity',
    'xss_javascript_function_based_block_period': 'xss-javascript-function-based-block-period',
    'xss_html_attribute_based_threat_weight_value': 'xss-html-attribute-based-threat-weight-value',
    'xss_html_attribute_based_threat_weight': 'xss-html-attribute-based-threat-weight',
    'sql_embeded_queries_trigger': 'sql-embeded-queries-trigger',
    'sql_line_comments_status': 'sql-line-comments-status',
    'xss_javascript_variable_based_trigger': 'xss-javascript-variable-based-trigger',
    'sql_line_comments_threat_weight_value': 'sql-line-comments-threat-weight-value',
    'xss_html_tag_based_block_period': 'xss-html-tag-based-block-period',
    'sql_arithmetic_operation_severity': 'sql-arithmetic-operation-severity',
    'sql_embeded_queries_status': 'sql-embeded-queries-status',
    'sql_condition_based_threat_weight': 'sql-condition-based-threat-weight',
    'xss_html_attribute_based_severity': 'xss-html-attribute-based-severity',
    'sql_condition_based_status': 'sql-condition-based-status',
    'sql_stacked_queries_trigger': 'sql-stacked-queries-trigger',
    'xss_html_css_based_status': 'xss-html-css-based-status',
    'xss_javascript_variable_based_block_period': 'xss-javascript-variable-based-block-period',
    'xss_html_attribute_based_action': 'xss-html-attribute-based-action',
    'detection_target_sql': 'detection-target-sql',
    'sql_stacked_queries_threat_weight_value': 'sql-stacked-queries-threat-weight-value',
    'sql_embeded_queries_threat_weight': 'sql-embeded-queries-threat-weight',
    'sql_stacked_queries_status': 'sql-stacked-queries-status',
    'sql_function_based_threat_weight': 'sql-function-based-threat-weight',
    'xss_javascript_variable_based_threat_weight': 'xss-javascript-variable-based-threat-weight',
    'sz_exception_element_list': 'sz_exception-element-list',
    'xss_html_tag_based_threat_weight': 'xss-html-tag-based-threat-weight',
    'sql_stacked_queries_action': 'sql-stacked-queries-action',
    'xss_javascript_variable_based_threat_weight_value': 'xss-javascript-variable-based-threat-weight-value',
    'sql_arithmetic_operation_action': 'sql-arithmetic-operation-action',
    'sql_condition_based_block_period': 'sql-condition-based-block-period',
    'sql_function_based_status': 'sql-function-based-status',
    'sql_embeded_queries_severity': 'sql-embeded-queries-severity',
    'sql_embeded_queries_action': 'sql-embeded-queries-action',
    'sql_arithmetic_operation_trigger': 'sql-arithmetic-operation-trigger',
    'xss_html_tag_based_action': 'xss-html-tag-based-action',
    'xss_html_tag_based_status': 'xss-html-tag-based-status',
    'sql_stacked_queries_severity': 'sql-stacked-queries-severity',
    'sql_arithmetic_operation_threat_weight_value': 'sql-arithmetic-operation-threat-weight-value',
    'sql_function_based_threat_weight_value': 'sql-function-based-threat-weight-value',
    'xss_html_css_based_trigger': 'xss-html-css-based-trigger',
    'xss_html_tag_based_severity': 'xss-html-tag-based-severity',
    'xss_javascript_function_based_severity': 'xss-javascript-function-based-severity',
    'sql_function_based_trigger': 'sql-function-based-trigger',
    'sql_line_comments_trigger': 'sql-line-comments-trigger',
    'xss_html_css_based_block_period': 'xss-html-css-based-block-period',
    'xss_javascript_variable_based_action': 'xss-javascript-variable-based-action',
    'xss_javascript_function_based_threat_weight_value': 'xss-javascript-function-based-threat-weight-value',
    'xss_javascript_function_based_status': 'xss-javascript-function-based-status',
    'detection_target_xss': 'detection-target-xss',
    'xss_javascript_function_based_threat_weight': 'xss-javascript-function-based-threat-weight',
    'sql_embeded_queries_threat_weight_value': 'sql-embeded-queries-threat-weight-value',
    'xss_javascript_variable_based_status': 'xss-javascript-variable-based-status',
    'xss_javascript_function_based_trigger': 'xss-javascript-function-based-trigger',
    'xss_html_css_based_threat_weight': 'xss-html-css-based-threat-weight',
    'sql_condition_based_action': 'sql-condition-based-action',
    'xss_javascript_variable_based_severity': 'xss-javascript-variable-based-severity',
    'sql_stacked_queries_block_period': 'sql-stacked-queries-block-period',
    'sql_line_comments_action': 'sql-line-comments-action',
    'xss_html_tag_based_check_level': 'xss-html-tag-based-check-level',
    'xss_html_tag_based_threat_weight_value': 'xss-html-tag-based-threat-weight-value',
    'sql_arithmetic_operation_threat_weight': 'sql-arithmetic-operation-threat-weight',
    'xss_html_css_based_severity': 'xss-html-css-based-severity',
    'sql_function_based_block_period': 'sql-function-based-block-period',
    'xss_html_css_based_action': 'xss-html-css-based-action',
    'sql_line_comments_threat_weight': 'sql-line-comments-threat-weight',
    'sql_function_based_action': 'sql-function-based-action',
    'xss_javascript_function_based_action': 'xss-javascript-function-based-action',
    'sql_line_comments_block_period': 'sql-line-comments-block-period',
    'sql_condition_based_trigger': 'sql-condition-based-trigger',
    'xss_html_attribute_based_status': 'xss-html-attribute-based-status',
    'sql_line_comments_severity': 'sql-line-comments-severity',
    'xss_html_css_based_threat_weight_value': 'xss-html-css-based-threat-weight-value',
    'xss_html_attribute_based_trigger': 'xss-html-attribute-based-trigger',
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
        sql_arithmetic_operation_block_period=dict(type='int'),
        sql_stacked_queries_threat_weight=dict(type='str'),
        sql_embeded_queries_block_period=dict(type='int'),
        sql_arithmetic_operation_status=dict(type='str'),
        sql_condition_based_severity=dict(type='str'),
        xss_html_attribute_based_block_period=dict(type='int'),
        xss_html_tag_based_trigger=dict(type='str'),
        sql_condition_based_threat_weight_value=dict(type='int'),
        sql_function_based_severity=dict(type='str'),
        xss_javascript_function_based_block_period=dict(type='int'),
        xss_html_attribute_based_threat_weight_value=dict(type='int'),
        xss_html_attribute_based_threat_weight=dict(type='str'),
        sql_embeded_queries_trigger=dict(type='str'),
        sql_line_comments_status=dict(type='str'),
        xss_javascript_variable_based_trigger=dict(type='str'),
        sql_line_comments_threat_weight_value=dict(type='int'),
        xss_html_tag_based_block_period=dict(type='int'),
        sql_arithmetic_operation_severity=dict(type='str'),
        sql_embeded_queries_status=dict(type='str'),
        sql_condition_based_threat_weight=dict(type='str'),
        xss_html_attribute_based_severity=dict(type='str'),
        sql_condition_based_status=dict(type='str'),
        sql_stacked_queries_trigger=dict(type='str'),
        xss_html_css_based_status=dict(type='str'),
        xss_javascript_variable_based_block_period=dict(type='int'),
        xss_html_attribute_based_action=dict(type='str'),
        detection_target_sql=dict(type='str'),
        sql_stacked_queries_threat_weight_value=dict(type='int'),
        sql_embeded_queries_threat_weight=dict(type='str'),
        sql_stacked_queries_status=dict(type='str'),
        sql_function_based_threat_weight=dict(type='str'),
        xss_javascript_variable_based_threat_weight=dict(type='str'),
        sz_exception_element_list=dict(type='int'),
        xss_html_tag_based_threat_weight=dict(type='str'),
        sql_stacked_queries_action=dict(type='str'),
        xss_javascript_variable_based_threat_weight_value=dict(type='int'),
        sql_arithmetic_operation_action=dict(type='str'),
        sql_condition_based_block_period=dict(type='int'),
        sql_function_based_status=dict(type='str'),
        sql_embeded_queries_severity=dict(type='str'),
        sql_embeded_queries_action=dict(type='str'),
        sql_arithmetic_operation_trigger=dict(type='str'),
        xss_html_tag_based_action=dict(type='str'),
        xss_html_tag_based_status=dict(type='str'),
        sql_stacked_queries_severity=dict(type='str'),
        sql_arithmetic_operation_threat_weight_value=dict(type='int'),
        sql_function_based_threat_weight_value=dict(type='int'),
        xss_html_css_based_trigger=dict(type='str'),
        xss_html_tag_based_severity=dict(type='str'),
        xss_javascript_function_based_severity=dict(type='str'),
        sql_function_based_trigger=dict(type='str'),
        sql_line_comments_trigger=dict(type='str'),
        xss_html_css_based_block_period=dict(type='int'),
        xss_javascript_variable_based_action=dict(type='str'),
        xss_javascript_function_based_threat_weight_value=dict(type='int'),
        xss_javascript_function_based_status=dict(type='str'),
        detection_target_xss=dict(type='str'),
        xss_javascript_function_based_threat_weight=dict(type='str'),
        sql_embeded_queries_threat_weight_value=dict(type='int'),
        xss_javascript_variable_based_status=dict(type='str'),
        xss_javascript_function_based_trigger=dict(type='str'),
        xss_html_css_based_threat_weight=dict(type='str'),
        sql_condition_based_action=dict(type='str'),
        xss_javascript_variable_based_severity=dict(type='str'),
        sql_stacked_queries_block_period=dict(type='int'),
        sql_line_comments_action=dict(type='str'),
        xss_html_tag_based_check_level=dict(type='str'),
        name=dict(type='str'),
        xss_html_tag_based_threat_weight_value=dict(type='int'),
        sql_arithmetic_operation_threat_weight=dict(type='str'),
        xss_html_css_based_severity=dict(type='str'),
        sql_function_based_block_period=dict(type='int'),
        xss_html_css_based_action=dict(type='str'),
        sql_line_comments_threat_weight=dict(type='str'),
        sql_function_based_action=dict(type='str'),
        xss_javascript_function_based_action=dict(type='str'),
        sql_line_comments_block_period=dict(type='int'),
        sql_condition_based_trigger=dict(type='str'),
        xss_html_attribute_based_status=dict(type='str'),
        sql_line_comments_severity=dict(type='str'),
        xss_html_css_based_threat_weight_value=dict(type='int'),
        xss_html_attribute_based_trigger=dict(type='str'),
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
        if 'results' in data.keys() and data['results'] and type(data['results']) is not int:
            res, new_data = needs_update(module, data['results'])
        else:
            res = False
            result['err_msg'] = 'Entry not found'
        if res:
            new_data1 = {}
            new_data1['data'] = new_data
            code, response = edit_obj(module, new_data1, connection)
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
