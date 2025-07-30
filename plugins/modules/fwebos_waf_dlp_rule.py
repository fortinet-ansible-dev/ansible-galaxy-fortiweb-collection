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
module: fwebos_waf_dlp_rule
description:
  - Config FortiWeb Data Loss Preventation Rule
version_added: "7.0.0"
authors:
  - Joseph Chen
requirements:
    - ansible>=2.11
options:
    name:
        description:
            - A unique name that can be referenced in other parts of the configuration.
        type: string
    security_action:
        description:
            - Select which action the FortiWeb appliance will take when it detects a violation of the rule.
        type: string
        choices:
            - 'alert'
            - 'alert_deny'
            - 'block-period'
    severity:
        description:
            - Select which severity level FortiWeb uses when it logs a CSRF attack.
        type: string
        choices:
            - 'Info'
            - 'Low'
            - 'Medium'
            - 'High'
    host_status:
        description:
            - Enable to apply this rule only to HTTP requests for specific web hosts. Disable to match the rule based on the URL and any parameter filter only.
        type: string
        choices:
            - 'enable'
            - 'disable'
    host:
        description:
            - Enter the IP address or FQDN of the host to which the DLP rule will be applied. Only available if Host Status is enabled.
        type: string
    url_type:
        description:
            - Simple string or regular expression
        type: string
        choices:
            - 'plain'
            - 'regular'
    url:
        description:
            - Expression to specify the URL.
        type: string
    direction:
        description:
            - simple string or regular expression
        type: string
        choices:
            - 'request'
            - 'response'
            - 'both'
    type:
        description:
            - What type of data FortiWeb will scan.
        type: string
        choices:
            - 'http-payload'
            - 'files'
    email_attachments:
        description:
            - Enable Attachments in Email to restrict the file scan exclusively to attachments in emails. Available only when 'files' is selected in Type.
        type: string
        choices:
            - 'enable'
            - 'disable'
    owa_protocol:
        description:
            - OWA Protocol. If enabled, FortiWeb will scan attachments in Email sent and received via a web browser login.
        type: string
        choices:
            - 'enable'
            - 'disable'
    activesync_protocol:
        description:
            - ActiveSync Protocol. If enabled, FortiWeb will scan attachments in Email sent and received via a mobile phone login.
        type: string
        choices:
            - 'enable'
            - 'disable'
    mapi_protocol:
        description:
            - MAPI Protocol. If enabled, FortiWeb will scan attachments in Email sent and received via the Messaging Application Programming Interface (MAPI), a transport protocol implemented in Microsoft Exchange Server 2013 Service Pack 1 (SP1).
        type: string
        choices:
            - 'enable'
            - 'disable'
    block_period:
        description:
            - Enter the amount of time (in seconds) that you want to block subsequent requests from the same IP address after FortiWeb detects a DLP rule violation. This setting is available only when Data Loss Prevention is set to Period Block. The valid range is 1–3,600
        type: string
    trigger:
        description:
            - Select the trigger policy, if any, that FortiWeb carries out when it logs and/or sends an alert email about a DLP rule violation.
        type: string
    sensor:
        description:
            - Select the DLP sensor.
        type: string
"""

EXAMPLES = """
    - name: add a policy of http payload type
      fwebos_waf_dlp_rule:
       action: add
       name: dlp3
       security_action: block-period
       severity: High
       host_status: enable
       url_type: plain
       direction: request
       type: http-payload
       block_period: 500
       host: myhost
       url: /folder2/*
       trigger: tp1
       sensor: sensor1

    - name: add a policy of file type
      fwebos_waf_dlp_rule:
       action: add
       name: dlp4
       security_action: alert
       severity: Low
       host_status: enable
       direction: request
       type: files
       trigger: tp1
       sensor: sensor1
       email_attachments: enable
       owa_protocol: enable
       activesync_protocol: disable
       mapi_protocol: disable

    - name: get a policy of file type
      fwebos_waf_dlp_rule:
       action: get
       name: dlp4

    - name: edit a policy of file type
      fwebos_waf_dlp_rule:
       action: edit
       name: dlp4
       security_action: alert
       severity: Info
       activesync_protocol: enable
       mapi_protocol: enable

    - name: delete a policy
      fwebos_waf_dlp_rule:
       action: delete
       name: dlp4




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

obj_url = '/api/v2.0/cmdb/waf/dlp.rule'


rep_dict = {
    "host_status": "host-status",
    "url_type": "url-type",
    "security_action": "action",
    "email_attachments": "email-attachments",
    "owa_protocol": "owa-protocol",
    "activesync_protocol": "activesync-protocol",
    "mapi_protocol": "mapi-protocol",
    "block_period": "block-period"
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
    # response['sent'] = payload1['data']

    return code, response, payload1['data']


def edit_obj(module, payload, connection):
    name = module.params['name']
    url = obj_url + '?mkey=' + name
    if 'id' in module.params:
        url += '&sub_mkey=' + module.params['id']
    payload1 = {}
    payload1['data'] = payload
    code, response = connection.send_request(url, payload1, 'PUT')

    return code, response


def get_obj(module, connection):
    name = module.params['name']
    payload = {}
    url = obj_url + '?mkey=' + name
    if 'id' in module.params:
        url += '&sub_mkey=' + module.params['id']
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_obj(module, connection):
    name = module.params['name']
    url = obj_url + '?mkey=' + name
    if 'id' in module.params:
        url += '&sub_mkey=' + module.params['id']
    payload = {}
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
    payload1 = {}
    payload1['data'] = module.params
    replace_key(payload1['data'], rep_dict)
    payload1['data'].pop('action')

    res = combine_dict(payload1['data'], data)
    return res, data

def value_check(params, key_name, good_values):
    msg = ''
    res = True
    if params[key_name] is not None:
        value_is_good = False
        for v in good_values:
            if params[key_name]==v:
                value_is_good = True
                return res, msg
        if value_is_good == False:
            # generate error message.
            res = False
            msg = 'The value of \''+ key_name + '\' should be'
            if len(good_values) == 1:
                msg+= f" '{good_values[0]}'."
            else:
                quoted_good_values = [f"'{val}'" for val in good_values]
                msg+= f" {', '.join(quoted_good_values[:-1])}, or {quoted_good_values[-1]}."

    return res, msg

def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = ''

    if (action == 'add' or action == 'edit' or action == 'delete') and module.params['name'] is None:
        err_msg = 'name need to set'
        res = False
    res, err_msg = value_check(module.params, 'direction', ['request', 'response', 'both'])
    if res == False:
        return res, err_msg
    res, err_msg = value_check(module.params, 'severity', ['Info', 'Low', 'Medium', 'High'])
    if res == False:
        return res, err_msg
    res, err_msg = value_check(module.params, 'email_attachments', ['enable', 'disable'])
    if res == False:
        return res, err_msg
    res, err_msg = value_check(module.params, 'owa_protocol', ['enable', 'disable'])
    if res == False:
        return res, err_msg
    res, err_msg = value_check(module.params, 'activesync_protocol', ['enable', 'disable'])
    if res == False:
        return res, err_msg
    res, err_msg = value_check(module.params, 'mapi_protocol', ['enable', 'disable'])
    if res == False:
        return res, err_msg
    res, err_msg = value_check(module.params, 'security_action', ['alert', 'alert_deny', 'block-period'])
    if res == False:
        return res, err_msg
    res, err_msg = value_check(module.params, 'url_type', ['plain', 'regular'])
    if res == False:
        return res, err_msg
    res, err_msg = value_check(module.params, 'type', ['http-payload', 'files'])
    if res == False:
        return res, err_msg
    res, err_msg = value_check(module.params, 'host_status', ['enable', 'disable'])
    if res == False:
        return res, err_msg
    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
        vdom=dict(type='str'),
        security_action=dict(type='str'),
        severity=dict(type='str'),
        host_status=dict(type='str'),
        url_type=dict(type='str'),
        direction=dict(type='str'),
        type=dict(type='str'),
        email_attachments=dict(type='str'),
        owa_protocol=dict(type='str'),
        activesync_protocol=dict(type='str'),
        mapi_protocol=dict(type='str'),
        block_period=dict(type='str'),
        host=dict(type='str'),
        url=dict(type='str'),
        trigger=dict(type='str'),
        sensor=dict(type='str'),
    )
    argument_spec.update(fwebos_argument_spec)

    required_if = [('name')]
    module = AnsibleModule(argument_spec=argument_spec,
                           required_if=required_if)
    action = module.params['action']
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
            result['err_msg'] = 'Entry not found'
        else:
            res, new_data = needs_update(module, data['results'])
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
        if result['res']['results']['errcode'] == -3 or result['res']['results']['errcode'] == -5:
            result['failed'] = False

    module.exit_json(**result)


if __name__ == '__main__':
    main()

            