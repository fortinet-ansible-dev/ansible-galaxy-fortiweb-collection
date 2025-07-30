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
module: fwebos_bot_detection
description:
  - Config FortiWeb Bot Detection Policy
version_added: "7.0.0"
authors:
  - Joseph Chen
requirements:
    - ansible>=2.11
options:
    id:
        description:
            - The numerical index of bot detection policy.
        type: string
    policy_id:
        description:
            - The numerical policy ID of the Server Policy. It is the same one as used in CLI.
        type: string
    allow_ip:
        description:
            - Limit Sample Collections From IPs.
        type: list
    advanced_mode:
        description:
            - Enable or disable Advanced Mode.
        type: string
        choices:
            - 'enable'
            - 'disable'
    client_identification_method:
        description:
            - Client Identification Method.
        type: string
        choices:
            - 'IP-and-User-Agent'
            - 'IP'
            - 'Cookie'
    sampling_count:
        description:
            - Sample Count. (range: 1-1000)
        type: integer
    sampling_count_per_client:
        description:
            - Sample Count per Client per Hour. (range: 1-60)
        type: integer
    sampling_time_per_vector:
        description:
            - Sampling Time per Vector. (range: 1-10)
        type: integer
    selected_model:
        description:
            - Model Type for Model Building Settings.
        type: string
        choices:
            - 'Strict'
            - 'Moderate'
    anomaly_count:
        description:
            - Anomaly Count. (range: 1-65535)
        type: integer
    bot_confirmation:
        description:
            - Enable or disable Bot Confirmation.
        type: string
        choices:
            - 'enable'
            - 'disable'
    verification_method:
        description:
            - Bot Verification Method.
        type: string
        choices:
            - 'Real-Browser-Enforement'
            - 'Disable'
            - 'Captcha-Enforcement'
    security:
        description:
            - Select security level.
        type: string
        choices:
            - 'Info'
            - 'Low'
            - 'Medium'
            - 'High'
    security_action:
        description:
            - Choose the action FortiWeb takes when a user client is confirmed as a bot.
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    block_period:
        description:
            - Block Period. (range: 1-3600)
        type: integer
    security:
        description:
            - Select security level.
        type: string
        choices:
            - 'Info'
            - 'Low'
            - 'Medium'
            - 'High'
    trigger:
        description:
            - Select the trigger policy, if any, that FortiWeb carries out when it logs and/or sends an alert email about a violation.
        type: string
    global_exception:
        description:
            - Select New Bot Mitigation Exception Policy.
        type: string
"""

EXAMPLES = """
    - name: add a bot detection policy
      fwebos_bot_detection:
        action: add
        policy_id: 6814698978843458079
        allow_ip:
          - 11.2.3.4
          - 192.168.253.1

    - name: get a bot detection policy
      fwebos_bot_detection:
        action: get
        id: 1

    - name: edit a bot detection policy
      fwebos_bot_detection:
        action: edit
        id: 1
        anomaly_count: 14456
        sampling_count: 999
        security_action: alert_deny

    - name: delete a bot detection policy
      fwebos_bot_detection:
        action: delete
        id: 1

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

edt_url = '/api/v2.0/waf/bot-detection-policy?is_refresh=0'
obj_url = '/api/v2.0/cmdb/waf/bot-detection-policy'
add_url = '/api/v2.0/machine_learning/policy.botdetection'

rep_dict = {
    "advanced_mode": "advanced-mode",
    "client_identification_method": "client-identification-method",
    "sampling_count": "sampling-count",
    "sampling_count_per_client": "sampling-count-per-client",
    "sampling_time_per_vector": "sampling-time-per-vector",
    "training_accuracy": "training-accuracy",
    "cross_validation": "cross-validation",
    "testing_accuracy": "testing-accuracy",
    "security_action": "action",
    "anomaly_count": "anomaly-count",
    "bot_confirmation": "bot-confirmation",
    "verification_method": "verification-method",
    "validation_timeout": "validation-timeout",
    "max_attempt_times": "max-attempt-times",
    "recaptcha_server": "recaptcha-server",
    "mobile_verification_method": "mobile-verification-method",
    "auto_refresh": "auto-refresh",
    "refresh_factor": "refresh-factor",
    "minimum_vector_number": "minimum-vector-number",
    "block_period": "block-period",
    "global_exception": "global-exception",
    "sz_allow_source_ip": "sz_allow-source-ip",
    "sz_bot_detection_exception_list": "sz_bot-detection-exception-list",
    "model_status": "model-status",
    "selected_model": "selected-model",
    "time_clustering": "time-clustering",
    "space_clustering": "space-clustering",
    "time_clustering_timeout": "time-clustering-timeout",
    "space_clustering_timeout": "space-clustering-timeout",
    "time_clustering_threshold_percentage": "time-clustering-threshold-percentage",
    "space_clustering_collecting_interval": "space-clustering-collecting-interval",
    "space_clustering_size_limit": "space-clustering-size-limit",
    "space_clustering_size_limit_in_percentage": "space-clustering-size-limit-in-percentage",
    "time_clustering_threshold": "time-clustering-threshold",
    "space_clustering_threshold": "space-clustering-threshold",
    "time_clustering_mode": "time-clustering-mode",
    "space_clustering_mode": "space-clustering-mode",
    "clustering_shadow_mode": "clustering-shadow-mode",
    "clustering_normalization": "clustering-normalization"
}

def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)

def add_obj(module, connection):

    url = add_url
    payload1 = {}
    payload1['data'] = {
        'policy_id': module.params['policy_id'],
        'allow_ip': module.params['allow_ip']
    }

    code, response = connection.send_request(url, payload1['data'])
    # # response['sent'] = payload1['data']

    return code, response, payload1['data']


def edit_obj(module, payload, connection):
    id = module.params['id']
    if id:
        url = obj_url + '?mkey=' + id
    payload1 = {}
    payload1['data'] = payload
    code, response = connection.send_request(url, payload1, 'PUT')

    return code, response


def get_obj(module, connection):
    payload = {}
    id = module.params['id']
    if id:
        url = obj_url + '?mkey=' + id
    code, response = connection.send_request(url, payload, 'GET')

    return code, response


def delete_obj(module, connection):
    id = module.params['id']
    if id:
        url = obj_url + '?mkey=' + id
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

    res = combine_dict(payload1['data'], data)
    return res, data

def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = ''

    if (action == 'get' or action == 'edit' or action == 'delete') and module.params['id'] is None:
        err_msg = 'id cannnot be empty'
        res = False
            
    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        vdom=dict(type='str'),
        policy_id=dict(type='str'),
        allow_ip=dict(type='list'),
        id=dict(type='str'),
        advanced_mode=dict(type='str'),
        client_identification_method=dict(type='str'),
        sampling_count=dict(type='str'),
        sampling_count_per_client=dict(type='str'),
        sampling_time_per_vector=dict(type='str'),
        training_accuracy=dict(type='str'),
        cross_validation=dict(type='str'),
        testing_accuracy=dict(type='str'),
        anomaly_count=dict(type='str'),
        bot_confirmation=dict(type='str'),
        verification_method=dict(type='str'),
        validation_timeout=dict(type='str'),
        max_attempt_times=dict(type='str'),
        recaptcha_server=dict(type='str'),
        mobile_verification_method=dict(type='str'),
        auto_refresh=dict(type='str'),
        refresh_factor=dict(type='str'),
        minimum_vector_number=dict(type='str'),
        security_action=dict(type='str'),
        block_period=dict(type='str'),
        severity=dict(type='str'),
        trigger=dict(type='str'),
        global_exception=dict(type='str'),
        sz_allow_source_ip=dict(type='str'),
        sz_bot_detection_exception_list=dict(type='str'),
        model_status=dict(type='str'),
        selected_model=dict(type='str'),
        time_clustering=dict(type='str'),
        space_clustering=dict(type='str'),
        time_clustering_timeout=dict(type='str'),
        space_clustering_timeout=dict(type='str'),
        time_clustering_threshold_percentage=dict(type='str'),
        space_clustering_collecting_interval=dict(type='str'),
        space_clustering_size_limit=dict(type='str'),
        space_clustering_size_limit_in_percentage=dict(type='str'),
        time_clustering_threshold=dict(type='str'),
        space_clustering_threshold=dict(type='str'),
        time_clustering_mode=dict(type='str'),
        space_clustering_mode=dict(type='str'),
        clustering_shadow_mode=dict(type='str'),
        clustering_normalization=dict(type='str'),
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

    # if 'errcode' in str(result):
    #     result['changed'] = False
    #     result['failed'] = True
    #     result['err_msg'] = 'Please check error code'
    #     if result['res']['results']['errcode'] == -3 or result['res']['results']['errcode'] == -5:
    #         result['failed'] = False

    module.exit_json(**result)


if __name__ == '__main__':
    main()
