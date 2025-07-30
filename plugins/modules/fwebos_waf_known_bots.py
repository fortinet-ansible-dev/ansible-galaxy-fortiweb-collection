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
module: fwebos_waf_known_bots
description:
  - Config FortiWeb Known Bots
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
    dos_status:
        description:
            - Enable or disable the DoS Bot check for this rule.
        type: string
        choices:
            - 'enable'
            - 'disable'
    dos_action:
        description:
            - Select the action that FortiWeb takes when it detects a DoS Bot violation of the rule.
        type: string
        choices:
            - 'bypass'
            - 'alert'
            - 'alert_deny'
            - 'redirect'
            - 'deny_no_log'
            - 'block-period'
            - 'send_http_response'
    dos_severity:
        description:
            - Select which severity level the FortiWeb appliance will use when it logs a violation of the rule.
        type: string
        choices:
            - 'Low'
            - 'Medium'
            - 'High'
            - 'Info'
    dos_threat_weight:
        description:
            - Set the weight for the threat.
        type: string
        choices:
            - 'informational'
            - 'low'
            - 'moderate'
            - 'substantial'
            - 'severe'
            - 'critical'
    dos_trigger:
        description:
            - Select which trigger, if any, that the FortiWeb appliance will use when it logs and/or sends an alert email about a violation of each rule.
        type: string
    dos_block_period:
        description:
            - The number of seconds that you want to block subsequent requests from the client after the FortiWeb appliance detects that the client has violated the rule. Only available when 'dos_action' is 'block-period'.
        type: string
    spam_status:
        description:
            - Enable or disable the Spam Bot check for this rule.
        type: string
        choices:
            - 'enable'
            - 'disable'
    spam_action:
        description:
            - Select the action that FortiWeb takes when it detects a spam Bot violation of the rule.
        type: string
        choices:
            - 'bypass'
            - 'alert'
            - 'alert_deny'
            - 'redirect'
            - 'deny_no_log'
            - 'block-period'
            - 'send_http_response'
    spam_severity:
        description:
            - Select which severity level the FortiWeb appliance will use when it logs a violation of the rule.
        type: string
        choices:
            - 'Low'
            - 'Medium'
            - 'High'
            - 'Info'
    spam_threat_weight:
        description:
            - Set the weight for the threat.
        type: string
        choices:
            - 'informational'
            - 'low'
            - 'moderate'
            - 'substantial'
            - 'severe'
            - 'critical'
    spam_trigger:
        description:
            - Select which trigger, if any, that the FortiWeb appliance will use when it logs and/or sends an alert email about a violation of each rule.
        type: string
    spam_block_period:
        description:
            - The number of seconds that you want to block subsequent requests from the client after the FortiWeb appliance detects that the client has violated the rule. Only available when 'spam_action' is 'block-period'.
        type: string
    trojan_status:
        description:
            - Enable or disable the trojan Bot check for this rule.
        type: string
        choices:
            - 'enable'
            - 'disable'
    trojan_action:
        description:
            - Select the action that FortiWeb takes when it detects a trojan Bot violation of the rule.
        type: string
        choices:
            - 'bypass'
            - 'alert'
            - 'alert_deny'
            - 'redirect'
            - 'deny_no_log'
            - 'block-period'
            - 'send_http_response'
    trojan_severity:
        description:
            - Select which severity level the FortiWeb appliance will use when it logs a violation of the rule.
        type: string
        choices:
            - 'Low'
            - 'Medium'
            - 'High'
            - 'Info'
    trojan_threat_weight:
        description:
            - Set the weight for the threat.
        type: string
        choices:
            - 'informational'
            - 'low'
            - 'moderate'
            - 'substantial'
            - 'severe'
            - 'critical'
    trojan_trigger:
        description:
            - Select which trigger, if any, that the FortiWeb appliance will use when it logs and/or sends an alert email about a violation of each rule.
        type: string
    trojan_block_period:
        description:
            - The number of seconds that you want to block subsequent requests from the client after the FortiWeb appliance detects that the client has violated the rule. Only available when 'trojan_action' is 'block-period'.
        type: string
    scanner_status:
        description:
            - Enable or disable the scanner Bot check for this rule.
        type: string
        choices:
            - 'enable'
            - 'disable'
    scanner_action:
        description:
            - Select the action that FortiWeb takes when it detects a scanner Bot violation of the rule.
        type: string
        choices:
            - 'bypass'
            - 'alert'
            - 'alert_deny'
            - 'redirect'
            - 'deny_no_log'
            - 'block-period'
            - 'send_http_response'
    scanner_severity:
        description:
            - Select which severity level the FortiWeb appliance will use when it logs a violation of the rule.
        type: string
        choices:
            - 'Low'
            - 'Medium'
            - 'High'
            - 'Info'
    scanner_threat_weight:
        description:
            - Set the weight for the threat.
        type: string
        choices:
            - 'informational'
            - 'low'
            - 'moderate'
            - 'substantial'
            - 'severe'
            - 'critical'
    scanner_trigger:
        description:
            - Select which trigger, if any, that the FortiWeb appliance will use when it logs and/or sends an alert email about a violation of each rule.
        type: string
    scanner_block_period:
        description:
            - The number of seconds that you want to block subsequent requests from the client after the FortiWeb appliance detects that the client has violated the rule. Only available when 'scanner_action' is 'block-period'.
        type: string
    crawler_status:
        description:
            - Enable or disable the crawler Bot check for this rule.
        type: string
        choices:
            - 'enable'
            - 'disable'
    crawler_action:
        description:
            - Select the action that FortiWeb takes when it detects a crawler Bot violation of the rule.
        type: string
        choices:
            - 'bypass'
            - 'alert'
            - 'alert_deny'
            - 'redirect'
            - 'deny_no_log'
            - 'block-period'
            - 'send_http_response'
    crawler_severity:
        description:
            - Select which severity level the FortiWeb appliance will use when it logs a violation of the rule.
        type: string
        choices:
            - 'Low'
            - 'Medium'
            - 'High'
            - 'Info'
    crawler_threat_weight:
        description:
            - Set the weight for the threat.
        type: string
        choices:
            - 'informational'
            - 'low'
            - 'moderate'
            - 'substantial'
            - 'severe'
            - 'critical'
    crawler_trigger:
        description:
            - Select which trigger, if any, that the FortiWeb appliance will use when it logs and/or sends an alert email about a violation of each rule.
        type: string
    crawler_block_period:
        description:
            - The number of seconds that you want to block subsequent requests from the client after the FortiWeb appliance detects that the client has violated the rule. Only available when 'crawler_action' is 'block-period'.
        type: string
    known_engines_status:
        description:
            - Enable or disable the known_engines Bot check for this rule.
        type: string
        choices:
            - 'enable'
            - 'disable'
    known_engines_action:
        description:
            - Select the action that FortiWeb takes when it detects a known_engines Bot violation of the rule.
        type: string
        choices:
            - 'bypass'
            - 'alert'
            - 'alert_deny'
            - 'redirect'
            - 'deny_no_log'
            - 'block-period'
            - 'send_http_response'
    known_engines_severity:
        description:
            - Select which severity level the FortiWeb appliance will use when it logs a violation of the rule.
        type: string
        choices:
            - 'Low'
            - 'Medium'
            - 'High'
            - 'Info'
    known_engines_threat_weight:
        description:
            - Set the weight for the threat.
        type: string
        choices:
            - 'informational'
            - 'low'
            - 'moderate'
            - 'substantial'
            - 'severe'
            - 'critical'
    known_engines_trigger:
        description:
            - Select which trigger, if any, that the FortiWeb appliance will use when it logs and/or sends an alert email about a violation of each rule.
        type: string
    known_engines_block_period:
        description:
            - The number of seconds that you want to block subsequent requests from the client after the FortiWeb appliance detects that the client has violated the rule. Only available when 'known_engines_action' is 'block-period'.
        type: string
    marketing_status:
        description:
            - Enable or disable the marketing Bot check for this rule.
        type: string
        choices:
            - 'enable'
            - 'disable'
    marketing_action:
        description:
            - Select the action that FortiWeb takes when it detects a marketing Bot violation of the rule.
        type: string
        choices:
            - 'bypass'
            - 'alert'
            - 'alert_deny'
            - 'redirect'
            - 'deny_no_log'
            - 'block-period'
            - 'send_http_response'
    marketing_severity:
        description:
            - Select which severity level the FortiWeb appliance will use when it logs a violation of the rule.
        type: string
        choices:
            - 'Low'
            - 'Medium'
            - 'High'
            - 'Info'
    marketing_threat_weight:
        description:
            - Set the weight for the threat.
        type: string
        choices:
            - 'informational'
            - 'low'
            - 'moderate'
            - 'substantial'
            - 'severe'
            - 'critical'
    marketing_trigger:
        description:
            - Select which trigger, if any, that the FortiWeb appliance will use when it logs and/or sends an alert email about a violation of each rule.
        type: string
    marketing_block_period:
        description:
            - The number of seconds that you want to block subsequent requests from the client after the FortiWeb appliance detects that the client has violated the rule. Only available when 'marketing_action' is 'block-period'.
        type: string
    page_preview_status:
        description:
            - Enable or disable the page_preview Bot check for this rule.
        type: string
        choices:
            - 'enable'
            - 'disable'
    page_preview_action:
        description:
            - Select the action that FortiWeb takes when it detects a page_preview Bot violation of the rule.
        type: string
        choices:
            - 'bypass'
            - 'alert'
            - 'alert_deny'
            - 'redirect'
            - 'deny_no_log'
            - 'block-period'
            - 'send_http_response'
    page_preview_severity:
        description:
            - Select which severity level the FortiWeb appliance will use when it logs a violation of the rule.
        type: string
        choices:
            - 'Low'
            - 'Medium'
            - 'High'
            - 'Info'
    page_preview_threat_weight:
        description:
            - Set the weight for the threat.
        type: string
        choices:
            - 'informational'
            - 'low'
            - 'moderate'
            - 'substantial'
            - 'severe'
            - 'critical'
    page_preview_trigger:
        description:
            - Select which trigger, if any, that the FortiWeb appliance will use when it logs and/or sends an alert email about a violation of each rule.
        type: string
    page_preview_block_period:
        description:
            - The number of seconds that you want to block subsequent requests from the client after the FortiWeb appliance detects that the client has violated the rule. Only available when 'page_preview_action' is 'block-period'.
        type: string
    feed_fetcher_status:
        description:
            - Enable or disable the feed_fetcher Bot check for this rule.
        type: string
        choices:
            - 'enable'
            - 'disable'
    feed_fetcher_action:
        description:
            - Select the action that FortiWeb takes when it detects a feed_fetcher Bot violation of the rule.
        type: string
        choices:
            - 'bypass'
            - 'alert'
            - 'alert_deny'
            - 'redirect'
            - 'deny_no_log'
            - 'block-period'
            - 'send_http_response'
    feed_fetcher_severity:
        description:
            - Select which severity level the FortiWeb appliance will use when it logs a violation of the rule.
        type: string
        choices:
            - 'Low'
            - 'Medium'
            - 'High'
            - 'Info'
    feed_fetcher_threat_weight:
        description:
            - Set the weight for the threat.
        type: string
        choices:
            - 'informational'
            - 'low'
            - 'moderate'
            - 'substantial'
            - 'severe'
            - 'critical'
    feed_fetcher_trigger:
        description:
            - Select which trigger, if any, that the FortiWeb appliance will use when it logs and/or sends an alert email about a violation of each rule.
        type: string
    feed_fetcher_block_period:
        description:
            - The number of seconds that you want to block subsequent requests from the client after the FortiWeb appliance detects that the client has violated the rule. Only available when 'feed_fetcher_action' is 'block-period'.
        type: string
    likely_good_bot_status:
        description:
            - Enable or disable the likely_good_bot Bot check for this rule.
        type: string
        choices:
            - 'enable'
            - 'disable'
    likely_good_bot_action:
        description:
            - Select the action that FortiWeb takes when it detects a likely_good_bot Bot violation of the rule.
        type: string
        choices:
            - 'bypass'
            - 'alert'
            - 'alert_deny'
            - 'redirect'
            - 'deny_no_log'
            - 'block-period'
            - 'send_http_response'
    likely_good_bot_severity:
        description:
            - Select which severity level the FortiWeb appliance will use when it logs a violation of the rule.
        type: string
        choices:
            - 'Low'
            - 'Medium'
            - 'High'
            - 'Info'
    likely_good_bot_threat_weight:
        description:
            - Set the weight for the threat.
        type: string
        choices:
            - 'informational'
            - 'low'
            - 'moderate'
            - 'substantial'
            - 'severe'
            - 'critical'
    likely_good_bot_trigger:
        description:
            - Select which trigger, if any, that the FortiWeb appliance will use when it logs and/or sends an alert email about a violation of each rule.
        type: string
    likely_good_bot_block_period:
        description:
            - The number of seconds that you want to block subsequent requests from the client after the FortiWeb appliance detects that the client has violated the rule. Only available when 'likely_good_bot_action' is 'block-period'.
        type: string
"""

EXAMPLES = """
    - name: add a known bot profile
      fwebos_waf_known_bots:
        action: add
        name: Bot1
        dos_status: enable
        dos_action: alert_deny
        dos_block_period: 600
        dos_severity: High
        dos_threat_weight: critical
        dos_trigger:


    - name: edit a known bot profile
      fwebos_waf_known_bots:
        action: edit
        name: Bot1
        feed_fetcher_status: enable
        feed_fetcher_action: redirect
        feed_fetcher_severity: Info
        feed_fetcher_threat_weight: moderate #substantial

    - name: get a known bot profile
      fwebos_waf_known_bots:
        action: get
        name: Bot1

    - name: delete a known bot profile
      fwebos_waf_known_bots:
        action: delete
        name: Bot1



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

obj_url = '/api/v2.0/cmdb/waf/known-bots'


rep_dict = {
    "dos_status": "dos-status",
    "dos_action": "dos-action",
    "dos_block_period": "dos-block-period",
    "dos_severity": "dos-severity",
    "dos_trigger": "dos-trigger",
    "dos_threat_weight": "dos-threat-weight",
    "spam_status": "spam-status",
    "spam_action": "spam-action",
    "spam_block_period": "spam-block-period",
    "spam_severity": "spam-severity",
    "spam_trigger": "spam-trigger",
    "spam_threat_weight": "spam-threat-weight",
    "trojan_status": "trojan-status",
    "trojan_action": "trojan-action",
    "trojan_block_period": "trojan-block-period",
    "trojan_severity": "trojan-severity",
    "trojan_trigger": "trojan-trigger",
    "trojan_threat_weight": "trojan-threat-weight",
    "scanner_status": "scanner-status",
    "scanner_action": "scanner-action",
    "scanner_block_period": "scanner-block-period",
    "scanner_severity": "scanner-severity",
    "scanner_trigger": "scanner-trigger",
    "scanner_threat_weight": "scanner-threat-weight",
    "crawler_status": "crawler-status",
    "crawler_action": "crawler-action",
    "crawler_block_period": "crawler-block-period",
    "crawler_severity": "crawler-severity",
    "crawler_trigger": "crawler-trigger",
    "crawler_threat_weight": "crawler-threat-weight",
    "known_engines_status": "known-engines-status",
    "known_engines_action": "known-engines-action",
    "known_engines_block_period": "known-engines-block-period",
    "known_engines_severity": "known-engines-severity",
    "known_engines_trigger": "known-engines-trigger",
    "known_engines_threat_weight": "known-engines-threat-weight",
    "marketing_status": "marketing-status",
    "marketing_action": "marketing-action",
    "marketing_block_period": "marketing-block-period",
    "marketing_severity": "marketing-severity",
    "marketing_trigger": "marketing-trigger",
    "marketing_threat_weight": "marketing-threat-weight",
    "page_preview_status": "page-preview-status",
    "page_preview_action": "page-preview-action",
    "page_preview_block_period": "page-preview-block-period",
    "page_preview_severity": "page-preview-severity",
    "page_preview_trigger": "page-preview-trigger",
    "page_preview_threat_weight": "page-preview-threat-weight",
    "monitor_status": "monitor-status",
    "monitor_action": "monitor-action",
    "monitor_block_period": "monitor-block-period",
    "monitor_severity": "monitor-severity",
    "monitor_trigger": "monitor-trigger",
    "monitor_threat_weight": "monitor-threat-weight",
    "feed_fetcher_status": "feed-fetcher-status",
    "feed_fetcher_action": "feed-fetcher-action",
    "feed_fetcher_block_period": "feed-fetcher-block-period",
    "feed_fetcher_severity": "feed-fetcher-severity",
    "feed_fetcher_trigger": "feed-fetcher-trigger",
    "feed_fetcher_threat_weight": "feed-fetcher-threat-weight",
    "likely_good_bot_status": "likely-good-bot-status",
    "likely_good_bot_action": "likely-good-bot-action",
    "likely_good_bot_block_period": "likely-good-bot-block-period",
    "likely_good_bot_severity": "likely-good-bot-severity",
    "likely_good_bot_trigger": "likely-good-bot-trigger",
    "likely_good_bot_threat_weight": "likely-good-bot-threat-weight",
    "sz_malicious_bot_disable_list": "sz_malicious-bot-disable-list",
    "sz_known_good_bots_disable_list": "sz_known-good-bots-disable-list",
    "dos_threat_weight_value": "dos-threat-weight-value",
    "spam_threat_weight_value": "spam-threat-weight-value",
    "trojan_threat_weight_value": "trojan-threat-weight-value",
    "scanner_threat_weight_value": "scanner-threat-weight-value",
    "crawler_threat_weight_value": "crawler-threat-weight-value",
    "known_engines_threat_weight_value": "known-engines-threat-weight-value",
    "marketing_threat_weight_value": "marketing-threat-weight-value",
    "page_preview_threat_weight_value": "page-preview-threat-weight-value",
    "monitor_threat_weight_value": "monitor-threat-weight-value",
    "feed_fetcher_threat_weight_value": "feed-fetcher-threat-weight-value",
    "likely_good_bot_threat_weight_value": "likely-good-bot-threat-weight-value"
}

def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)

def add_obj(module, connection):

    url = obj_url

    payload1 = {}
    payload1['data'] = module.params
    payload1['data'].pop('action')
    replace_key(payload1['data'], rep_dict)

    code, response = connection.send_request(url, payload1)
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
    if 'id' in module.params and module.params['id'] is not None:
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

def param_check(module, connection):
    res = True
    action = module.params['action']
    err_msg = ''

    if (action == 'add' or action == 'edit' or action == 'delete') and module.params['name'] is None:
        err_msg = 'name need to set'
        res = False
    for weight in ['dos_threat_weight', 'spam_threat_weight', 'trojan_threat_weight', 'scanner_threat_weight', 'crawler_threat_weight', 'known_engines_threat_weight', 'marketing_threat_weight', 'page_preview_threat_weight', 'monitor_threat_weight', 'feed_fetcher_threat_weight', 'likely_good_bot_threat_weight']:
        res, err_msg = value_check(module.params, weight, ['informational', 'low', 'moderate', 'substantial', 'severe', 'critical'])
        if res == False:
            return res, err_msg
    for bot_action in ['dos_action', 'spam_action', 'trojan_action', 'scanner_action', 'crawler_action', 'known_engines_action', 'marketing_action', 'page_preview_action', 'monitor_action', 'feed_fetcher_action', 'likely_good_bot_action']:
        res, err_msg = value_check(module.params, bot_action, ['bypass','alert_deny', 'alert', 'redirect', 'deny_no_log', 'block-period', 'send_http_response'])
        if res == False:
            return res, err_msg
    for bot_severity in ['dos_severity', 'spam_severity', 'trojan_severity', 'scanner_severity', 'crawler_severity', 'known_engines_severity', 'marketing_severity', 'page_preview_severity', 'monitor_severity', 'feed_fetcher_severity', 'likely_good_bot_severity']:
        res, err_msg = value_check(module.params, bot_severity, ['Low','Medium', 'High', 'Info'])
        if res == False:
            return res, err_msg
    for bot_status in ['dos_status', 'spam_status', 'trojan_status', 'scanner_status', 'crawler_status', 'known_engines_status', 'marketing_status', 'page_preview_status', 'monitor_status', 'feed_fetcher_status', 'likely_good_bot_status']:
        res, err_msg = value_check(module.params, bot_status, ['enable','disable'])
        if res == False:
            return res, err_msg
    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
        vdom=dict(type='str'),
        dos_status=dict(type='str'),
        dos_action=dict(type='str'),
        dos_block_period=dict(type='str'),
        dos_severity=dict(type='str'),
        dos_trigger=dict(type='str'),
        dos_threat_weight=dict(type='str'),
        spam_status=dict(type='str'),
        spam_action=dict(type='str'),
        spam_block_period=dict(type='str'),
        spam_severity=dict(type='str'),
        spam_trigger=dict(type='str'),
        spam_threat_weight=dict(type='str'),
        trojan_status=dict(type='str'),
        trojan_action=dict(type='str'),
        trojan_block_period=dict(type='str'),
        trojan_severity=dict(type='str'),
        trojan_trigger=dict(type='str'),
        trojan_threat_weight=dict(type='str'),
        scanner_status=dict(type='str'),
        scanner_action=dict(type='str'),
        scanner_block_period=dict(type='str'),
        scanner_severity=dict(type='str'),
        scanner_trigger=dict(type='str'),
        scanner_threat_weight=dict(type='str'),
        crawler_status=dict(type='str'),
        crawler_action=dict(type='str'),
        crawler_block_period=dict(type='str'),
        crawler_severity=dict(type='str'),
        crawler_trigger=dict(type='str'),
        crawler_threat_weight=dict(type='str'),
        known_engines_status=dict(type='str'),
        known_engines_action=dict(type='str'),
        known_engines_block_period=dict(type='str'),
        known_engines_severity=dict(type='str'),
        known_engines_trigger=dict(type='str'),
        known_engines_threat_weight=dict(type='str'),
        marketing_status=dict(type='str'),
        marketing_action=dict(type='str'),
        marketing_block_period=dict(type='str'),
        marketing_severity=dict(type='str'),
        marketing_trigger=dict(type='str'),
        marketing_threat_weight=dict(type='str'),
        page_preview_status=dict(type='str'),
        page_preview_action=dict(type='str'),
        page_preview_block_period=dict(type='str'),
        page_preview_severity=dict(type='str'),
        page_preview_trigger=dict(type='str'),
        page_preview_threat_weight=dict(type='str'),
        monitor_status=dict(type='str'),
        monitor_action=dict(type='str'),
        monitor_block_period=dict(type='str'),
        monitor_severity=dict(type='str'),
        monitor_trigger=dict(type='str'),
        monitor_threat_weight=dict(type='str'),
        feed_fetcher_status=dict(type='str'),
        feed_fetcher_action=dict(type='str'),
        feed_fetcher_block_period=dict(type='str'),
        feed_fetcher_severity=dict(type='str'),
        feed_fetcher_trigger=dict(type='str'),
        feed_fetcher_threat_weight=dict(type='str'),
        likely_good_bot_status=dict(type='str'),
        likely_good_bot_action=dict(type='str'),
        likely_good_bot_block_period=dict(type='str'),
        likely_good_bot_severity=dict(type='str'),
        likely_good_bot_trigger=dict(type='str'),
        likely_good_bot_threat_weight=dict(type='str'),
        sz_malicious_bot_disable_list=dict(type='str'),
        sz_known_good_bots_disable_list=dict(type='str'),
        exception=dict(type='str'),
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

            