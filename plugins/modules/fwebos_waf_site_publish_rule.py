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
module: fwebos_waf_site_publish_rule
description:
  - Config FortiWeb Published Site Policy
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
    published_site:
        description:
            - Name of Published Site.
        type: string
    published_site_type:
        description:
            - Published Site Type. Simple string ('plain') or regular expression ('regular').
        type: string
        choices:
            - 'plain'
            - 'regular'
    path:
        description:
            - Path of Published Site.
        type: string
    account_lockout:
        description:
            - Enable or disable Account Lockout.
        type: string
        choices:
            - 'enable'
            - 'disable'
    cookieless:
        description:
            - Enable or disable cookieless.
        type: string
        choices:
            - 'enable'
            - 'disable'
    max_login_failures:
        description:
            - Max Login Failures. Only available when 'account_lockout' is enabled. (range: 1-30)
        type: integer
    within:
        description:
            - The number of minutes allowing max login login failures. Only available when 'account_lockout' is enabled. (range: 1-30)
        type: integer
    account_block_period:
        description:
            - Account Block Period. Only available when 'account_lockout' is enabled. (range: 1-3600)
        type: integer
    limit_users:
        description:
            - Enable or disable Limit Concurrent Users Per Account.
        type: string
        choices:
            - 'enable'
            - 'disable'
    maximum_users:
        description:
            - Maximum Concurrent Users. Only available when 'limit_users' is enabled. (range: 1-128)
        type: integer
    session_idle_timeout:
        description:
            - Session Idle Timeout (Unit: minute). Only available when 'limit_users' is enabled. (range: 1-1440)
        type: integer
    credential_stuffing_online_query:
        description:
            - Enable or disable Credential Stuffing Defense.
        type: string
        choices:
            - 'enable'
            - 'disable'
    credential_stuffing_protection:
        description:
            - Enable or disable Credential Stuffing Online Check.
        type: string
        choices:
            - 'enable'
            - 'disable'
    match_type:
        description:
            - Select Match type.
        type: string
        choices:
            - 'any'
            - 'all'
    security_action:
        description:
            - Choose the action FortiWeb takes when a rule is violated.
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    block_period:
        description:
            - Block Period. Only available when 'security_action' is 'block-period'. (range: 1-30)
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
    client_auth_method:
        description:
            - Client Authentication Method. Only available when 'cookieless' is enabled.
        type: string
        choices:
            - 'html-form-auth'
            - 'http-auth'
            - 'client-cert-auth'
            - 'saml-auth'
            - 'oauth-auth'
            - 'ntlm-auth'
    cookie_timeout:
        description:
            - Authentication Cookie Timeout. (range: 1-216000)
        type: integer
    redirect_url:
        description:
            - Redirect URL After Authentication (Optional).
        type: string
    sso_support:
        description:
            - SSO Support.
        type: string
        choices:
            - 'enable'
            - 'disable'
    sso_domain:
        description:
            - SSO Domain. Only available when 'sso_support' is enabled.
        type: string
    auth_server-pool:
        description:
            - Authentication Server Pool. Only available when 'client_auth_method' is 'html-form-auth'.
        type: string
    auth_delegation:
        description:
            - Authentication Delegation.
        type: string
        choices:
            - 'no-delegation'
            - 'kerberos'
            - 'ntlm'
            - 'form-based-delegation'
            - 'kerberos-constrained-delegation'
            - 'radius-constrained-delegation'
    form_based_delegation:
        description:
            - Form based delegation. Only available when 'client_auth_method' is 'html-form-auth' and 'auth_delegation' is 'form-based-delegation'.
        type: string
    ntlm-server:
        description:
            - NTLM Server. Only available when 'client_auth_method' is 'ntlm-auth'.
        type: string
    alert-type:
        description:
            - Select Alert Type.
        type: string
        choices:
            - 'fail (Failed Only)'
            - 'success (successful Only)'
            - 'none'
            - 'all'
"""

EXAMPLES = """
    - name: add a site_publish rule
      fwebos_waf_site_publish_rule:
        action: add
        name: spr_test
        published_site: testsite.com
        published_site_type: plain
        status: enable
        cookieless: disable
        cookieless_cache: 3600
        client_auth_method: html-form-auth
        auth_server_pool: asp1
        auth_delegation: no-delegation
        sso_support: enable
        sso_domain: domin1
        prefix_support: enable
        prefix_domain: prefix1
        path: /path1/path2/*
        alert_type: fail
        logoff_path_type: plain
        Published_Server_Logoff_Path: /abc/efg
        cookie_timeout: 222
        csrf_enhancement: enable
        append_custom_header: enable
        pass_failed_auth: enable
        cache_tgs_ticket: enable

    - name: get a site_publish rule
      fwebos_waf_site_publish_rule:
        action: get
        name: spr_test

    - name: edit a site_publish rule
      fwebos_waf_site_publish_rule:
        action: edit
        name: spr_test
        published_site: testsite1.com
        published_site_type: plain
        status: enable
        client_auth_method: http-auth

    - name: delete a site_publish rule
      fwebos_waf_site_publish_rule:
        action: delete
        name: spr_test

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

obj_url = '/api/v2.0/cmdb/waf/site-publish-helper.rule'


rep_dict = {
    "published_site": "published-site",
    "published_site_type": "req-type",
    "cookieless_cache": "cookieless-cache",
    "client_auth_method": "client-auth-method",
    "client_auth_method_val": "client-auth-method_val",
    "auth_server_pool": "auth-server-pool",
    "saml_server_pool": "saml-server-pool",
    "oauth_spool": "oauth-spool",
    "ntlm_server": "ntlm-server",
    "auth_delegation": "auth-delegation",
    "form_based_delegation": "form-based-delegation",
    "radius_server_val": "radius-server_val",
    "delegation_mode_val": "delegation-mode_val",
    "service_principal_name_pool_val": "service-principal-name-pool_val",
    "sso_support": "sso-support",
    "sso_support_val": "sso-support_val",
    "sso_domain": "sso-domain",
    "prefix_support": "prefix-support",
    "prefix_support_val": "prefix-support_val",
    "prefix_domain": "prefix-domain",
    "alert_type": "alert-type",
    "alert_type_val": "alert-type_val",
    "logoff_path_type": "logoff-path-type",
    "Published_Server_Logoff_Path": "Published-Server-Logoff-Path",
    "redirect_url": "redirect-url",
    "cookie_timeout": "cookie-timeout",
    "csrf_enhancement": "csrf-enhancement",
    "append_custom_header": "append-custom-header",
    "pass_failed_auth": "pass-failed-auth",
    "cache_tgs_ticket": "cache-tgs-ticket",
    "sz_custom_headers": "sz_custom-headers",
    "delegated_spn": "delegated-spn",
    "delegation_mode": "delegation-mode",
    "single_server": "single-server",
    "delegator_spn": "delegator-spn",
}

def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)

def add_obj(module, connection):

    name = module.params['name']

    url = obj_url + '?mkey=' + name

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
    res, err_msg = value_check(module.params, 'published_site_type', ['plain', 'regular'])
    if res == False:
        return res, err_msg
    res, err_msg = value_check(module.params, 'csrf_enhancement', ['enable', 'disable'])
    if res == False:
        return res, err_msg
    res, err_msg = value_check(module.params, 'append_custom_header', ['enable', 'disable'])
    if res == False:
        return res, err_msg
    res, err_msg = value_check(module.params, 'pass_failed_auth', ['enable', 'disable'])
    if res == False:
        return res, err_msg
    res, err_msg = value_check(module.params, 'cache_tgs_ticket', ['enable', 'disable'])
    if res == False:
        return res, err_msg
    res, err_msg = value_check(module.params, 'prefix_support', ['enable', 'disable'])
    if res == False:
        return res, err_msg
    res, err_msg = value_check(module.params, 'sso_support', ['enable', 'disable'])
    if res == False:
        return res, err_msg
    res, err_msg = value_check(module.params, 'client_auth_method', ['html-form-auth', 'http-auth', 'client-cert-auth', 'saml-auth', 'oauth-auth', 'ntlm-auth'])
    if res == False:
        return res, err_msg
    res, err_msg = value_check(module.params, 'auth_delegation', ['no-delegation', 'kerberos-constrained-delegation', 'kerberos', 'ntlm', 'form-based-delegation','kerberos-constrained-delegation','radius-constrained-delegation'])
    if res == False:
        return res, err_msg
    res, err_msg = value_check(module.params, 'delegation_mode', ['single-server', 'server-pool'])
    if res == False:
        return res, err_msg
    res, err_msg = value_check(module.params, 'logoff_path_type', ['plain', 'regular'])
    if res == False:
        return res, err_msg
    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        name=dict(type='str'),
        vdom=dict(type='str'),
        published_site=dict(type='str'),
        published_site_type=dict(type='str'),
        status=dict(type='str'),
        cookieless=dict(type='str'),
        cookieless_cache=dict(type='str'),
        client_auth_method=dict(type='str'),
        auth_server_pool=dict(type='str'),
        ntlm_server=dict(type='str'),
        oauth_spool=dict(type='str'),
        saml_server_pool=dict(type='str'),
        auth_delegation=dict(type='str'),
        form_based_delegation=dict(type='str'),
        delegated_spn=dict(type='str'),
        delegation_mode=dict(type='str'),
        single_server=dict(type='str'),
        delegator_spn=dict(type='str'),
        sso_support=dict(type='str'),
        sso_domain=dict(type='str'),
        prefix_support=dict(type='str'),
        prefix_domain=dict(type='str'),
        path=dict(type='str'),
        alert_type=dict(type='str'),
        logoff_path_type=dict(type='str'),
        Published_Server_Logoff_Path=dict(type='str'),
        redirect_url=dict(type='str'),
        cookie_timeout=dict(type='str'),
        csrf_enhancement=dict(type='str'),
        append_custom_header=dict(type='str'),
        pass_failed_auth=dict(type='str'),
        cache_tgs_ticket=dict(type='str'),
        sz_custom_headers=dict(type='str'),
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