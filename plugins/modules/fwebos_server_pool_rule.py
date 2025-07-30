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
module: fwebos_server_pool_rule
description:
  - Config FortiWeb server objects Server Pool member
version_added: "7.0.0"
authors:
  - Jie Li
  - Brad Zhang
requirements:
    - ansible>=2.11
options:
    http2_ssl_custom_cipher:
        description:
            - SSL custom cipher-suite
        type: str
"""

EXAMPLES = """
     - name: delete
       fwebos_server_pool_rule:
        action: delete
        table_name: test4
        name: 1
        vdom: root

     - name: Create
       fwebos_server_pool_rule:
        action: add
        table_name: test4
        vdom: root
        http2_ssl_custom_cipher: ECDHE-ECDSA-AES256-GCM-SHA384 DHE-DSS-AES128-GCM-SHA256 DHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES256-GCM-SHA384
        weight: 1
        ip: 2.2.2.2
        hsts_max_age: 15552000
        tls13_custom_cipher: TLS_AES_256_GCM_SHA384
        server_type: physical
        proxy_protocol_version: v1
        sni_strict: disable
        recover: 0
        port: 80
        ssl_cipher: medium
        conn_limit: 0
        client_certificate_forwarding_cert_header: X-Client-Cert
        multi_certificate: disable
        hsts_header: disable
        tls_v12: enable
        tls_v13: disable
        tls_v10: enable
        tls_v11: enable
        proxy_protocol: disable
        client_certificate_proxy: disable
        server_side_sni: disable
        ssl_custom_cipher: ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-GCM-SHA384 ECDHE-ECDSA-CHACHA20-POLY1305 ECDHE-RSA-CHACHA20-POLY1305 ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-RSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-SHA384 ECDHE-RSA-AES256-SHA384 ECDHE-ECDSA-AES128-SHA256 ECDHE-RSA-AES128-SHA256 ECDHE-ECDSA-AES256-SHA ECDHE-RSA-AES256-SHA ECDHE-ECDSA-AES128-SHA ECDHE-RSA-AES128-SHA AES256-GCM-SHA384 AES128-GCM-SHA256 AES256-SHA256 AES128-SHA256
        session_id_reuse: disable
        status: enable
        urlcert: disable
        hsts_include_subdomains: disable
        client_certificate_forwarding_sub_header: X-Client-DN
        warm_rate: 10
        server_certificate_verify_action: alert
        sni: disable
        warm_up: 0
        ssl: disable
        ssl_noreg: enable
        health_check_inherit: enable
        session_ticket_reuse: disable
        backup_server: disable
        client_certificate_forwarding: disable
        http2: disable
        hsts_preload: disable
        certificate_type: disable

     - name: edit
       fwebos_server_pool_rule:
        action: edit
        table_name: test4
        name: 1
        vdom: root
        http2_ssl_custom_cipher: ECDHE-ECDSA-AES256-GCM-SHA384 DHE-DSS-AES128-GCM-SHA256 DHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES256-GCM-SHA384
        weight: 1
        ip: 2.2.2.9
        hsts_max_age: 15552000
        tls13_custom_cipher: TLS_AES_256_GCM_SHA384
        server_type: physical
        proxy_protocol_version: v1
        sni_strict: disable
        recover: 0
        port: 80
        ssl_cipher: medium
        conn_limit: 0
        client_certificate_forwarding_cert_header: X-Client-Cert
        multi_certificate: disable
        hsts_header: disable
        tls_v12: enable
        tls_v13: disable
        tls_v10: enable
        tls_v11: enable
        proxy_protocol: disable
        client_certificate_proxy: disable
        server_side_sni: disable
        ssl_custom_cipher: ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-GCM-SHA384 ECDHE-ECDSA-CHACHA20-POLY1305 ECDHE-RSA-CHACHA20-POLY1305 ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-RSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-SHA384 ECDHE-RSA-AES256-SHA384 ECDHE-ECDSA-AES128-SHA256 ECDHE-RSA-AES128-SHA256 ECDHE-ECDSA-AES256-SHA ECDHE-RSA-AES256-SHA ECDHE-ECDSA-AES128-SHA ECDHE-RSA-AES128-SHA AES256-GCM-SHA384 AES128-GCM-SHA256 AES256-SHA256 AES128-SHA256
        session_id_reuse: disable
        status: enable
        urlcert: disable
        hsts_include_subdomains: disable
        client_certificate_forwarding_sub_header: X-Client-DN
        warm_rate: 10
        server_certificate_verify_action: alert
        sni: disable
        warm_up: 0
        ssl: disable
        ssl_noreg: enable
        health_check_inherit: enable
        session_ticket_reuse: disable
        backup_server: disable
        client_certificate_forwarding: disable
        http2: disable
        hsts_preload: disable
        certificate_type: disable


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

obj_url = '/api/v2.0/cmdb/server-policy/server-pool/pserver-list'


rep_dict = {
    'http2_ssl_custom_cipher': 'http2-ssl-custom-cipher',
    'hsts_max_age': 'hsts-max-age',
    'tls13_custom_cipher': 'tls13-custom-cipher',
    'server_type': 'server-type',
    'proxy_protocol_version': 'proxy-protocol-version',
    'sni_strict': 'sni-strict',
    'ssl_cipher': 'ssl-cipher',
    'conn_limit': 'conn-limit',
    'client_certificate_forwarding_cert_header': 'client-certificate-forwarding-cert-header',
    'multi_certificate': 'multi-certificate',
    'hsts_header': 'hsts-header',
    'tls_v12': 'tls-v12',
    'tls_v13': 'tls-v13',
    'tls_v10': 'tls-v10',
    'tls_v11': 'tls-v11',
    'proxy_protocol': 'proxy-protocol',
    'client_certificate_proxy': 'client-certificate-proxy',
    'server_side_sni': 'server-side-sni',
    'ssl_custom_cipher': 'ssl-custom-cipher',
    'session_id_reuse': 'session-id-reuse',
    'hsts_include_subdomains': 'hsts-include-subdomains',
    'client_certificate_forwarding_sub_header': 'client-certificate-forwarding-sub-header',
    'warm_rate': 'warm-rate',
    'server_certificate_verify_action': 'server-certificate-verify-action',
    'warm_up': 'warm-up',
    'ssl_noreg': 'ssl-noreg',
    'health_check_inherit': 'health-check-inherit',
    'session_ticket_reuse': 'session-ticket-reuse',
    'backup_server': 'backup-server',
    'client_certificate_forwarding': 'client-certificate-forwarding',
    'hsts_preload': 'hsts-preload',
    'certificate_type': 'certificate-type',
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
    server_type = module.params['server_type']
    err_msg = ''

    if (action == 'edit' or action == 'delete') and module.params['name'] is None:
        err_msg = 'name need to set'
        res = False
    if (server_type != 'physical' and server_type != 'domain') and action == 'add':
        err_msg = 'server_type need to set physical or domain'
        res = False
    elif server_type == 'domain' and module.params['domain'] is None:
        err_msg = 'domain need to set when server_type is domain'
        res = False
    elif server_type == 'physical' and module.params['ip'] is None:
        err_msg = 'ip need to set when server_type is physical'
        res = False

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        table_name=dict(type='str'),
        name=dict(type='str'),
        http2_ssl_custom_cipher=dict(type='str'),
        weight=dict(type='int'),
        ip=dict(type='str'),
        hsts_max_age=dict(type='int'),
        tls13_custom_cipher=dict(type='str'),
        server_type=dict(type='str'),
        proxy_protocol_version=dict(type='str'),
        sni_strict=dict(type='str'),
        recover=dict(type='int'),
        port=dict(type='int'),
        ssl_cipher=dict(type='str'),
        conn_limit=dict(type='int'),
        client_certificate_forwarding_cert_header=dict(type='str'),
        multi_certificate=dict(type='str'),
        hsts_header=dict(type='str'),
        tls_v12=dict(type='str'),
        tls_v13=dict(type='str'),
        tls_v10=dict(type='str'),
        tls_v11=dict(type='str'),
        proxy_protocol=dict(type='str'),
        client_certificate_proxy=dict(type='str'),
        server_side_sni=dict(type='str'),
        ssl_custom_cipher=dict(type='str'),
        session_id_reuse=dict(type='str'),
        status=dict(type='str'),
        urlcert=dict(type='str'),
        hsts_include_subdomains=dict(type='str'),
        client_certificate_forwarding_sub_header=dict(type='str'),
        warm_rate=dict(type='int'),
        server_certificate_verify_action=dict(type='str'),
        sni=dict(type='str'),
        warm_up=dict(type='int'),
        ssl=dict(type='str'),
        ssl_noreg=dict(type='str'),
        health_check_inherit=dict(type='str'),
        session_ticket_reuse=dict(type='str'),
        backup_server=dict(type='str'),
        client_certificate_forwarding=dict(type='str'),
        http2=dict(type='str'),
        hsts_preload=dict(type='str'),
        certificate_type=dict(type='str'),
        domain=dict(type='str'),
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
