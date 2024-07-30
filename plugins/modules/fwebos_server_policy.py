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
module: fwebos_server_policy
description:
  - Configure FortiWeb devices via RESTful APIs
"""

EXAMPLES = """
"""

RETURN = """
"""

obj_url = '/api/v2.0/cmdb/server-policy/policy'


rep_dict = {
    'retry_on_connect_failure': 'retry-on-connect-failure',
    'client_certificate_forwarding': 'client-certificate-forwarding',
    'client_real_ip': 'client-real-ip',
    'urlcert_hlen': 'urlcert-hlen',
    'hsts_max_age': 'hsts-max-age',
    'tls13_custom_cipher': 'tls13-custom-cipher',
    'hsts_preload': 'hsts-preload',
    'sni_strict': 'sni-strict',
    'client_certificate_forwarding_cert_header': 'client-certificate-forwarding-cert-header',
    'retry_times_on_connect_failure': 'retry-times-on-connect-failure',
    'ssl_cipher': 'ssl-cipher',
    'traffic_mirror_type': 'traffic-mirror-type',
    'multi_certificate': 'multi-certificate',
    'hsts_header': 'hsts-header',
    'monitor_mode': 'monitor-mode',
    'deployment_mode': 'deployment-mode',
    'tls_v13': 'tls-v13',
    'tls_v10': 'tls-v10',
    'tls_v11': 'tls-v11',
    'proxy_protocol': 'proxy-protocol',
    'real_ip_addr': 'real-ip-addr',
    'ssl_custom_cipher': 'ssl-custom-cipher',
    'retry_on_cache_size': 'retry-on-cache-size',
    'http_to_https': 'http-to-https',
    'hsts_include_subdomains': 'hsts-include-subdomains',
    'half_open_threshold': 'half-open-threshold',
    'retry_on_http_layer': 'retry-on-http-layer',
    'traffic_mirror': 'traffic-mirror',
    'client_certificate_forwarding_sub_header': 'client-certificate-forwarding-sub-header',
    'web_cache': 'web-cache',
    'ssl_noreg': 'ssl-noreg',
    'retry_on_http_response_codes': 'retry-on-http-response-codes',
    'prefer_current_session': 'prefer-current-session',
    'retry_times_on_http_layer': 'retry-times-on-http-layer',
    'case_sensitive': 'case-sensitive',
    'server_pool': 'server-pool',
    'retry_on': 'retry-on',
    'tls_v12': 'tls-v12',
    'https_service': 'https-service',
    'certificate_type': 'certificate-type',
    'http2_custom_cipher': 'http2-custom-cipher',
    'lets_certificate': 'lets-certificate',
    'certificate_group': 'certificate-group',
    'intermediate_certificate_group': 'intermediate-certificate-group',
    'web_protection_profile': 'web-protection-profile',
    'allow_hosts': 'allow-hosts',
    'chunk_encoding': 'chunk-encoding',
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
        retry_on_connect_failure=dict(type='str'),
        protocol=dict(type='str'),
        client_certificate_forwarding=dict(type='str'),
        client_real_ip=dict(type='str'),
        urlcert_hlen=dict(type='int'),
        hsts_max_age=dict(type='int'),
        tls13_custom_cipher=dict(type='str'),
        urlcert=dict(type='str'),
        syncookie=dict(type='str'),
        service=dict(type='str'),
        hsts_preload=dict(type='str'),
        sni_strict=dict(type='str'),
        client_certificate_forwarding_cert_header=dict(type='str'),
        retry_times_on_connect_failure=dict(type='int'),
        ssl_cipher=dict(type='str'),
        traffic_mirror_type=dict(type='str'),
        multi_certificate=dict(type='str'),
        hsts_header=dict(type='str'),
        monitor_mode=dict(type='str'),
        deployment_mode=dict(type='str'),
        tls_v13=dict(type='str'),
        tls_v10=dict(type='str'),
        tls_v11=dict(type='str'),
        proxy_protocol=dict(type='str'),
        vserver=dict(type='str'),
        real_ip_addr=dict(type='str'),
        ssl_custom_cipher=dict(type='str'),
        retry_on_cache_size=dict(type='int'),
        http_to_https=dict(type='str'),
        hsts_include_subdomains=dict(type='str'),
        half_open_threshold=dict(type='int'),
        retry_on_http_layer=dict(type='str'),
        traffic_mirror=dict(type='str'),
        client_certificate_forwarding_sub_header=dict(type='str'),
        sni=dict(type='str'),
        ssl=dict(type='str'),
        web_cache=dict(type='str'),
        ssl_noreg=dict(type='str'),
        retry_on_http_response_codes=dict(type='str'),
        prefer_current_session=dict(type='str'),
        retry_times_on_http_layer=dict(type='int'),
        case_sensitive=dict(type='str'),
        name=dict(type='str'),
        replacemsg=dict(type='str'),
        server_pool=dict(type='str'),
        retry_on=dict(type='str'),
        tls_v12=dict(type='str'),
        https_service=dict(type='str'),
        http2=dict(type='str'),
        certificate_type=dict(type='str'),
        http2_custom_cipher=dict(type='str'),
        certificate=dict(type='str'),
        intermediate_certificate_group=dict(type='str'),
        certificate_group=dict(type='str'),
        lets_certificate=dict(type='str'),
        web_protection_profile=dict(type='str'),
        allow_hosts=dict(type='str'),
        comment=dict(type='str'),
        tlog=dict(type='str'),
        chunk_encoding=dict(type='str'),
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
