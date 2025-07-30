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
module: fwebos_server_policy
description:
  - Config FortiWeb Policy Server Policy
version_added: "7.0.0"
authors:
  - Jie Li
  - Brad Zhang
requirements:
    - ansible>=2.11
options:
    name:
        description:
            - policy name
        type: string
    deployment-mode:
        description:
            - deployment mode
        type: string
        choices:
            - 'server-pool'
            - 'http-content-routing'
            - 'offline-protection'
            - 'transparent-servers'
            - 'wccp-servers'
    protocol:
        description:
            - protocol
        type: string
        choices:
            - 'HTTP'
            - 'FTP'
            - 'ADFSPIP'
            - 'TCPPROXY'
    ssl:
        description:
            - ssl switch
        type: string
        choices:
            - 'enable'
            - 'disable'
    implicit_ssl:
        description:
            - implicit ssl switch
        type: string
        choices:
            - 'enable'
            - 'disable'
    proxy-protocol:
        description:
            - policy proxy protocol switch
        type: string
        choices:
            - 'enable'
            - 'disable'
    use-proxy-protocol-addr:
        description:
            - use addr from proxy protocol for security checking
        type: string
        choices:
            - 'enable'
            - 'disable'
    traffic-mirror:
        description:
            - traffic mirror switch
        type: string
        choices:
            - 'enable'
            - 'disable'
    traffic-mirror-type:
        description:
            - traffic mirror type
        type: string
        choices:
            - 'client-side'
            - 'server-side'
            - 'both-side'
    multi-certificate:
        description:
            - enable multi certificate
        type: string
        choices:
            - 'enable'
            - 'disable'
    send-buffers-number:
        description:
            - the number of the send buffers used for forwarding data, range 0-256, 0 means no limit, each buffer size is 4kB (range: 0-256)
        type: integer
    certificate-type:
        description:
            - enable letsencrypt certificate
        type: string
        choices:
            - 'enable'
            - 'disable'
    use-ciphers-group:
        description:
            - use SSL ciphers group or not
        type: string
        choices:
            - 'enable'
            - 'disable'
    tls-v10:
        description:
            - TLS 1.0 protocol status
        type: string
        choices:
            - 'enable'
            - 'disable'
    tls-v11:
        description:
            - TLS 1.1 protocol status
        type: string
        choices:
            - 'enable'
            - 'disable'
    tls-v12:
        description:
            - TLS 1.2 protocol status
        type: string
        choices:
            - 'enable'
            - 'disable'
    tls-v13:
        description:
            - TLS 1.3 protocol status
        type: string
        choices:
            - 'enable'
            - 'disable'
    ssl-noreg:
        description:
            - SSL no renegotiate
        type: string
        choices:
            - 'enable'
            - 'disable'
    ssl-cipher:
        description:
            - SSL cipher-suite
        type: string
        choices:
            - 'medium'
            - 'high'
            - 'custom'
    ssl-custom-cipher:
        description:
            - SSL custom cipher-suite
        type: string
        choices:
            - 'ECDHE-ECDSA-AES256-GCM-SHA384'
            - 'ECDHE-RSA-AES256-GCM-SHA384'
            - 'DHE-DSS-AES256-GCM-SHA384'
            - 'DHE-RSA-AES256-GCM-SHA384'
            - 'ECDHE-ECDSA-CHACHA20-POLY1305'
            - 'ECDHE-RSA-CHACHA20-POLY1305'
            - 'DHE-RSA-CHACHA20-POLY1305'
            - 'ECDHE-ECDSA-AES256-CCM8'
            - 'ECDHE-ECDSA-AES256-CCM'
            - 'DHE-RSA-AES256-CCM8'
            - 'DHE-RSA-AES256-CCM'
            - 'ECDHE-ECDSA-AES128-GCM-SHA256'
            - 'ECDHE-RSA-AES128-GCM-SHA256'
            - 'DHE-DSS-AES128-GCM-SHA256'
            - 'DHE-RSA-AES128-GCM-SHA256'
            - 'ECDHE-ECDSA-AES128-CCM8'
            - 'ECDHE-ECDSA-AES128-CCM'
            - 'DHE-RSA-AES128-CCM8'
            - 'DHE-RSA-AES128-CCM'
            - 'ECDHE-ECDSA-AES256-SHA384'
            - 'ECDHE-RSA-AES256-SHA384'
            - 'DHE-RSA-AES256-SHA256'
            - 'DHE-DSS-AES256-SHA256'
            - 'ECDHE-ECDSA-CAMELLIA256-SHA384'
            - 'ECDHE-RSA-CAMELLIA256-SHA384'
            - 'DHE-RSA-CAMELLIA256-SHA256'
            - 'DHE-DSS-CAMELLIA256-SHA256'
            - 'ECDHE-ECDSA-AES128-SHA256'
            - 'ECDHE-RSA-AES128-SHA256'
            - 'DHE-RSA-AES128-SHA256'
            - 'DHE-DSS-AES128-SHA256'
            - 'ECDHE-ECDSA-CAMELLIA128-SHA256'
            - 'ECDHE-RSA-CAMELLIA128-SHA256'
            - 'DHE-RSA-CAMELLIA128-SHA256'
            - 'DHE-DSS-CAMELLIA128-SHA256'
            - 'ECDHE-ECDSA-AES256-SHA'
            - 'ECDHE-RSA-AES256-SHA'
            - 'DHE-RSA-AES256-SHA'
            - 'DHE-DSS-AES256-SHA'
            - 'DHE-RSA-CAMELLIA256-SHA'
            - 'DHE-DSS-CAMELLIA256-SHA'
            - 'ECDHE-ECDSA-AES128-SHA'
            - 'ECDHE-RSA-AES128-SHA'
            - 'DHE-RSA-AES128-SHA'
            - 'DHE-DSS-AES128-SHA'
            - 'ECDHE-ARIA128-GCM-SHA256'
            - 'DHE-RSA-ARIA128-GCM-SHA256'
            - 'AES256-GCM-SHA384'
            - 'AES256-CCM8'
            - 'AES256-CCM'
            - 'AES128-GCM-SHA256'
            - 'AES128-CCM8'
            - 'AES128-CCM'
            - 'AES256-SHA256'
            - 'CAMELLIA256-SHA256'
            - 'AES128-SHA256'
            - 'CAMELLIA128-SHA256'
            - 'AES256-SHA'
            - 'DHE-RSA-ARIA256-GCM-SHA384'
            - 'AES128-SHA'
            - 'ECDHE-ARIA256-GCM-SHA384'
            - 'DHE-RSA-SEED-SHA'
            - 'ECDHE-RSA-DES-CBC3-SHA'
            - 'DES-CBC3-SHA'
    tls13-custom-cipher:
        description:
            - TLSv1.3 custom cipher-suite
        type: string
        choices:
            - 'TLS_AES_256_GCM_SHA384'
            - 'TLS_CHACHA20_POLY1305_SHA256'
            - 'TLS_AES_128_GCM_SHA256'
            - 'TLS_AES_128_CCM_SHA256'
            - 'TLS_AES_128_CCM_8_SHA256'
    sni:
        description:
            - SNI status
        type: string
        choices:
            - 'enable'
            - 'disable'
    sni-strict:
        description:
            - strict SNI mode
        type: string
        choices:
            - 'enable'
            - 'disable'
    urlcert:
        description:
            - URL based client certificate
        type: string
        choices:
            - 'enable'
            - 'disable'
    urlcert-hlen:
        description:
            - URL based client certificate max http request length if matched(16-10240K) (range: 16-10240)
        type: integer
    case-sensitive:
        description:
            - case sensitive
        type: string
        choices:
            - 'enable'
            - 'disable'
    status:
        description:
            - status: enable/disable
        type: string
        choices:
            - 'enable'
            - 'disable'
    comment:
        description:
            - comment
        type: string
    noparse:
        description:
            - Enable pure proxy or not: enable/disable
        type: string
        choices:
            - 'enable'
            - 'disable'
    monitor-mode:
        description:
            - Monitor mode: enable/disable
        type: string
        choices:
            - 'enable'
            - 'disable'
    web-cache:
        description:
            - WEB cache mode: enable/disable
        type: string
        choices:
            - 'enable'
            - 'disable'
    http-to-https:
        description:
            - Redirect naked domain request to "www" domain requests: enable/disable
        type: string
        choices:
            - 'enable'
            - 'disable'
    redirect_naked_domain:
        description:
            - Redirect HTTP to HTTPs: enable/disable
        type: string
        choices:
            - 'enable'
            - 'disable'
    sessioncookie-enforce:
        description:
            - Enforce session cookie per transaction
        type: string
        choices:
            - 'enable'
            - 'disable'
    syncookie:
        description:
            - syn cookie: enable/disable
        type: string
        choices:
            - 'enable'
            - 'disable'
    half-open-threshold:
        description:
            - half-open threshold (10~10000) (range: 10-10000)
        type: integer
    client-certificate-forwarding:
        description:
            - client certificate forwarding: enable/disable
        type: string
        choices:
            - 'enable'
            - 'disable'
    client-certificate-forwarding-sub-header:
        description:
            - custom header of client certificate forwarding subject
        type: string
    client-certificate-forwarding-cert-header:
        description:
            - custom header of client certificate forwarding certificate
        type: string
    http-pipeline:
        description:
            - HTTP pipeline support: enable/disable
        type: string
        choices:
            - 'enable'
            - 'disable'
    hsts-header:
        description:
            - hsts header support
        type: string
        choices:
            - 'enable'
            - 'disable'
    hsts-max-age:
        description:
            - max age value(unit: second, 1 hour-1 year) (range: 3600-31536000)
        type: integer
    hsts-include-subdomains:
        description:
            - hsts include subdomains
        type: string
        choices:
            - 'enable'
            - 'disable'
    hsts-preload:
        description:
            - hsts preload
        type: string
        choices:
            - 'enable'
            - 'disable'
    prefer-current-session:
        description:
            - prefer current session
        type: string
        choices:
            - 'enable'
            - 'disable'
    client-real-ip:
        description:
            - keep client real ip to server
        type: string
        choices:
            - 'enable'
            - 'disable'
    http2:
        description:
            - set http2 enable/disable
        type: string
        choices:
            - 'enable'
            - 'disable'
    tcp-recv-timeout:
        description:
            - max age value(unit: second) of the first http request after tcp handshake (range: 0-300)
        type: integer
    http-header-timeout:
        description:
            - max age value(unit: second) of receiving a successful http header (range: 0-1200)
        type: integer
    tcp-conn-timeout:
        description:
            - max age value(unit: second) of TCP connection timeout (range: 0-600)
        type: integer
    internal-cookie-httponly:
        description:
            - internal cookie http only: enable/disable
        type: string
        choices:
            - 'enable'
            - 'disable'
    internal-cookie-secure:
        description:
            - internal cookie secure: enable/disable
        type: string
        choices:
            - 'enable'
            - 'disable'
    internal-cookie-samesite:
        description:
            - internal cookie samesite: enable/disable
        type: string
        choices:
            - 'enable'
            - 'disable'
    internal-cookie-samesite-value:
        description:
            - internal cookie samesite value
        type: string
        choices:
            - 'strict'
            - 'lax'
            - 'none'
    content-security-policy-inline:
        description:
            - content security policy inline: enable/disable
        type: string
        choices:
            - 'enable'
            - 'disable'
    ssl-quiet-shutdown:
        description:
            - enable/disable SSL quiet Shutdown
        type: string
        choices:
            - 'enable'
            - 'disable'
    ssl-session-timeout:
        description:
            - ssl session timeout setting, default value 7200s, range (1, 14400) (range: 1-14400)
        type: integer
    client-timeout:
        description:
            - max age value(unit: second):Prevent front end connection from closing for a long time, especially when multiplexing function is turned on (range: 0-1200)
        type: integer
    retry-on:
        description:
            - enable/disable retry on
        type: string
        choices:
            - 'enable'
            - 'disable'
    retry-on-cache-size:
        description:
            - the http request cache size when retry on(32~2048 kB) (range: 32-2048)
        type: integer
    retry-on-connect-failure:
        description:
            - enable/disable retry on connect failure
        type: string
        choices:
            - 'enable'
            - 'disable'
    retry-times-on-connect-failure:
        description:
            - retry times on connect failure, range 1-5 (range: 1-5)
        type: integer
    retry-on-http-layer:
        description:
            - enable/disable retry on http layer, only HEAD/GET methods supported
        type: string
        choices:
            - 'enable'
            - 'disable'
    retry-times-on-http-layer:
        description:
            - retry times on http layer, range 1-5 (range: 1-5)
        type: integer
    retry-on-http-response-codes:
        description:
            - http response codes
        type: string
        choices:
            - '404'
            - '408'
            - '500'
            - '501'
            - '502'
            - '503'
            - '504'
    replacemsg-on-connect-failure:
        description:
            - enable/disable sending replacemsg to client on connect failure
        type: string
        choices:
            - 'enable'
            - 'disable'
    chunk-encoding:
        description:
            - chunk-encoding
        type: string
        choices:
            - 'enable'
            - 'disable'
    tlog:
        description:
            - tlog: enable/disable
        type: string
        choices:
            - 'enable'
            - 'disable'
    web-cache-storage:
        description:
            - Web Cache Storage
        type: string
        choices:
            - 'redis-db'
            - 'hash-table'
    scripting:
        description:
            - enable/disable policy scripting
        type: string
        choices:
            - 'enable'
            - 'disable'
"""

EXAMPLES = """
     - name: Create
       fwebos_server_policy:
        action: add
        vdom: root
        retry_on_connect_failure: disable
        protocol: HTTP
        client_certificate_forwarding: disable
        client_real_ip: disable
        urlcert_hlen: 32
        hsts_max_age: 15552000
        tls13_custom_cipher: TLS_AES_256_GCM_SHA384
        urlcert: disable
        syncookie: disable
        service: HTTP
        hsts_preload: disable
        sni_strict: disable
        client_certificate_forwarding_cert_header: X-Client-Cert
        retry_times_on_connect_failure: 3
        ssl_cipher: medium
        traffic_mirror_type: client-side
        multi_certificate: enable
        hsts_header: disable
        monitor_mode: disable
        deployment_mode: server-pool
        tls_v13: disable
        tls_v10: enable
        tls_v11: enable
        proxy_protocol: disable
        vserver: test4
        real_ip_addr:
        ssl_custom_cipher: ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-GCM-SHA384 ECDHE-ECDSA-CHACHA20-POLY1305 ECDHE-RSA-CHACHA20-POLY1305 ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-RSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-SHA384 ECDHE-RSA-AES256-SHA384 ECDHE-ECDSA-AES128-SHA256 ECDHE-RSA-AES128-SHA256 ECDHE-ECDSA-AES256-SHA ECDHE-RSA-AES256-SHA ECDHE-ECDSA-AES128-SHA ECDHE-RSA-AES128-SHA AES256-GCM-SHA384 AES128-GCM-SHA256 AES256-SHA256 AES128-SHA256
        retry_on_cache_size: 512
        http_to_https: disable
        hsts_include_subdomains: disable
        half_open_threshold: 8192
        retry_on_http_layer: disable
        traffic_mirror: disable
        client_certificate_forwarding_sub_header: X-Client-DN
        sni: disable
        ssl: enable
        web_cache: disable
        ssl_noreg: enable
        retry_on_http_response_codes: 404 408 500 501 502 503 504
        prefer_current_session: disable
        retry_times_on_http_layer: 3
        case_sensitive: disable
        name: test4
        replacemsg: Predefined
        server_pool: test4
        retry_on: disable
        tls_v12: enable
        https_service: HTTPS
        http2: disable
        certificate_type: disable
        http2_custom_cipher: ECDHE-ECDSA-AES256-GCM-SHA384 DHE-DSS-AES128-GCM-SHA256 DHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES256-GCM-SHA384
        web_protection_profile: Inline Standard Protection
        certificate_group: test
        allow_hosts: test.com
        intermediate_certificate_group: test
        comment: test111
        tlog: disable
        chunk_encoding: enable

     - name: edit
       fwebos_server_policy:
        action: edit
        vdom: root
        retry_on_connect_failure: disable
        protocol: HTTP
        client_certificate_forwarding: disable
        client_real_ip: disable
        urlcert_hlen: 32
        hsts_max_age: 15552000
        tls13_custom_cipher: TLS_AES_256_GCM_SHA384
        urlcert: disable
        syncookie: disable
        service: HTTP
        hsts_preload: disable
        sni_strict: disable
        client_certificate_forwarding_cert_header: X-Client-Cert
        retry_times_on_connect_failure: 3
        ssl_cipher: medium
        traffic_mirror_type: client-side
        multi_certificate: disable
        hsts_header: disable
        monitor_mode: disable
        deployment_mode: server-pool
        tls_v13: disable
        tls_v10: enable
        tls_v11: enable
        proxy_protocol: disable
        vserver: test4
        real_ip_addr:
        ssl_custom_cipher: ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-GCM-SHA384 ECDHE-ECDSA-CHACHA20-POLY1305 ECDHE-RSA-CHACHA20-POLY1305 ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-RSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-SHA384 ECDHE-RSA-AES256-SHA384 ECDHE-ECDSA-AES128-SHA256 ECDHE-RSA-AES128-SHA256 ECDHE-ECDSA-AES256-SHA ECDHE-RSA-AES256-SHA ECDHE-ECDSA-AES128-SHA ECDHE-RSA-AES128-SHA AES256-GCM-SHA384 AES128-GCM-SHA256 AES256-SHA256 AES128-SHA256
        retry_on_cache_size: 512
        http_to_https: disable
        hsts_include_subdomains: disable
        half_open_threshold: 8192
        retry_on_http_layer: disable
        traffic_mirror: disable
        client_certificate_forwarding_sub_header: X-Client-DN
        sni: disable
        ssl: enable
        web_cache: disable
        ssl_noreg: enable
        retry_on_http_response_codes: 404 408 500 501 502 503 504
        prefer_current_session: disable
        retry_times_on_http_layer: 3
        case_sensitive: disable
        name: test4
        replacemsg: Predefined
        server_pool: test4
        retry_on: disable
        tls_v12: enable
        https_service: HTTPS
        http2: disable
        certificate_type: enable
        http2_custom_cipher: ECDHE-ECDSA-AES256-GCM-SHA384 DHE-DSS-AES128-GCM-SHA256 DHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES256-GCM-SHA384
        web_protection_profile: Inline Standard Protection
        lets_certificate: test
        allow_hosts: test.com
        intermediate_certificate_group: test
        comment: test111
        tlog: enable
        chunk_encoding: enable

     - name: edit
       fwebos_server_policy:
        action: edit
        vdom: root
        retry_on_connect_failure: disable
        protocol: HTTP
        client_certificate_forwarding: disable
        client_real_ip: disable
        urlcert_hlen: 32
        hsts_max_age: 15552000
        tls13_custom_cipher: TLS_AES_256_GCM_SHA384
        urlcert: disable
        syncookie: disable
        service: HTTP
        hsts_preload: disable
        sni_strict: disable
        client_certificate_forwarding_cert_header: X-Client-Cert
        retry_times_on_connect_failure: 3
        ssl_cipher: medium
        traffic_mirror_type: client-side
        multi_certificate: disable
        hsts_header: disable
        monitor_mode: disable
        deployment_mode: server-pool
        tls_v13: disable
        tls_v10: enable
        tls_v11: enable
        proxy_protocol: disable
        vserver: test4
        real_ip_addr:
        ssl_custom_cipher: ECDHE-ECDSA-AES256-GCM-SHA384 ECDHE-RSA-AES256-GCM-SHA384 ECDHE-ECDSA-CHACHA20-POLY1305 ECDHE-RSA-CHACHA20-POLY1305 ECDHE-ECDSA-AES128-GCM-SHA256 ECDHE-RSA-AES128-GCM-SHA256 ECDHE-ECDSA-AES256-SHA384 ECDHE-RSA-AES256-SHA384 ECDHE-ECDSA-AES128-SHA256 ECDHE-RSA-AES128-SHA256 ECDHE-ECDSA-AES256-SHA ECDHE-RSA-AES256-SHA ECDHE-ECDSA-AES128-SHA ECDHE-RSA-AES128-SHA AES256-GCM-SHA384 AES128-GCM-SHA256 AES256-SHA256 AES128-SHA256
        retry_on_cache_size: 512
        http_to_https: disable
        hsts_include_subdomains: disable
        half_open_threshold: 8192
        retry_on_http_layer: disable
        traffic_mirror: disable
        client_certificate_forwarding_sub_header: X-Client-DN
        sni: disable
        ssl: enable
        web_cache: disable
        ssl_noreg: enable
        retry_on_http_response_codes: 404 408 500 501 502 503 504
        prefer_current_session: disable
        retry_times_on_http_layer: 3
        case_sensitive: disable
        name: test4
        replacemsg: Predefined
        server_pool: test4
        retry_on: disable
        tls_v12: enable
        https_service: HTTPS
        http2: disable
        certificate_type: disable
        http2_custom_cipher: ECDHE-ECDSA-AES256-GCM-SHA384 DHE-DSS-AES128-GCM-SHA256 DHE-RSA-AES128-GCM-SHA256 ECDHE-RSA-AES256-GCM-SHA384
        web_protection_profile: Inline Standard Protection
        certificate: aaa1
        allow_hosts: test.com
        intermediate_certificate_group: test
        comment: test111
        tlog: enable
        chunk_encoding: enable

     - name: delete
       fwebos_server_policy:
        action: delete
        name: test4
        vdom: root


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
    'redirect_naked_domain': 'redirect-naked-domain',
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
    'http3_service': 'http3-service',
    'certificate_type': 'certificate-type',
    'http2_custom_cipher': 'http2-custom-cipher',
    'lets_certificate': 'lets-certificate',
    'certificate_group': 'certificate-group',
    'intermediate_certificate_group': 'intermediate-certificate-group',
    'web_protection_profile': 'web-protection-profile',
    'allow_hosts': 'allow-hosts',
    'chunk_encoding': 'chunk-encoding',
    'use-ciphers-group': 'use_ciphers_group',
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
    # # response['sent'] = payload1['data']
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
        http3_service=dict(type='str'),
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
        redirect_naked_domain=dict(type='str'),
        use_ciphers_group=dict(type='str'),
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
