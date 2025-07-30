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
module: fwebos_waf_http_protocol_parameter_restriction
description:
  - Config FortiWeb Web Protection HTTP Constraints
version_added: "7.0.0"
authors:
  - Jie Li
  - Brad Zhang
requirements:
    - ansible>=2.11
options:
    name:
        description:
            - name
        type: string
    max-http-header-length-check:
        description:
            - check
        type: string
        choices:
            - 'enable'
            - 'disable'
    max-http-header-length:
        description:
            - max length of header, default value is 8192 (range: 0-12288)
        type: integer
    max-http-header-length-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    max-http-header-length-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    max-http-header-length-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    max-http-header-length-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    max-http-content-length-check:
        description:
            - check
        type: string
        choices:
            - 'enable'
            - 'disable'
    max-http-content-length:
        description:
            - max length (KB) of content, 0 means this value has not limitation (range: 0-65536)
        type: integer
    max-http-content-length-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    max-http-content-length-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    max-http-content-length-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    max-http-content-length-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    max-http-body-length-check:
        description:
            - check
        type: string
        choices:
            - 'enable'
            - 'disable'
    max-http-body-length:
        description:
            - max length (KB) of body, 0 means this value has not limitation (range: 0-65536)
        type: integer
    max-http-body-length-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    max-http-body-length-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    max-http-body-length-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    max-http-body-length-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    max-http-request-length-check:
        description:
            - check
        type: string
        choices:
            - 'enable'
            - 'disable'
    max-http-request-length:
        description:
            - max length of http request, default value is 2048[0,65536] (KB) (range: 0-65536)
        type: integer
    max-http-request-length-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    max-http-request-length-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    max-http-request-length-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    max-http-request-length-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    max-url-parameter-length-check:
        description:
            - check
        type: string
        choices:
            - 'enable'
            - 'disable'
    max-url-parameter-length:
        description:
            - max length of url parameter, default value is 8192 (range: 0-12288)
        type: integer
    max-url-parameter-length-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    max-url-parameter-length-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    max-url-parameter-length-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    max-url-parameter-length-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    Illegal-http-version-check:
        description:
            - 
        type: string
        choices:
            - 'enable'
            - 'disable'
    Illegal-http-version-check-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    Illegal-http-version-check-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    Illegal-http-version-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    Illegal-http-version-check-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    max-cookie-in-request-check:
        description:
            - check
        type: string
        choices:
            - 'enable'
            - 'disable'
    max-cookie-in-request:
        description:
            - max count of cookie request, default value is 128 [0,1023] (range: 0-1023)
        type: integer
    max-cookie-in-request-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    max-cookie-in-request-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    max-cookie-in-request-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    max-cookie-in-request-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    max-header-line-request-check:
        description:
            - check
        type: string
        choices:
            - 'enable'
            - 'disable'
    max-header-line-request:
        description:
            - max count of header line request, default value is 64 [0,128] (range: 0-128)
        type: integer
    max-header-line-request-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    max-header-line-request-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    max-header-line-request-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    max-header-line-request-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    Illegal-http-request-method-check:
        description:
            - 
        type: string
        choices:
            - 'enable'
            - 'disable'
    Illegal-http-request-method-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    Illegal-http-request-method-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    Illegal-http-request-method-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    Illegal-http-request-method-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    max-url-parameter-check:
        description:
            - check
        type: string
        choices:
            - 'enable'
            - 'disable'
    max-url-parameter:
        description:
            - max number of url parameter, default value is 128 [0,1023] (range: 0-1023)
        type: integer
    max-url-parameter-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    max-url-parameter-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    max-url-parameter-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    max-url-parameter-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    Illegal-host-name-check:
        description:
            - 
        type: string
        choices:
            - 'enable'
            - 'disable'
    Illegal-host-name-check-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    Illegal-host-name-check-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    Illegal-host-name-check-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    Illegal-host-name-check-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    number-of-ranges-in-range-header-check:
        description:
            - check
        type: string
        choices:
            - 'enable'
            - 'disable'
    number-of-ranges-in-range-header:
        description:
            - max ranges in Range Header,default value is 5 [0 ,64] (range: 0-64)
        type: integer
    number-of-ranges-in-range-header-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    number-of-ranges-in-range-header-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    number-of-ranges-in-range-header-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    number-of-ranges-in-range-header-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    http2-max-requests-check:
        description:
            - check
        type: string
        choices:
            - 'enable'
            - 'disable'
    http2-max-requests:
        description:
            - max number of requests in HTTP2 connection, default value is 1000 [0 ,65535] (range: 0-65535)
        type: integer
    http2-max-requests-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    http2-max-requests-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    http2-max-requests-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    http2-max-requests-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    block-malformed-request-check:
        description:
            - block malformed request check
        type: string
        choices:
            - 'enable'
            - 'disable'
    block-malformed-request-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    block-malformed-request-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    block-malformed-request-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    block-malformed-request-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    Illegal-content-length-check:
        description:
            - 
        type: string
        choices:
            - 'enable'
            - 'disable'
    Illegal-content-length-check-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    Illegal-content-length-check-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    Illegal-content-length-check-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    Illegal-content-length-check-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    Illegal-content-type-check:
        description:
            - 
        type: string
        choices:
            - 'enable'
            - 'disable'
    Illegal-content-type-check-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    Illegal-content-type-check-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    Illegal-content-type-check-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    Illegal-content-type-check-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    Illegal-response-code-check:
        description:
            - 
        type: string
        choices:
            - 'enable'
            - 'disable'
    Illegal-response-code-check-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    Illegal-response-code-check-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    Illegal-response-code-check-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    Illegal-response-code-check-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    Post-request-ctype-check:
        description:
            - Post Request -- Missing Content Type Check
        type: string
        choices:
            - 'enable'
            - 'disable'
    Post-request-ctype-check-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    Post-request-ctype-check-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    Post-request-ctype-check-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    Post-request-ctype-check-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    max-http-header-name-length-check:
        description:
            - check
        type: string
        choices:
            - 'enable'
            - 'disable'
    max-http-header-name-length:
        description:
            - max length of header name, default value is 50 (range: 0-255)
        type: integer
    max-http-header-name-length-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    max-http-header-name-length-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    max-http-header-name-length-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    max-http-header-name-length-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    max-http-header-value-length-check:
        description:
            - check
        type: string
        choices:
            - 'enable'
            - 'disable'
    max-http-header-value-length:
        description:
            - max length of header value, default value is 4096 (range: 0-12288)
        type: integer
    max-http-header-value-length-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    max-http-header-value-length-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    max-http-header-value-length-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    max-http-header-value-length-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    parameter-name-check:
        description:
            - Null Character in Parameter Name
        type: string
        choices:
            - 'enable'
            - 'disable'
    parameter-name-check-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    parameter-name-check-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    parameter-name-check-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    parameter-name-check-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    parameter-value-check:
        description:
            - Null Character in Parameter Value
        type: string
        choices:
            - 'enable'
            - 'disable'
    parameter-value-check-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    parameter-value-check-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    parameter-value-check-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    parameter-value-check-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    Illegal-header-name-check:
        description:
            - Illgal Byte Code Character in Header Name Check
        type: string
        choices:
            - 'enable'
            - 'disable'
    Illegal-header-name-check-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    Illegal-header-name-check-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    Illegal-header-name-check-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    Illegal-header-name-check-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    Illegal-header-value-check:
        description:
            - Illgal Byte Code Character in Header Value Check
        type: string
        choices:
            - 'enable'
            - 'disable'
    Illegal-header-value-check-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    Illegal-header-value-check-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    Illegal-header-value-check-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    Illegal-header-value-check-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    max-http-body-parameter-length-check:
        description:
            - check
        type: string
        choices:
            - 'enable'
            - 'disable'
    max-http-body-parameter-length:
        description:
            - max length of body parameter, default value is 8192 (range: 0-16384)
        type: integer
    max-http-body-parameter-length-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    max-http-body-parameter-length-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    max-http-body-parameter-length-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    max-http-body-parameter-length-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    max-http-request-filename-length-check:
        description:
            - check
        type: string
        choices:
            - 'enable'
            - 'disable'
    max-http-request-filename-length:
        description:
            - max length of request filename, default value is 2048 (range: 0-12288)
        type: integer
    max-http-request-filename-length-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    max-http-request-filename-length-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    max-http-request-filename-length-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    max-http-request-filename-length-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    web-socket-protocol-check:
        description:
            - check
        type: string
        choices:
            - 'enable'
            - 'disable'
    web-socket-protocol-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    web-socket-protocol-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    web-socket-protocol-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    max-setting-header-table-size-check:
        description:
            - check
        type: string
        choices:
            - 'enable'
            - 'disable'
    max-setting-header-table-size:
        description:
            - max setting header table size, default value is 4096 (range: 0-16777215)
        type: integer
    max-setting-header-table-size-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    max-setting-header-table-size-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    max-setting-header-table-size-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    max-setting-current-streams-num-check:
        description:
            - check
        type: string
        choices:
            - 'enable'
            - 'disable'
    max-setting-current-streams-num:
        description:
            - max setting current streams number, default value is 256 (range: 0-100000)
        type: integer
    max-setting-current-streams-num-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    max-setting-current-streams-num-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    max-setting-current-streams-num-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    max-setting-initial-window-size-check:
        description:
            - check
        type: string
        choices:
            - 'enable'
            - 'disable'
    max-setting-initial-window-size:
        description:
            - max setting initial window size, default value is 6291456 (range: 0-2147483647)
        type: integer
    max-setting-initial-window-size-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    max-setting-initial-window-size-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    max-setting-initial-window-size-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    max-setting-frame-size-check:
        description:
            - check
        type: string
        choices:
            - 'enable'
            - 'disable'
    max-setting-frame-size:
        description:
            - max setting frame size, default value is 16384 (range: 0-16777215)
        type: integer
    max-setting-frame-size-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    max-setting-frame-size-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    max-setting-frame-size-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    max-setting-header-list-size-check:
        description:
            - check
        type: string
        choices:
            - 'enable'
            - 'disable'
    max-setting-header-list-size:
        description:
            - max setting header list size, default value is 65536 (range: 0-16777215)
        type: integer
    max-setting-header-list-size-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    max-setting-header-list-size-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    max-setting-header-list-size-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    max-url-param-name-len-check:
        description:
            - check
        type: string
        choices:
            - 'enable'
            - 'disable'
    max-url-param-name-len:
        description:
            - max url parameter name length, default value is 4096 (range: 0-8192)
        type: integer
    max-url-param-name-len-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    max-url-param-name-len-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    max-url-param-name-len-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    max-url-param-name-len-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    max-url-param-value-len-check:
        description:
            - check
        type: string
        choices:
            - 'enable'
            - 'disable'
    max-url-param-value-len:
        description:
            - max url parameter value length, default value is 4096 (range: 0-8192)
        type: integer
    max-url-param-value-len-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    max-url-param-value-len-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    max-url-param-value-len-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    max-url-param-value-len-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    url-param-name-check:
        description:
            - check
        type: string
        choices:
            - 'enable'
            - 'disable'
    url-param-name-check-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    url-param-name-check-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    url-param-name-check-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    url-param-name-check-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    url-param-value-check:
        description:
            - check
        type: string
        choices:
            - 'enable'
            - 'disable'
    url-param-value-check-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    url-param-value-check-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    url-param-value-check-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    url-param-value-check-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    null-byte-in-url-check:
        description:
            - check
        type: string
        choices:
            - 'enable'
            - 'disable'
    null-byte-in-url-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    null-byte-in-url-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    null-byte-in-url-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    null-byte-in-url-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    illegal-byte-in-url-check:
        description:
            - check
        type: string
        choices:
            - 'enable'
            - 'disable'
    illegal-byte-in-url-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    illegal-byte-in-url-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    illegal-byte-in-url-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    illegal-byte-in-url-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    malformed-url-check:
        description:
            - check
        type: string
        choices:
            - 'enable'
            - 'disable'
    malformed-url-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    malformed-url-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    malformed-url-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    malformed-url-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    redundant-header-check:
        description:
            - check
        type: string
        choices:
            - 'enable'
            - 'disable'
    redundant-header-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    redundant-header-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    redundant-header-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    redundant-header-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    chunk-size-check:
        description:
            - check
        type: string
        choices:
            - 'enable'
            - 'disable'
    chunk-size-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    chunk-size-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    chunk-size-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    chunk-size-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    Internal-resource-limits-check:
        description:
            - Internal resource limits check
        type: string
        choices:
            - 'enable'
            - 'disable'
    Internal-resource-limits-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    Internal-resource-limits-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    Internal-resource-limits-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    Internal-resource-limits-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    rpc-protocol-check:
        description:
            - rpc protocol check
        type: string
        choices:
            - 'enable'
            - 'disable'
    rpc-protocol-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    rpc-protocol-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    rpc-protocol-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    rpc-protocol-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    duplicate-paramname-check:
        description:
            - check
        type: string
        choices:
            - 'enable'
            - 'disable'
    duplicate-paramname-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    duplicate-paramname-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    duplicate-paramname-threat-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
    duplicate-paramname-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    odd-and-even-space-attack-check:
        description:
            - check
        type: string
        choices:
            - 'enable'
            - 'disable'
    odd-and-even-space-attack-action:
        description:
            - action
        type: string
        choices:
            - 'alert'
            - 'deny_no_log'
            - 'alert_deny'
            - 'block-period'
            - 'client-id-block-period'
    odd-and-even-space-attack-block-period:
        description:
            - block period(1-3600) (range: 1-3600)
        type: integer
    odd-and-even-space-attack-severity:
        description:
            - severity:High, Medium, Low or Informative
        type: string
        choices:
            - 'High'
            - 'Medium'
            - 'Low'
            - 'Info'
    odd-and-even-space-attack-weight:
        description:
            - threat weight
        type: string
        choices:
            - 'low'
            - 'critical'
            - 'informational'
            - 'moderate'
            - 'substantial'
            - 'severe'
"""

EXAMPLES = """
     - name: delete
       fwebos_waf_http_protocol_parameter_restriction:
        action: delete
        name: aaa
        vdom: root

     - name: Create
       fwebos_waf_http_protocol_parameter_restriction:
        action: add
        vdom: root
        exception_name: test4
        name: test3

     - name: edit
       fwebos_waf_http_protocol_parameter_restriction:
        action: edit
        vdom: root
        exception_name: test4
        name: test4


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

obj_url = '/api/v2.0/cmdb/waf/http-protocol-parameter-restriction'


rep_dict = {
    'illegal_byte_in_url_block_period': 'illegal-byte-in-url-block-period',
    'Illegal_content_type_check_trigger': 'Illegal-content-type-check-trigger',
    'max_url_parameter_length_trigger': 'max-url-parameter-length-trigger',
    'max_http_header_name_length_threat_weight_index': 'max-http-header-name-length-threat-weight-index',
    'duplicate_paramname_trigger': 'duplicate-paramname-trigger',
    'Illegal_header_name_check_threat_weight_index': 'Illegal-header-name-check-threat-weight-index',
    'Internal_resource_limits_block_period': 'Internal-resource-limits-block-period',
    'max_setting_frame_size_threat_weight_index': 'max-setting-frame-size-threat-weight-index',
    'max_url_param_value_len_trigger': 'max-url-param-value-len-trigger',
    'max_header_line_request_check': 'max-header-line-request-check',
    'Illegal_http_request_method_threat_weight_index': 'Illegal-http-request-method-threat-weight-index',
    'Illegal_http_request_method_severity': 'Illegal-http-request-method-severity',
    'max_http_request_length_check': 'max-http-request-length-check',
    'Post_request_ctype_check_threat_weight': 'Post-request-ctype-check-threat-weight',
    'null_byte_in_url_block_period': 'null-byte-in-url-block-period',
    'url_param_value_check_threat_weight': 'url-param-value-check-threat-weight',
    'max_http_request_length_threat_weight_index': 'max-http-request-length-threat-weight-index',
    'Illegal_header_name_check_severity': 'Illegal-header-name-check-severity',
    'number_of_ranges_in_range_header': 'number-of-ranges-in-range-header',
    'max_http_body_parameter_length_trigger': 'max-http-body-parameter-length-trigger',
    'Illegal_http_request_method_block_period': 'Illegal-http-request-method-block-period',
    'malformed_url_weight_index': 'malformed-url-weight-index',
    'max_url_parameter_threat_weight_index': 'max-url-parameter-threat-weight-index',
    'max_setting_frame_size_action': 'max-setting-frame-size-action',
    'max_url_param_value_len_action': 'max-url-param-value-len-action',
    'max_url_param_name_len_threat_weight_index': 'max-url-param-name-len-threat-weight-index',
    'max_http_body_parameter_length_threat_weight': 'max-http-body-parameter-length-threat-weight',
    'max_http_request_filename_length_trigger': 'max-http-request-filename-length-trigger',
    'http2_max_requests_block_period': 'http2-max-requests-block-period',
    'max_http_body_parameter_length_block_period': 'max-http-body-parameter-length-block-period',
    'max_setting_frame_size_check': 'max-setting-frame-size-check',
    'Internal_resource_limits_severity': 'Internal-resource-limits-severity',
    'max_header_line_request_block_period': 'max-header-line-request-block-period',
    'malformed_url_trigger': 'malformed-url-trigger',
    'url_param_name_check_trigger': 'url-param-name-check-trigger',
    'Illegal_header_name_check': 'Illegal-header-name-check',
    'Illegal_host_name_check_threat_weight': 'Illegal-host-name-check-threat-weight',
    'Illegal_host_name_check_severity': 'Illegal-host-name-check-severity',
    'odd_and_even_space_attack_trigger': 'odd-and-even-space-attack-trigger',
    'max_url_param_value_len_threat_weight_index': 'max-url-param-value-len-threat-weight-index',
    'max_cookie_in_request_threat_weight_index': 'max-cookie-in-request-threat-weight-index',
    'chunk_size_weight': 'chunk-size-weight',
    'max_http_request_filename_length_severity': 'max-http-request-filename-length-severity',
    'max_header_line_request': 'max-header-line-request',
    'max_http_header_name_length_trigger': 'max-http-header-name-length-trigger',
    'max_header_line_request_trigger': 'max-header-line-request-trigger',
    'chunk_size_severity': 'chunk-size-severity',
    'max_setting_current_streams_num_action': 'max-setting-current-streams-num-action',
    'Illegal_http_version_check_block_period': 'Illegal-http-version-check-block-period',
    'http2_max_requests_severity': 'http2-max-requests-severity',
    'max_http_content_length_trigger': 'max-http-content-length-trigger',
    'rpc_protocol_check': 'rpc-protocol-check',
    'max_http_content_length_block_period': 'max-http-content-length-block-period',
    'duplicate_paramname_block_period': 'duplicate-paramname-block-period',
    'duplicate_paramname_threat_weight_index': 'duplicate-paramname-threat-weight-index',
    'Illegal_host_name_check_action': 'Illegal-host-name-check-action',
    'Post_request_ctype_check_trigger': 'Post-request-ctype-check-trigger',
    'max_url_param_value_len_threat_weight': 'max-url-param-value-len-threat-weight',
    'url_param_value_check_block_period': 'url-param-value-check-block-period',
    'Illegal_response_code_check_severity': 'Illegal-response-code-check-severity',
    'max_url_param_name_len_threat_weight': 'max-url-param-name-len-threat-weight',
    'max_http_content_length': 'max-http-content-length',
    'null_byte_in_url_severity': 'null-byte-in-url-severity',
    'Illegal_http_request_method_trigger': 'Illegal-http-request-method-trigger',
    'max_http_request_filename_length_threat_weight': 'max-http-request-filename-length-threat-weight',
    'Internal_resource_limits_check': 'Internal-resource-limits-check',
    'max_setting_current_streams_num_block_period': 'max-setting-current-streams-num-block-period',
    'Illegal_content_type_check': 'Illegal-content-type-check',
    'parameter_name_check_block_period': 'parameter-name-check-block-period',
    'max_url_parameter_severity': 'max-url-parameter-severity',
    'max_url_param_name_len_trigger': 'max-url-param-name-len-trigger',
    'max_http_body_parameter_length_check': 'max-http-body-parameter-length-check',
    'Illegal_response_code_check_action': 'Illegal-response-code-check-action',
    'web_socket_protocol_action': 'web-socket-protocol-action',
    'Illegal_http_version_threat_weight': 'Illegal-http-version-threat-weight',
    'parameter_name_check_severity': 'parameter-name-check-severity',
    'url_param_name_check_threat_weight': 'url-param-name-check-threat-weight',
    'max_setting_header_table_size_action': 'max-setting-header-table-size-action',
    'redundant_header_action': 'redundant-header-action',
    'odd_and_even_space_attack_weight': 'odd-and-even-space-attack-weight',
    'Illegal_header_name_check_trigger': 'Illegal-header-name-check-trigger',
    'Post_request_ctype_check_threat_weight_index': 'Post-request-ctype-check-threat-weight-index',
    'Illegal_host_name_check_block_period': 'Illegal-host-name-check-block-period',
    'max_setting_frame_size_severity': 'max-setting-frame-size-severity',
    'max_url_param_value_len_check': 'max-url-param-value-len-check',
    'url_param_name_check': 'url-param-name-check',
    'max_http_header_value_length_trigger': 'max-http-header-value-length-trigger',
    'Post_request_ctype_check': 'Post-request-ctype-check',
    'max_http_content_length_threat_weight': 'max-http-content-length-threat-weight',
    'parameter_name_check_threat_weight_index': 'parameter-name-check-threat-weight-index',
    'max_setting_header_list_size_trigger': 'max-setting-header-list-size-trigger',
    'max_setting_initial_window_size_action': 'max-setting-initial-window-size-action',
    'max_http_request_length_action': 'max-http-request-length-action',
    'max_http_body_length_threat_weight_index': 'max-http-body-length-threat-weight-index',
    'max_setting_current_streams_num_trigger': 'max-setting-current-streams-num-trigger',
    'Post_request_ctype_check_severity': 'Post-request-ctype-check-severity',
    'Illegal_response_code_check_trigger': 'Illegal-response-code-check-trigger',
    'block_malformed_request_check': 'block-malformed-request-check',
    'illegal_byte_in_url_check': 'illegal-byte-in-url-check',
    'illegal_byte_in_url_threat_weight': 'illegal-byte-in-url-threat-weight',
    'number_of_ranges_in_range_header_check': 'number-of-ranges-in-range-header-check',
    'block_malformed_request_trigger': 'block-malformed-request-trigger',
    'redundant_header_block_period': 'redundant-header-block-period',
    'Illegal_content_length_check_severity': 'Illegal-content-length-check-severity',
    'Internal_resource_limits_trigger': 'Internal-resource-limits-trigger',
    'max_http_content_length_severity': 'max-http-content-length-severity',
    'max_setting_initial_window_size': 'max-setting-initial-window-size',
    'Illegal_content_length_check_block_period': 'Illegal-content-length-check-block-period',
    'null_byte_in_url_trigger': 'null-byte-in-url-trigger',
    'max_setting_header_table_size_severity': 'max-setting-header-table-size-severity',
    'parameter_name_check_trigger': 'parameter-name-check-trigger',
    'illegal_byte_in_url_severity': 'illegal-byte-in-url-severity',
    'max_url_param_name_len_action': 'max-url-param-name-len-action',
    'rpc_protocol_threat_weight_index': 'rpc-protocol-threat-weight-index',
    'parameter_name_check': 'parameter-name-check',
    'max_url_parameter_length': 'max-url-parameter-length',
    'duplicate_paramname_severity': 'duplicate-paramname-severity',
    'max_setting_initial_window_size_trigger': 'max-setting-initial-window-size-trigger',
    'Illegal_response_code_check': 'Illegal-response-code-check',
    'Post_request_ctype_check_block_period': 'Post-request-ctype-check-block-period',
    'null_byte_in_url_threat_weight_index': 'null-byte-in-url-threat-weight-index',
    'max_http_header_name_length_check': 'max-http-header-name-length-check',
    'block_malformed_request_severity': 'block-malformed-request-severity',
    'Illegal_http_version_threat_weight_index': 'Illegal-http-version-threat-weight-index',
    'max_setting_initial_window_size_threat_weight_index': 'max-setting-initial-window-size-threat-weight-index',
    'Illegal_content_length_check_threat_weight': 'Illegal-content-length-check-threat-weight',
    'max_setting_current_streams_num': 'max-setting-current-streams-num',
    'max_setting_header_list_size_block_period': 'max-setting-header-list-size-block-period',
    'Illegal_response_code_check_threat_weight': 'Illegal-response-code-check-threat-weight',
    'web_socket_protocol_trigger': 'web-socket-protocol-trigger',
    'url_param_name_check_action': 'url-param-name-check-action',
    'max_http_body_parameter_length_action': 'max-http-body-parameter-length-action',
    'max_setting_header_list_size': 'max-setting-header-list-size',
    'max_http_body_length_threat_weight': 'max-http-body-length-threat-weight',
    'max_url_parameter_trigger': 'max-url-parameter-trigger',
    'duplicate_paramname_action': 'duplicate-paramname-action',
    'max_setting_header_table_size_block_period': 'max-setting-header-table-size-block-period',
    'max_http_header_value_length': 'max-http-header-value-length',
    'max_url_parameter': 'max-url-parameter',
    'max_setting_frame_size_trigger': 'max-setting-frame-size-trigger',
    'odd_and_even_space_attack_check': 'odd-and-even-space-attack-check',
    'chunk_size_action': 'chunk-size-action',
    'max_http_header_length_block_period': 'max-http-header-length-block-period',
    'Illegal_content_length_check_trigger': 'Illegal-content-length-check-trigger',
    'Illegal_host_name_check_trigger': 'Illegal-host-name-check-trigger',
    'max_cookie_in_request_action': 'max-cookie-in-request-action',
    'number_of_ranges_in_range_header_trigger': 'number-of-ranges-in-range-header-trigger',
    'http2_max_requests_threat_weight': 'http2-max-requests-threat-weight',
    'Internal_resource_limits_threat_weight': 'Internal-resource-limits-threat-weight',
    'max_url_parameter_length_severity': 'max-url-parameter-length-severity',
    'parameter_value_check_threat_weight': 'parameter-value-check-threat-weight',
    'max_url_param_name_len': 'max-url-param-name-len',
    'max_url_parameter_action': 'max-url-parameter-action',
    'web_socket_protocol_threat_weight_index': 'web-socket-protocol-threat-weight-index',
    'max_http_header_name_length_severity': 'max-http-header-name-length-severity',
    'max_url_param_name_len_severity': 'max-url-param-name-len-severity',
    'max_http_header_value_length_check': 'max-http-header-value-length-check',
    'odd_and_even_space_attack_weight_index': 'odd-and-even-space-attack-weight-index',
    'max_http_header_value_length_threat_weight_index': 'max-http-header-value-length-threat-weight-index',
    'max_url_parameter_check': 'max-url-parameter-check',
    'max_http_content_length_check': 'max-http-content-length-check',
    'illegal_byte_in_url_trigger': 'illegal-byte-in-url-trigger',
    'parameter_value_check_trigger': 'parameter-value-check-trigger',
    'max_url_param_value_len': 'max-url-param-value-len',
    'rpc_protocol_block_period': 'rpc-protocol-block-period',
    'http2_max_requests_trigger': 'http2-max-requests-trigger',
    'odd_and_even_space_attack_severity': 'odd-and-even-space-attack-severity',
    'max_url_parameter_length_action': 'max-url-parameter-length-action',
    'number_of_ranges_in_range_header_action': 'number-of-ranges-in-range-header-action',
    'max_url_parameter_length_threat_weight': 'max-url-parameter-length-threat-weight',
    'malformed_url_action': 'malformed-url-action',
    'max_cookie_in_request_severity': 'max-cookie-in-request-severity',
    'url_param_value_check_trigger': 'url-param-value-check-trigger',
    'max_header_line_request_threat_weight_index': 'max-header-line-request-threat-weight-index',
    'max_header_line_request_threat_weight': 'max-header-line-request-threat-weight',
    'number_of_ranges_in_range_header_severity': 'number-of-ranges-in-range-header-severity',
    'Illegal_content_type_check_action': 'Illegal-content-type-check-action',
    'redundant_header_threat_weight': 'redundant-header-threat-weight',
    'max_setting_header_list_size_threat_weight_index': 'max-setting-header-list-size-threat-weight-index',
    'Illegal_http_request_method_check': 'Illegal-http-request-method-check',
    'parameter_value_check_block_period': 'parameter-value-check-block-period',
    'max_http_request_filename_length_block_period': 'max-http-request-filename-length-block-period',
    'Illegal_header_value_check_severity': 'Illegal-header-value-check-severity',
    'max_http_header_length_threat_weight': 'max-http-header-length-threat-weight',
    'malformed_url_check': 'malformed-url-check',
    'max_http_header_length_threat_weight_index': 'max-http-header-length-threat-weight-index',
    'max_url_param_name_len_block_period': 'max-url-param-name-len-block-period',
    'max_http_request_length': 'max-http-request-length',
    'chunk_size_block_period': 'chunk-size-block-period',
    'url_param_value_check_severity': 'url-param-value-check-severity',
    'max_http_body_parameter_length_severity': 'max-http-body-parameter-length-severity',
    'max_setting_initial_window_size_block_period': 'max-setting-initial-window-size-block-period',
    'parameter_name_check_threat_weight': 'parameter-name-check-threat-weight',
    'max_setting_frame_size': 'max-setting-frame-size',
    'Illegal_content_length_check': 'Illegal-content-length-check',
    'max_setting_header_list_size_check': 'max-setting-header-list-size-check',
    'malformed_url_block_period': 'malformed-url-block-period',
    'redundant_header_threat_weight_index': 'redundant-header-threat-weight-index',
    'Illegal_header_value_check_action': 'Illegal-header-value-check-action',
    'http2_max_requests_action': 'http2-max-requests-action',
    'max_http_body_length': 'max-http-body-length',
    'block_malformed_request_threat_weight_index': 'block-malformed-request-threat-weight-index',
    'max_http_header_name_length_threat_weight': 'max-http-header-name-length-threat-weight',
    'max_http_content_length_threat_weight_index': 'max-http-content-length-threat-weight-index',
    'Illegal_content_type_check_threat_weight_index': 'Illegal-content-type-check-threat-weight-index',
    'max_setting_header_list_size_severity': 'max-setting-header-list-size-severity',
    'parameter_value_check': 'parameter-value-check',
    'max_url_parameter_threat_weight': 'max-url-parameter-threat-weight',
    'parameter_value_check_action': 'parameter-value-check-action',
    'chunk_size_check': 'chunk-size-check',
    'parameter_name_check_action': 'parameter-name-check-action',
    'url_param_value_check_action': 'url-param-value-check-action',
    'max_cookie_in_request_threat_weight': 'max-cookie-in-request-threat-weight',
    'max_header_line_request_action': 'max-header-line-request-action',
    'duplicate_paramname_threat_weight': 'duplicate-paramname-threat-weight',
    'max_setting_header_table_size_check': 'max-setting-header-table-size-check',
    'max_setting_header_table_size_trigger': 'max-setting-header-table-size-trigger',
    'max_url_param_value_len_severity': 'max-url-param-value-len-severity',
    'Post_request_ctype_check_action': 'Post-request-ctype-check-action',
    'max_http_request_length_severity': 'max-http-request-length-severity',
    'Illegal_http_version_check': 'Illegal-http-version-check',
    'Illegal_header_name_check_threat_weight': 'Illegal-header-name-check-threat-weight',
    'malformed_url_weight': 'malformed-url-weight',
    'max_cookie_in_request_block_period': 'max-cookie-in-request-block-period',
    'max_url_param_name_len_check': 'max-url-param-name-len-check',
    'illegal_byte_in_url_action': 'illegal-byte-in-url-action',
    'Illegal_header_value_check': 'Illegal-header-value-check',
    'Illegal_http_request_method_threat_weight': 'Illegal-http-request-method-threat-weight',
    'max_http_content_length_action': 'max-http-content-length-action',
    'max_url_parameter_length_block_period': 'max-url-parameter-length-block-period',
    'parameter_value_check_threat_weight_index': 'parameter-value-check-threat-weight-index',
    'max_http_header_name_length_action': 'max-http-header-name-length-action',
    'max_http_body_length_check': 'max-http-body-length-check',
    'max_http_request_filename_length_action': 'max-http-request-filename-length-action',
    'Illegal_response_code_check_threat_weight_index': 'Illegal-response-code-check-threat-weight-index',
    'max_http_header_value_length_block_period': 'max-http-header-value-length-block-period',
    'block_malformed_request_action': 'block-malformed-request-action',
    'max_http_request_filename_length': 'max-http-request-filename-length',
    'max_setting_current_streams_num_threat_weight_index': 'max-setting-current-streams-num-threat-weight-index',
    'http2_max_requests_threat_weight_index': 'http2-max-requests-threat-weight-index',
    'max_http_request_length_trigger': 'max-http-request-length-trigger',
    'illegal_byte_in_url_threat_weight_index': 'illegal-byte-in-url-threat-weight-index',
    'chunk_size_trigger': 'chunk-size-trigger',
    'Illegal_response_code_check_block_period': 'Illegal-response-code-check-block-period',
    'max_http_header_value_length_threat_weight': 'max-http-header-value-length-threat-weight',
    'max_cookie_in_request': 'max-cookie-in-request',
    'rpc_protocol_trigger': 'rpc-protocol-trigger',
    'redundant_header_severity': 'redundant-header-severity',
    'max_cookie_in_request_trigger': 'max-cookie-in-request-trigger',
    'max_http_body_length_trigger': 'max-http-body-length-trigger',
    'Illegal_host_name_check': 'Illegal-host-name-check',
    'max_http_body_parameter_length_threat_weight_index': 'max-http-body-parameter-length-threat-weight-index',
    'chunk_size_weight_index': 'chunk-size-weight-index',
    'null_byte_in_url_action': 'null-byte-in-url-action',
    'Illegal_http_version_check_severity': 'Illegal-http-version-check-severity',
    'max_http_header_value_length_action': 'max-http-header-value-length-action',
    'max_http_header_value_length_severity': 'max-http-header-value-length-severity',
    'max_http_body_parameter_length': 'max-http-body-parameter-length',
    'Illegal_http_version_check_trigger': 'Illegal-http-version-check-trigger',
    'odd_and_even_space_attack_action': 'odd-and-even-space-attack-action',
    'max_setting_initial_window_size_check': 'max-setting-initial-window-size-check',
    'max_setting_current_streams_num_severity': 'max-setting-current-streams-num-severity',
    'block_malformed_request_block_period': 'block-malformed-request-block-period',
    'redundant_header_trigger': 'redundant-header-trigger',
    'Illegal_content_type_check_block_period': 'Illegal-content-type-check-block-period',
    'redundant_header_check': 'redundant-header-check',
    'max_http_body_length_action': 'max-http-body-length-action',
    'http2_max_requests_check': 'http2-max-requests-check',
    'max_http_request_length_block_period': 'max-http-request-length-block-period',
    'null_byte_in_url_check': 'null-byte-in-url-check',
    'Illegal_content_length_check_action': 'Illegal-content-length-check-action',
    'max_http_header_length': 'max-http-header-length',
    'max_http_header_length_severity': 'max-http-header-length-severity',
    'Illegal_host_name_check_threat_weight_index': 'Illegal-host-name-check-threat-weight-index',
    'max_cookie_in_request_check': 'max-cookie-in-request-check',
    'Illegal_header_value_check_threat_weight': 'Illegal-header-value-check-threat-weight',
    'max_http_request_length_threat_weight': 'max-http-request-length-threat-weight',
    'max_url_parameter_length_check': 'max-url-parameter-length-check',
    'max_header_line_request_severity': 'max-header-line-request-severity',
    'url_param_value_check': 'url-param-value-check',
    'duplicate_paramname_check': 'duplicate-paramname-check',
    'url_param_value_check_threat_weight_index': 'url-param-value-check-threat-weight-index',
    'max_setting_current_streams_num_check': 'max-setting-current-streams-num-check',
    'malformed_url_severity': 'malformed-url-severity',
    'max_url_param_value_len_block_period': 'max-url-param-value-len-block-period',
    'rpc_protocol_severity': 'rpc-protocol-severity',
    'block_malformed_request_threat_weight': 'block-malformed-request-threat-weight',
    'web_socket_protocol_block_period': 'web-socket-protocol-block-period',
    'odd_and_even_space_attack_block_period': 'odd-and-even-space-attack-block-period',
    'max_http_request_filename_length_check': 'max-http-request-filename-length-check',
    'number_of_ranges_in_range_header_threat_weight': 'number-of-ranges-in-range-header-threat-weight',
    'parameter_value_check_severity': 'parameter-value-check-severity',
    'max_http_header_name_length_block_period': 'max-http-header-name-length-block-period',
    'url_param_name_check_block_period': 'url-param-name-check-block-period',
    'max_http_header_length_check': 'max-http-header-length-check',
    'number_of_ranges_in_range_header_threat_weight_index': 'number-of-ranges-in-range-header-threat-weight-index',
    'url_param_name_check_threat_weight_index': 'url-param-name-check-threat-weight-index',
    'Illegal_http_request_method_action': 'Illegal-http-request-method-action',
    'Illegal_content_length_check_threat_weight_index': 'Illegal-content-length-check-threat-weight-index',
    'http2_max_requests': 'http2-max-requests',
    'max_url_parameter_length_threat_weight_index': 'max-url-parameter-length-threat-weight-index',
    'Illegal_content_type_check_threat_weight': 'Illegal-content-type-check-threat-weight',
    'Illegal_content_type_check_severity': 'Illegal-content-type-check-severity',
    'Illegal_header_value_check_threat_weight_index': 'Illegal-header-value-check-threat-weight-index',
    'max_http_request_filename_length_threat_weight_index': 'max-http-request-filename-length-threat-weight-index',
    'Illegal_http_version_check_action': 'Illegal-http-version-check-action',
    'Illegal_header_value_check_block_period': 'Illegal-header-value-check-block-period',
    'url_param_name_check_severity': 'url-param-name-check-severity',
    'rpc_protocol_threat_weight': 'rpc-protocol-threat-weight',
    'max_http_body_length_severity': 'max-http-body-length-severity',
    'web_socket_protocol_check': 'web-socket-protocol-check',
    'max_setting_header_list_size_action': 'max-setting-header-list-size-action',
    'Illegal_header_name_check_block_period': 'Illegal-header-name-check-block-period',
    'max_setting_frame_size_block_period': 'max-setting-frame-size-block-period',
    'web_socket_protocol_severity': 'web-socket-protocol-severity',
    'null_byte_in_url_threat_weight': 'null-byte-in-url-threat-weight',
    'Illegal_header_value_check_trigger': 'Illegal-header-value-check-trigger',
    'max_setting_header_table_size_threat_weight_index': 'max-setting-header-table-size-threat-weight-index',
    'max_setting_header_table_size': 'max-setting-header-table-size',
    'max_http_header_length_action': 'max-http-header-length-action',
    'max_url_parameter_block_period': 'max-url-parameter-block-period',
    'rpc_protocol_action': 'rpc-protocol-action',
    'Internal_resource_limits_action': 'Internal-resource-limits-action',
    'max_http_body_length_block_period': 'max-http-body-length-block-period',
    'max_setting_initial_window_size_severity': 'max-setting-initial-window-size-severity',
    'number_of_ranges_in_range_header_block_period': 'number-of-ranges-in-range-header-block-period',
    'max_http_header_length_trigger': 'max-http-header-length-trigger',
    'Illegal_header_name_check_action': 'Illegal-header-name-check-action',
    'max_http_header_name_length': 'max-http-header-name-length',
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
        name=dict(type='str'),
        exception_name=dict(type='str'),
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
