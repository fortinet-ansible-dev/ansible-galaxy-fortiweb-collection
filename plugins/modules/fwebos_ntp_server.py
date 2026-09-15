#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
from ansible.module_utils.connection import ConnectionError as AnsibleConnectionError
from ansible_collections.fortinet.fortiweb.plugins.module_utils.network.fwebos.fwebos import (
    fwebos_argument_spec,
    is_vdom_enable,
)

__metaclass__ = type


ANSIBLE_METADATA = {
    'metadata_version': '1.1',
    'status': ['preview'],
    'supported_by': 'network',
}


DOCUMENTATION = r'''
---
module: fwebos_ntp_server
short_description: Manage FortiWeb NTP servers
description:
  - Add, read, edit, and delete FortiWeb NTP server entries.
  - Uses the C(/api/v2.0/cmdb/system/ntp/ntpserver) API.
version_added: "7.0.0"
author:
  - Joseph Chen
requirements:
  - ansible>=2.11
options:
  action:
    description:
      - Operation to perform.
    type: str
    required: true
    choices: [add, get, edit, delete]
  id:
    description:
      - ID of the NTP server entry.
      - Required for I(action=edit) and I(action=delete).
      - When supplied with I(action=get), returns only that entry.
    type: str
  server:
    description:
      - Hostname or IP address of the NTP server.
    type: str
  authentication:
    description:
      - Enables or disables NTP authentication.
    type: str
    choices: [enable, disable]
  ip_type:
    description:
      - IP version used to contact the NTP server.
    type: str
    choices: [v4, v6, both]
  key:
    description:
      - Authentication key.
      - Required when enabling authentication on a new entry.
    type: str
  key_id:
    description:
      - NTP authentication key ID.
    type: int
  key_type:
    description:
      - NTP authentication key algorithm.
    type: str
    choices: [sha1, sha256, aes128, aes256]
'''


EXAMPLES = r'''
- name: Add an authenticated IPv6 NTP server
  fortinet.fortiweb.fwebos_ntp_server:
    action: add
    server: s2
    authentication: enable
    ip_type: v6
    key: DC2948BC9C28202DD173699014AFFBB7B2D89F5B
    key_id: 1
    key_type: sha1

- name: Get all NTP servers
  fortinet.fortiweb.fwebos_ntp_server:
    action: get

- name: Get one NTP server
  fortinet.fortiweb.fwebos_ntp_server:
    action: get
    id: "2"

- name: Edit an NTP server
  fortinet.fortiweb.fwebos_ntp_server:
    action: edit
    id: "2"
    server: s2
    ip_type: v4
    authentication: enable
    key_type: sha1
    key: ENC XXXX
    key_id: 1

- name: Delete an NTP server
  fortinet.fortiweb.fwebos_ntp_server:
    action: delete
    id: "2"
'''


RETURN = r'''
changed:
  description: Whether the FortiWeb configuration was changed.
  returned: always
  type: bool
diff:
  description: Values before and after the requested operation.
  returned: when diff mode is enabled
  type: dict
res:
  description: Response from the FortiWeb REST API.
  returned: always
  type: dict
'''


NTP_SERVER_URL = '/api/v2.0/cmdb/system/ntp/ntpserver'

PARAM_TO_API = {
    'server': 'server',
    'authentication': 'authentication',
    'ip_type': 'ip-type',
    'key': 'key',
    'key_id': 'key-id',
    'key_type': 'key-type',
}
API_TO_PARAM = dict((value, key) for key, value in PARAM_TO_API.items())
EDIT_PARAMS = tuple(PARAM_TO_API.keys())
ENTRY_FIELDS = ('id',) + tuple(PARAM_TO_API.values())
NON_FATAL_ERRCODES = (-3, -5)


def request(connection, method, entry_id=None, data=None):
    url = NTP_SERVER_URL
    if entry_id is not None:
        url += '?sub_mkey=' + str(entry_id)

    payload = {}
    if method in ('POST', 'PUT'):
        payload['data'] = data

    return connection.send_request(url, payload, method)


def response_errcode(response):
    if not isinstance(response, dict):
        return None

    results = response.get('results')
    errcode = (
        results.get('errcode')
        if isinstance(results, dict)
        else response.get('errcode')
    )
    try:
        return int(errcode)
    except (TypeError, ValueError):
        return errcode


def require_success(module, code, response, operation, result, nonfatal_errcodes=()):
    errcode = response_errcode(response)
    if errcode in nonfatal_errcodes:
        result['changed'] = False
        result['failed'] = False
        result['res'] = response
        return False
    if (
        isinstance(code, int)
        and 200 <= code < 300
        and (errcode is None or (isinstance(errcode, int) and errcode >= 0))
    ):
        return True
    result['res'] = response
    module.fail_json(
        msg='Unable to {0} the NTP server entry'.format(operation),
        **result
    )


def get_results(module, code, response):
    result = {'changed': False, 'res': response}
    require_success(module, code, response, 'read', result)
    if not isinstance(response, dict) or 'results' not in response:
        module.fail_json(
            msg='Unexpected response while reading NTP server entries',
            **result
        )
    return response['results']


def find_entry(results, entry_id):
    if isinstance(results, dict):
        return results if str(results.get('id')) == str(entry_id) else None
    if isinstance(results, list):
        for entry in results:
            if isinstance(entry, dict) and str(entry.get('id')) == str(entry_id):
                return entry
    return None


def find_server(results, server):
    requested = server.strip().lower()
    entries = [results] if isinstance(results, dict) else results
    if not isinstance(entries, list):
        return None
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        current = entry.get('server')
        if isinstance(current, str) and current.strip().lower() == requested:
            return entry
    return None


def build_add_payload(params):
    payload = {
        'server': params['server'],
        'authentication': params['authentication'] or 'disable',
        'ip-type': params['ip_type'] or 'v4',
    }
    if payload['authentication'] == 'enable':
        payload['key'] = params['key']
        payload['key-id'] = params['key_id']
        payload['key-type'] = params['key_type']
    return payload


def build_edit_payload(params, current):
    payload = {}
    for param_name, api_name in PARAM_TO_API.items():
        value = params[param_name]
        payload[api_name] = current.get(api_name) if value is None else value

    if payload.get('authentication') == 'disable':
        for api_name in ('key', 'key-id', 'key-type'):
            payload.pop(api_name, None)

    return payload


def validate_parameters(module, current=None):
    params = module.params

    if params['id'] is not None and not str(params['id']).isdigit():
        module.fail_json(msg='id must be a positive integer.')
    if params['id'] is not None and int(params['id']) < 1:
        module.fail_json(msg='id must be a positive integer.')
    if params['key_id'] is not None and params['key_id'] < 0:
        module.fail_json(msg='key_id must be zero or greater.')
    if params['server'] is not None and not params['server'].strip():
        module.fail_json(msg='server must not be empty.')

    if params['action'] == 'edit' and all(params[name] is None for name in EDIT_PARAMS):
        module.fail_json(msg='At least one configurable parameter is required for action edit.')

    if params['action'] == 'add':
        authentication = params['authentication'] or 'disable'
        if authentication == 'enable':
            missing = [
                name for name in ('key', 'key_id', 'key_type')
                if params[name] is None
            ]
            if missing:
                module.fail_json(
                    msg='{0} required when authentication is enable.'.format(
                        ', '.join(missing)
                    )
                )

    if params['action'] == 'edit' and current is not None:
        authentication = params['authentication'] or current.get('authentication')
        if authentication == 'enable':
            enabling_authentication = (
                params['authentication'] == 'enable'
                and current.get('authentication') != 'enable'
            )
            if enabling_authentication:
                values = dict(
                    (name, params[name])
                    for name in ('key', 'key_id', 'key_type')
                )
            else:
                values = {}
                for param_name, api_name in (
                    ('key', 'key'),
                    ('key_id', 'key-id'),
                    ('key_type', 'key-type'),
                ):
                    values[param_name] = (
                        params[param_name]
                        if params[param_name] is not None
                        else current.get(api_name)
                    )
            missing = [name for name, value in values.items() if value in (None, '')]
            if missing:
                module.fail_json(
                    msg='{0} required when authentication is enable.'.format(
                        ', '.join(missing)
                    )
                )


def values_equal(api_name, old_value, new_value):
    if api_name == 'key-id':
        try:
            return int(old_value) == int(new_value)
        except (TypeError, ValueError):
            return old_value == new_value
    if isinstance(old_value, str) and isinstance(new_value, str):
        return old_value.rstrip() == new_value.rstrip()
    return old_value == new_value


def changed_fields(params, current, desired):
    changed = []
    for param_name, api_name in PARAM_TO_API.items():
        if params[param_name] is None:
            continue
        if api_name == 'key':
            if params[param_name] != 'ENC XXXX':
                changed.append(api_name)
            continue
        if not values_equal(api_name, current.get(api_name), desired.get(api_name)):
            changed.append(api_name)
    return changed


def display_data(data, fields=None):
    if not isinstance(data, dict):
        return data
    selected = fields if fields is not None else data.keys()
    output = {}
    for api_name in selected:
        if api_name not in data:
            continue
        name = API_TO_PARAM.get(api_name, api_name)
        output[name] = 'VALUE_SPECIFIED' if api_name == 'key' else data[api_name]
    return output


def main():
    argument_spec = dict(
        action=dict(type='str', required=True, choices=['add', 'get', 'edit', 'delete']),
        id=dict(type='str'),
        server=dict(type='str'),
        authentication=dict(type='str', choices=['enable', 'disable']),
        ip_type=dict(type='str', choices=['v4', 'v6', 'both']),
        key=dict(type='str', no_log=True),
        key_id=dict(type='int'),
        key_type=dict(type='str', choices=['sha1', 'sha256', 'aes128', 'aes256']),
    )
    argument_spec.update(fwebos_argument_spec)

    module = AnsibleModule(
        argument_spec=argument_spec,
        required_if=[
            ('action', 'add', ['server']),
            ('action', 'edit', ['id']),
            ('action', 'delete', ['id']),
        ],
        supports_check_mode=True,
    )
    params = module.params
    result = {'changed': False, 'res': {}}
    connection = Connection(module._socket_path)

    try:
        if is_vdom_enable(connection):
            connection.change_auth_for_vdom('root')

        validate_parameters(module)

        if params['action'] == 'get':
            code, response = request(connection, 'GET')
            entries = get_results(module, code, response)
            if params['id'] is None:
                result['res'] = response
            else:
                entry = find_entry(entries, params['id'])
                result['res'] = {'results': entry if entry is not None else []}
            module.exit_json(**result)

        current = None
        if params['action'] == 'add':
            code, response = request(connection, 'GET')
            entries = get_results(module, code, response)
            current = find_server(entries, params['server'])
            if current is not None:
                result['res'] = {'results': current}
                result['diff'] = {
                    'before': display_data(current, ENTRY_FIELDS),
                    'after': display_data(current, ENTRY_FIELDS),
                }
                module.exit_json(**result)

        if params['action'] in ('edit', 'delete'):
            code, response = request(connection, 'GET')
            entries = get_results(module, code, response)
            current = find_entry(entries, params['id'])
            if current is None:
                if params['action'] == 'delete':
                    result['res'] = {'results': []}
                    module.exit_json(**result)
                module.fail_json(msg='NTP server entry not found.', **result)

        if params['action'] == 'add':
            desired = build_add_payload(params)
            result['changed'] = True
            result['diff'] = {'before': {}, 'after': display_data(desired)}
            if module.check_mode:
                result['res'] = 'Check mode: NTP server would be added.'
                module.exit_json(**result)
            code, response = request(connection, 'POST', data=desired)
            require_success(
                module,
                code,
                response,
                'add',
                result,
                NON_FATAL_ERRCODES,
            )
            result['res'] = response

        elif params['action'] == 'edit':
            validate_parameters(module, current)
            desired = build_edit_payload(params, current)
            fields = changed_fields(params, current, desired)
            result['changed'] = bool(fields)
            result['diff'] = {
                'before': display_data(current, fields),
                'after': display_data(desired, fields),
            }
            if not result['changed']:
                result['res'] = response
                module.exit_json(**result)
            if module.check_mode:
                result['res'] = 'Check mode: NTP server would be edited.'
                module.exit_json(**result)
            code, response = request(connection, 'PUT', params['id'], desired)
            require_success(module, code, response, 'edit', result)
            result['res'] = response

        elif params['action'] == 'delete':
            result['changed'] = True
            result['diff'] = {
                'before': display_data(current, ENTRY_FIELDS),
                'after': {},
            }
            if module.check_mode:
                result['res'] = 'Check mode: NTP server would be deleted.'
                module.exit_json(**result)
            code, response = request(connection, 'DELETE', params['id'])
            require_success(
                module,
                code,
                response,
                'delete',
                result,
                NON_FATAL_ERRCODES,
            )
            result['res'] = response

    except AnsibleConnectionError as error:
        module.fail_json(
            msg='FortiWeb API request failed: {0}'.format(error),
            **result
        )

    module.exit_json(**result)


if __name__ == '__main__':
    main()