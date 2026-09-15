#!/usr/bin/python
from __future__ import (absolute_import, division, print_function)

import re
from datetime import datetime

from ansible.module_utils.basic import AnsibleModule
from ansible.module_utils.connection import Connection
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
module: fwebos_system_time
short_description: Configure FortiWeb system time settings
description:
  - Configure the FortiWeb time zone, daylight saving behavior, time source,
    manual system time, and NTP synchronization interval.
  - Requires FortiWeb OS 7.6.0 or later. Use M(fortinet.fortiweb.fwebos_ntp)
    for earlier versions.
  - NTP server entries are managed by the separate
    C(/api/v2.0/cmdb/system/ntp/ntpserver) API.
version_added: "7.6.0"
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
    choices: [get, edit]
  timeZone:
    description:
      - FortiWeb time zone index.
    type: int
  daylightSaving:
    description:
      - Whether FortiWeb automatically adjusts its clock for daylight saving
        time changes.
    type: int
    choices: [0, 1]
  mode:
    description:
      - Selects NTP synchronization or manual time configuration.
    type: str
    choices: [ntpServer, setTime]
  time:
    description:
      - Requested manual date and time when I(mode=setTime).
      - Uses C(M/D/YYYY H:MM:SS) format, for example C(3/25/2026 17:20:17).
    type: str
  syncinterval:
    description:
      - Number of minutes between NTP synchronization attempts.
      - This value is stored by C(/api/v2.0/cmdb/system/ntp).
    type: int
'''


EXAMPLES = r'''
- name: Read the current system time settings
  fortinet.fortiweb.fwebos_system_time:
    action: get

- name: Configure NTP time synchronization
  fortinet.fortiweb.fwebos_system_time:
    action: edit
    timeZone: 6
    daylightSaving: 0
    mode: ntpServer
    syncinterval: 70

- name: Configure the system time manually
  fortinet.fortiweb.fwebos_system_time:
    action: edit
    timeZone: 6
    daylightSaving: 0
    mode: setTime
    time: "3/25/2026 17:20:17"
'''


RETURN = r'''
changed:
  description: Whether the FortiWeb configuration was changed.
  returned: always
  type: bool
diff:
  description: Values before and after an edit operation.
  returned: when action is edit
  type: dict
res:
  description: Response from the system time REST API.
  returned: always
  type: dict
ntp_res:
  description: Response from the NTP REST API.
  returned: always
  type: dict
'''


SYSTEM_TIME_URL = '/api/v2.0/system/maintenance.systemtime'
NTP_URL = '/api/v2.0/cmdb/system/ntp'
SYSTEM_STATUS_URL = '/api/v2.0/system/status.systemstatus'
MINIMUM_FIRMWARE_VERSION = (7, 6, 0)


def get_obj(connection, url):
    return connection.send_request(url, {}, 'GET')


def edit_obj(connection, url, payload):
    return connection.send_request(url, payload, 'PUT')


def get_results(module, response, endpoint_name):
    results = response.get('results') if isinstance(response, dict) else None
    if not isinstance(results, dict):
        module.fail_json(
            msg='Unexpected response while reading {0} settings'.format(endpoint_name),
            res=response,
        )
    return results


def get_firmware_version(module, connection):
    code, response = get_obj(connection, SYSTEM_STATUS_URL)
    if not isinstance(code, int) or not 200 <= code < 300:
        module.fail_json(
            msg='Unable to determine the FortiWeb OS version.',
            changed=False,
            res=response,
        )

    status = response.get('results') if isinstance(response, dict) else None
    firmware = status.get('firmwareVersion', '') if isinstance(status, dict) else ''
    match = re.search(r'\b[vV]?(\d+)\.(\d+)(?:\.(\d+))?', str(firmware))
    if match is None:
        module.fail_json(
            msg="Unable to parse the FortiWeb OS version from '{0}'.".format(firmware),
            changed=False,
            res=response,
        )

    version = (
        int(match.group(1)),
        int(match.group(2)),
        int(match.group(3) or 0),
    )
    return version, firmware


def normalize_time(value):
    value = value.strip()
    if re.match(
        r'^(0?[1-9]|1[0-2])/(0?[1-9]|[12][0-9]|3[01])/([0-9]{4}) '
        r'([01]?[0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9])$',
        value,
    ) is None:
        return None

    try:
        parsed = datetime.strptime(value, '%m/%d/%Y %H:%M:%S')
    except ValueError:
        return None

    return '{0}/{1}/{2} {3}:{4:02d}:{5:02d}'.format(
        parsed.month,
        parsed.day,
        parsed.year,
        parsed.hour,
        parsed.minute,
        parsed.second,
    )


def normalize_existing_time(value):
    try:
        parsed = datetime.strptime(value.strip(), '%m/%d/%Y %H:%M:%S')
    except (AttributeError, ValueError):
        return None

    return '{0}/{1}/{2} {3}:{4:02d}:{5:02d}'.format(
        parsed.month,
        parsed.day,
        parsed.year,
        parsed.hour,
        parsed.minute,
        parsed.second,
    )


def param_check(module, system_time):
    params = module.params

    if params['action'] == 'get':
        return True, ''

    configurable = (
        'timeZone',
        'daylightSaving',
        'mode',
        'time',
        'syncinterval',
    )
    if all(params[name] is None for name in configurable):
        return False, 'At least one configurable parameter must be provided for action edit.'

    if params['timeZone'] is not None and params['timeZone'] < 0:
        return False, 'timeZone must be zero or greater.'

    if params['syncinterval'] is not None and not 1 <= params['syncinterval'] <= 1440:
        return False, 'syncinterval must be between 1 and 1440 minutes.'

    time = params['time']
    if time is not None and normalize_time(time) is None:
        return False, 'time must use M/D/YYYY H:MM:SS format.'

    effective_mode = params['mode'] or system_time.get('mode')
    if time is not None and effective_mode != 'setTime':
        return False, 'time can only be set when mode is setTime.'

    if (
        params['mode'] == 'setTime'
        and system_time.get('mode') != 'setTime'
        and time is None
    ):
        return False, 'time is required when changing mode to setTime.'

    return True, ''


def build_updates(module, system_time, ntp):
    params = module.params
    before = {}
    after = {}

    system_payload = {
        key: system_time[key]
        for key in ('timeZone', 'daylightSaving', 'mode', '_id')
        if key in system_time
    }
    ntp_payload = {}

    system_changed = False
    ntp_changed = False

    if params['timeZone'] is not None and params['timeZone'] != system_time.get('timeZone'):
        before['timeZone'] = system_time.get('timeZone')
        after['timeZone'] = params['timeZone']
        system_payload['timeZone'] = params['timeZone']
        system_changed = True

    if (
        params['daylightSaving'] is not None
        and params['daylightSaving'] != system_time.get('daylightSaving')
    ):
        before['daylightSaving'] = system_time.get('daylightSaving')
        after['daylightSaving'] = params['daylightSaving']
        system_payload['daylightSaving'] = params['daylightSaving']
        system_changed = True

    if params['mode'] is not None:
        if params['mode'] != system_time.get('mode'):
            before['mode'] = system_time.get('mode')
            after['mode'] = params['mode']
            system_payload['mode'] = params['mode']
            system_changed = True

            ntp_sync = 'enable' if params['mode'] == 'ntpServer' else 'disable'
            if ntp_sync != ntp.get('ntpsync'):
                before['ntpsync'] = ntp.get('ntpsync')
                after['ntpsync'] = ntp_sync
            ntp_payload['ntpsync'] = ntp_sync
            ntp_changed = True

        if params['mode'] == 'setTime' and 'time' in system_time:
            system_payload['time'] = system_time['time']

    if params['time'] is not None:
        time = normalize_time(params['time'])
        current_time = str(system_time.get('time', '')).strip()
        comparable_time = normalize_existing_time(current_time) or current_time
        if time != comparable_time:
            before['time'] = current_time
            after['time'] = time
            system_payload['time'] = time
            system_changed = True

    if params['syncinterval'] is not None and params['syncinterval'] != ntp.get('syncinterval'):
        before['syncinterval'] = ntp.get('syncinterval')
        after['syncinterval'] = params['syncinterval']
        ntp_payload['syncinterval'] = params['syncinterval']
        ntp_changed = True

    return {
        'system_changed': system_changed,
        'system_payload': system_payload,
        'ntp_changed': ntp_changed,
        'ntp_payload': ntp_payload,
        'diff': {
            'before': before,
            'after': after,
        },
    }


def main():
    argument_spec = dict(
        action=dict(type='str', required=True, choices=['get', 'edit']),
        timeZone=dict(type='int'),
        daylightSaving=dict(type='int', choices=[0, 1]),
        mode=dict(type='str', choices=['ntpServer', 'setTime']),
        time=dict(type='str'),
        syncinterval=dict(type='int'),
    )
    argument_spec.update(fwebos_argument_spec)

    module = AnsibleModule(
        argument_spec=argument_spec,
        supports_check_mode=True,
    )
    connection = Connection(module._socket_path)

    if is_vdom_enable(connection):
        connection.change_auth_for_vdom('root')

    firmware_version, firmware = get_firmware_version(module, connection)
    if firmware_version < MINIMUM_FIRMWARE_VERSION:
        module.fail_json(
            msg=(
                'fwebos_system_time requires FortiWeb with firmware version 7.6.0 or later. '
                "Detected '{0}'. Use fwebos_ntp on this device."
            ).format(firmware),
            changed=False,
        )

    _, system_response = get_obj(connection, SYSTEM_TIME_URL)
    _, ntp_response = get_obj(connection, NTP_URL)
    system_time = get_results(module, system_response, 'system time')
    ntp = get_results(module, ntp_response, 'NTP')

    result = {
        'changed': False,
        'res': system_response,
        'ntp_res': ntp_response,
    }

    if module.params['action'] == 'get':
        module.exit_json(**result)

    param_pass, param_err = param_check(module, system_time)
    if not param_pass:
        module.fail_json(msg=param_err, **result)

    updates = build_updates(module, system_time, ntp)
    result['changed'] = updates['system_changed'] or updates['ntp_changed']
    result['diff'] = updates['diff']

    if not result['changed']:
        module.exit_json(**result)

    if module.check_mode:
        result['res'] = 'Check mode: changes detected.'
        result['ntp_res'] = 'Check mode: changes detected.'
        module.exit_json(**result)

    responses = {}

    if updates['system_changed']:
        system_code, responses['system_time'] = edit_obj(
            connection,
            SYSTEM_TIME_URL,
            updates['system_payload'],
        )
        if not isinstance(system_code, int) or not 200 <= system_code < 300:
            result['changed'] = False
            result['res'] = responses['system_time']
            module.fail_json(
                msg='Unable to update system time settings',
                **result
            )

    if updates['ntp_changed']:
        ntp_code, responses['ntp'] = edit_obj(
            connection,
            NTP_URL,
            {'data': updates['ntp_payload']},
        )
        if not isinstance(ntp_code, int) or not 200 <= ntp_code < 300:
            result['res'] = responses.get('system_time', result['res'])
            result['ntp_res'] = responses['ntp']
            module.fail_json(
                msg='System time was updated, but NTP status could not be updated',
                **result
            )

    if module.params['mode'] is not None:
        _, responses['ntp'] = get_obj(connection, NTP_URL)

    if 'system_time' in responses:
        result['res'] = responses['system_time']
    if 'ntp' in responses:
        result['ntp_res'] = responses['ntp']

    module.exit_json(**result)


if __name__ == '__main__':
    main()