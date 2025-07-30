from __future__ import (absolute_import, division, print_function)
from ansible.module_utils.connection import ConnectionError as AnsibleConnectionError
__metaclass__ = type

fwebos_argument_spec = dict()


def is_global_admin(connection):
    payload = {}
    url = '/api/v2.0/cmdb/system/admin?mkey=' + str(connection.get_option('remote_user'))

    code, response = connection.send_request(url, payload, 'GET')

    user_data = response['results']
    if user_data.get('access-profile') == 'prof_admin':
        return True
    else:
        return False


class VdomCheckError(Exception):
    """A catch-all for errors during the vDOM check."""
    pass

def is_vdom_enable(connection):
    payload = {}
    try:
        code, response = connection.send_request(
            '/api/v2.0/system/status.systemstatus',
            payload,
            'GET'
        )
    except AnsibleConnectionError as e:
        raise VdomCheckError(f"Connection failed: {e}. Please check authenication status") from e
    except Exception as e:
        # any other unexpected error during send_request
        raise VdomCheckError(f"Unexpected error in send_request: {e}") from e
    # Validate response type:
    if not isinstance(response, dict):
        raise VdomCheckError(
            f"Fail to obtain system VDOM status"
        )
    sys_setting = response['results']
    if 'administrativeDomain' not in sys_setting.keys():
        return False
    elif sys_setting['administrativeDomain'] == 'Enabled':
        return True
    else:
        return False
