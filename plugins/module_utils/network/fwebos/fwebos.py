from __future__ import (absolute_import, division, print_function)
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


def is_vdom_enable(connection):
    payload = {}
    code, response = connection.send_request(
        '/api/v2.0/system/status.systemstatus', payload, 'GET')
    sys_setting = response['results']
    if 'administrativeDomain' not in sys_setting.keys():
        return False
    elif sys_setting['administrativeDomain'] == 'Enabled':
        return True
    else:
        return False
