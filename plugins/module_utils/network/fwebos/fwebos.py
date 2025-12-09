from __future__ import (absolute_import, division, print_function)
from ansible.module_utils.connection import ConnectionError as AnsibleConnectionError
__metaclass__ = type
import copy

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


def reverse_replace_keys(data, rep_dict):
    # Build a reverse mapping: 'access-profile' -> 'access_profile'
    reverse_dict = {v: k for k, v in rep_dict.items()}
    
    # Replace keys in `data` using the reverse mapping
    return {
        reverse_dict.get(key, key): value
        for key, value in data.items()
    }

def check_mode_process(module, data, rep_dict):
    result = {}
    action = module.params['action']
    changed = False
    before = {}
    after = {}
    action = module.params['action']
    params =  module.params.copy()
    if 'action' in module.params.keys():
        params.pop('action')
    if 'vdom' in module.params.keys():
        params.pop('vdom')
    result['changed'] = changed
    if data is None or data == {}:
        return result
    if action == 'get':
        result['changed'] = False
        result['res'] = data
        return result

    if 'results' in data.keys() and data['results'] and isinstance(data['results'], dict) and 'errcode' not in str(data):
        if action == 'edit':
            if rep_dict is not None:
            # translate back the keys in data, the keys in API return are different from the user input
                data = reverse_replace_keys(data['results'], rep_dict)
            else:
                data = data['results']
            for key in params.keys():
                if params[key] is not None and key in data.keys() and params[key] != data[key]:
                    if isinstance(params[key], str) and isinstance(data[key], str) and params[key].rstrip() == data[key].rstrip():
                        continue #some sring values returned from API have trailing whitespace
                    before[key] = data[key]
                    after[key] = params[key]
                    changed = True
        elif action == 'delete':
            after['deleted'] = params
            changed = True
    else:
        if action == 'add' or action == 'post':
            changed = True
            after['added'] = params
        else:
            result['res'] = 'Entry not found.'
    # if module._diff:
    result['diff'] = {
        'before': before,
        'after': after
    }
    result['changed'] = changed
    if module.check_mode:
        if changed == True:
            result['res'] = 'Check mode: changes detected.'   
        else:
            result['res'] = 'Check mode: no changes detected.'    
    return result