#!/usr/bin/python
#
# This file is part of Ansible
#
#
# updata date:2019/03/12

from __future__ import (absolute_import, division, print_function)
import json
from ansible_collections.fortinet.fortiweb.plugins.module_utils.network.fwebos.fwebos import (fwebos_argument_spec, is_global_admin)
from ansible.module_utils.connection import Connection
from ansible.module_utils.basic import AnsibleModule
__metaclass__ = type


ANSIBLE_METADATA = {'metadata_version': '1.1',
                    'status': ['preview'],
                    'supported_by': 'network'}


DOCUMENTATION = """
---
module: fwebos_ha
description:
  - Configure FortiWeb devices via RESTful APIs
"""

EXAMPLES = """
"""

RETURN = """
"""

obj_url = '/api/v2.0/cmdb/system/ha'


rep_dict = {
    'group_id': 'group-id',
    'group_name': 'group-name',
    'network_type': 'network-type',
    'network_type_val': 'network-type_val',
    'tunnel_local': 'tunnel-local',
    'tunnel_peer': 'tunnel-peer',
    'hbdev_backup': 'hbdev-backup',
    'hbdev_backup_val': 'hbdev-backup_val',
    'boot_time': 'boot-time',
    'hb_interval': 'hb-interval',
    'hb_lost_threshold': 'hb-lost-threshold',
    'arp_interval': 'arp-interval',
    'lacp_ha_slave': 'lacp-ha-slave',
    'lacp_ha_slave_val': 'lacp-ha-slave_val',
    'ha_mgmt_status': 'ha-mgmt-status',
    'ha_mgmt_status_val': 'ha-mgmt-status_val',
    'ha_mgmt_interface': 'ha-mgmt-interface',
    'session_pickup': 'session-pickup',
    'session_pickup_val': 'session-pickup_val',
    'session_sync_dev': 'session-sync-dev',
    'session_sync_broadcast': 'session-sync-broadcast',
    'session_sync_broadcast_val': 'session-sync-broadcast_val',
    'session_warm_up': 'session-warm-up',
    'weight_1': 'weight-1',
    'weight_2': 'weight-2',
    'weight_3': 'weight-3',
    'weight_4': 'weight-4',
    'weight_5': 'weight-5',
    'weight_6': 'weight-6',
    'weight_7': 'weight-7',
    'weight_8': 'weight-8',
    'link_failed_signal': 'link-failed-signal',
    'link_failed_signal_val': 'link-failed-signal_val',
    'l7_persistence_sync': 'l7-persistence-sync',
    'l7_persistence_sync_val': 'l7-persistence-sync_val',
    'eip_addr': 'eip-addr',
    'eip_aid': 'eip-aid',
    'ha_eth_type': 'ha-eth-type',
    'hc_eth_type': 'hc-eth-type',
    'l2ep_eth_type': 'l2ep-eth-type',
    'server_policy_hlck': 'server-policy-hlck',
    'server_policy_hlck_val': 'server-policy-hlck_val',
    'multi_cluster': 'multi-cluster',
    'multi_cluster_val': 'multi-cluster_val',
    'multi_cluster_group': 'multi-cluster-group',
    'multi_cluster_group_val': 'multi-cluster-group_val',
    'multi_cluster_switch_by': 'multi-cluster-switch-by',
    'multi_cluster_switch_by_val': 'multi-cluster-switch-by_val',
    'multi_cluster_move_primary_cluster': 'multi-cluster-move-primary-cluster',
    'multi_cluster_move_primary_cluster_val': 'multi-cluster-move-primary-cluster_val',
    'cluster_arp': 'cluster-arp',
    'cluster_arp_val': 'cluster-arp_val',
    'sdn_connector': 'sdn-connector',
    'sdn_connector_val': 'sdn-connector_val',
    'lb_name': 'lb-name',
    'lb_ocid': 'lb-ocid',
}


def replace_key(src_dict, rep_dict):
    for key in rep_dict:
        if key in src_dict:
            new_key = rep_dict[key]
            src_dict[new_key] = src_dict.pop(key)


def edit_obj(module, payload, connection):
    url = obj_url
    code, response = connection.send_request(url, payload, 'PUT')

    return code, response


def get_obj(module, connection):
    payload = {}
    url = obj_url
    code, response = connection.send_request(url, payload, 'GET')

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

    return res, err_msg


def main():
    argument_spec = dict(
        action=dict(type='str', required=True),
        mode=dict(type='str'),
        mode_val=dict(type='str'),
        group_id=dict(type='int'),
        group_name=dict(type='str'),
        priority=dict(type='int'),
        override=dict(type='str'),
        override_val=dict(type='str'),
        network_type=dict(type='str'),
        network_type_val=dict(type='str'),
        tunnel_local=dict(type='str'),
        tunnel_peer=dict(type='str'),
        hbdev=dict(type='str'),
        hbdev_val=dict(type='str'),
        hbdev_backup=dict(type='str'),
        hbdev_backup_val=dict(type='str'),
        boot_time=dict(type='int'),
        hb_interval=dict(type='int'),
        hb_lost_threshold=dict(type='int'),
        arps=dict(type='int'),
        arp_interval=dict(type='int'),
        monitor=dict(type='str'),
        lacp_ha_slave=dict(type='str'),
        lacp_ha_slave_val=dict(type='str'),
        ha_mgmt_status=dict(type='str'),
        ha_mgmt_status_val=dict(type='str'),
        ha_mgmt_interface=dict(type='str'),
        session_pickup=dict(type='str'),
        session_pickup_val=dict(type='str'),
        session_sync_dev=dict(type='str'),
        session_sync_broadcast=dict(type='str'),
        session_sync_broadcast_val=dict(type='str'),
        session_warm_up=dict(type='int'),
        schedule=dict(type='str'),
        schedule_val=dict(type='str'),
        weight_1=dict(type='int'),
        weight_2=dict(type='int'),
        weight_3=dict(type='int'),
        weight_4=dict(type='int'),
        weight_5=dict(type='int'),
        weight_6=dict(type='int'),
        weight_7=dict(type='int'),
        weight_8=dict(type='int'),
        link_failed_signal=dict(type='str'),
        link_failed_signal_val=dict(type='str'),
        l7_persistence_sync=dict(type='str'),
        l7_persistence_sync_val=dict(type='str'),
        eip_addr=dict(type='str'),
        eip_aid=dict(type='str'),
        ha_eth_type=dict(type='str'),
        hc_eth_type=dict(type='str'),
        l2ep_eth_type=dict(type='str'),
        server_policy_hlck=dict(type='str'),
        server_policy_hlck_val=dict(type='str'),
        multi_cluster=dict(type='str'),
        multi_cluster_val=dict(type='str'),
        multi_cluster_group=dict(type='str'),
        multi_cluster_group_val=dict(type='str'),
        multi_cluster_switch_by=dict(type='str'),
        multi_cluster_switch_by_val=dict(type='str'),
        multi_cluster_move_primary_cluster=dict(type='str'),
        multi_cluster_move_primary_cluster_val=dict(type='str'),
        encryption=dict(type='str'),
        encryption_val=dict(type='str'),
        cluster_arp=dict(type='str'),
        cluster_arp_val=dict(type='str'),
        sdn_connector=dict(type='str'),
        sdn_connector_val=dict(type='str'),
        lb_name=dict(type='str'),
        lb_ocid=dict(type='str'),
    )
    argument_spec.update(fwebos_argument_spec)

    required_if = [('mode')]
    module = AnsibleModule(argument_spec=argument_spec,
                           required_if=required_if)
    action = module.params['action']
    result = {}
    connection = Connection(module._socket_path)
    param_pass, param_err = param_check(module, connection)
    if not param_pass:
        result['err_msg'] = param_err
        result['failed'] = True
    elif action == 'get':
        code, response = get_obj(module, connection)
        result['res'] = response
    elif action == 'edit':
        code, data = get_obj(module, connection)
        if 'results' in data.keys() and data['results'] and type(data['results']) is not int:
            res, new_data = needs_update(module, data['results'])
        else:
            result['failed'] = True
            res = False
            result['err_msg'] = 'Entry not found'
        if res:
            new_data1 = {}
            new_data1['data'] = new_data
            code, response = edit_obj(module, new_data1, connection)
            result['res'] = response
            result['changed'] = True
    else:
        result['err_msg'] = 'error action: ' + action
        result['failed'] = True

    # if 'res' in result.keys() and type(result['res']) is dict\
    #        and type(result['res']['results']) is int and result['res']['results'] < 0:
        # result['err_msg'] = get_err_msg(connection, result['res']['payload'])
    #    result['changed'] = False
    #    result['failed'] = True
    if 'errcode' in str(result):
        result['changed'] = False
        result['failed'] = True
    module.exit_json(**result)


if __name__ == '__main__':
    main()
