## FortiWeb Ansible Collection
***

The collection is the FortiWeb Ansible Automation project. It includes the modules that are able to configure FortiWeb OS features.

## Modules
The collection provides the following modules:


* `fwebos_admin` Configure FortiWeb admin
* `fwebos_admin_profiles` Configure FortiWeb admin profiles
* `fwebos_backup_download` Download FortiWeb config file
* `fwebos_certificate_ca` Config FortiWeb server objects CA 
* `fwebos_certificate_ca_group` Config FortiWeb server objects CA group
* `fwebos_certificate_ca_group_member` Config FortiWeb server objects group member
* `fwebos_certificate_ca_tsl` Config FortiWeb server objects TSL CA
* `fwebos_certificate_crl` Config FortiWeb server objects CRL
* `fwebos_certificate_crl_group` Config FortiWeb server objects CRL group
* `fwebos_certificate_crl_group_member` Config FortiWeb server objects CRL group member
* `fwebos_certificate_intermediate_ca` Config FortiWeb server objects Intermediate CA
* `fwebos_certificate_intermediate_ca_group` Config FortiWeb server objects Intermediate CA group
* `fwebos_certificate_intermediate_ca_group_member` Config FortiWeb server objects Intermediate CA group member
* `fwebos_certificate_letsencrypt` Config FortiWeb server objects Letsencrypt
* `fwebos_certificate_letsencrypt_issue` Call FortiWeb server objects Letsencrypt issue action
* `fwebos_certificate_letsencrypt_revoke` Call FortiWeb server objects Letsencrypt revoke action
* `fwebos_certificate_local_csr` Config FortiWeb server objects Local
* `fwebos_certificate_local_import_certificate` Upload local certificates to FortiWeb
* `fwebos_certificate_local_multi` Config FortiWeb server objects Local Multi-certificate
* `fwebos_certificate_ocsp_stapling` Config FortiWeb server objects OCSP Stapling
* `fwebos_certificate_offline_sni_group` Config FortiWeb server objects SNI Offline SNI
* `fwebos_certificate_offline_sni_member` Config FortiWeb server objects SNI Offline SNI member
* `fwebos_certificate_public_key_pinning` Config FortiWeb server objects Public Key Pinning
* `fwebos_certificate_sign_ca` Config FortiWeb server objects Sign CA
* `fwebos_certificate_sni_group` Config FortiWeb server objects SNI Inline SNI
* `fwebos_certificate_sni_member` Config FortiWeb server objects SNI Inline SNI member
* `fwebos_certificate_urlcert_group` Config FortiWeb server objects URL Certificate group
* `fwebos_certificate_urlcert_list` Config FortiWeb server objects URL Certificate list
* `fwebos_certificate_verify` Config FortiWeb server objects Certificate Verify
* `fwebos_certificate_verify_server` Config FortiWeb server objects Server Certificate Verify
* `fwebos_certificate_xml_certificate_client` Config FortiWeb server objects XML Certificate Client Certificate
* `fwebos_certificate_xml_certificate_server` Config FortiWeb server objects XML Certificate Server Certificate
* `fwebos_certificate_xml_client_group` Config FortiWeb server objects XML Certificate Client group
* `fwebos_certificate_xml_client_group_member` Config FortiWeb server objects XML Certificate Client group member
* `fwebos_fortiguard_config` Config FortiWeb System FortiGuard info
* `fwebos_ha` Config FortiWeb HA options
* `fwebos_hsm_partion` Config FortiWeb HSM Partion
* `fwebos_hsm_server` Config FortiWeb HSM Server info
* `fwebos_hsm_server_download` Download HSM Server Certificate
* `fwebos_ntp` Config FortiWeb NTP settings
* `fwebos_server_policy` Config FortiWeb Policy Server Policy
* `fwebos_server_pool` Config FortiWeb server objects Server Pool
* `fwebos_server_pool_rule` Config FortiWeb server objects Server Pool member
* `fwebos_server_service` Config FortiWeb server objects Service
* `fwebos_snmp_community` Config FortiWeb SNMP v1/v2c Community
* `fwebos_snmp_sysinfo` Config FortiWeb SNMP system info
* `fwebos_snmp_user` Config FortiWeb SNMP v3 user
* `fwebos_system_setting` Config FortiWeb system settings
* `fwebos_virtual_ip` Config FortiWeb Network Virtual IP
* `fwebos_virtual_server` Config FortiWeb server objects virtual server
* `fwebos_virtual_server_vip` Assign FortiWeb virtual IP with virtual server
* `fwebos_waf_cookie_security` Config FortiWeb Web Protection Cookie Security
* `fwebos_waf_cookie_security_exception` Config FortiWeb Web Protection Cookie Security exceptions
* `fwebos_waf_custom_protection_group` Config FortiWeb Custom Policy policy
* `fwebos_waf_custom_protection_group_type_list` Assign FortiWeb Custom Policy Custom Rule to policy
* `fwebos_waf_custom_protection_rule` Config FortiWeb Custom Policy Custom Rule
* `fwebos_waf_custom_protection_rule_condition` Config FortiWeb Custom Policy Custom Rule conditions
* `fwebos_waf_file_upload_policy` Config FortiWeb Input Validation File Security
* `fwebos_waf_file_upload_policy_rule` Assign FortiWeb Input Validation File Security rules to policy
* `fwebos_waf_file_upload_rule` Config FortiWeb Input Validation File Security Rule
* `fwebos_waf_file_upload_rule_filetype` Config FortiWeb Input Validation File Security Rule file types
* `fwebos_waf_geo_block` Config FortiWeb IP Protection GEO IP
* `fwebos_waf_geo_block_country` Edit Country list in GEO IP Policy
* `fwebos_waf_http_constraints_exceptions` Config FortiWeb Web Protection HTTP Constraints exceptions
* `fwebos_waf_http_constraints_exceptions_list` Config FortiWeb Web Protection HTTP Constraints exceptions rules
* `fwebos_waf_http_protocol_parameter_restriction` Config FortiWeb Web Protection HTTP Constraints
* `fwebos_waf_ip` Config FortiWeb IP Protection IP List
* `fwebos_waf_ip_members` Config FortiWeb IP Protection IP List member
* `fwebos_waf_signature` Config FortiWeb Web Protection Signature
* `fwebos_waf_signature_filter_list` Config FortiWeb Web Protection Signature filter list
* `fwebos_waf_syntax` Config FortiWeb Web Protection SQL/XSS Syntax Based Detetction
* `fwebos_waf_url_access_policy` Config FortiWeb Web Protection URL Access policy
* `fwebos_waf_url_access_policy_rule` Assign URL policy rule to a policy
* `fwebos_waf_url_access_rule` Config FortiWeb Web Protection URL Access rules
* `fwebos_waf_url_access_rule_condition` Config FortiWeb Web Protection URL Access rules conditions
* `fwebos_waf_webshell` Config FortiWeb Web Protection Web Shell Detetction
* `fwebos_waf_xml_policy` Config FortiWeb API Protection XML Protection policy
* `fwebos_waf_xml_policy_rule_list` Assign FortiWeb API Protection XML Protection rule to a policy
* `fwebos_waf_xml_rule` Config FortiWeb API Protection XML Protection rule
* `fwebos_waf_xff` Config FortiWeb X-Forward-For policy
* `fwebos_waf_xff_ip_list` Config FortiWeb X-Forward-For policy ip list


## Usage
This collection includes some playbooks for configuring FortiWeb OS.
Here is a quick example:

Create the `hosts` inventory file
```
[fortiweb]
web01 ansible_host=192.168.1.99 ansible_user="admin" ansible_password="password"

[fortiweb:vars]
ansible_network_os=fortinet.fortiweb.fwebos
ansible_httpapi_use_ssl=yes
ansible_httpapi_validate_certs=no
ansible_httpapi_port=443

```

Run the playbook:
```bash
ansible-playbook -i hosts fwebos_system_setting.yml
```

This operation will adjust system idle timeout.

For other playbooks, please make sure required settings are already done in FortiWeb OS before running them.


