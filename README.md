EMQ
=========

A ansible role for installing emq on VMs.

Role Variables
--------------

All necessary defaults variables are inside defaults/main.yml, vars/main.yml, and any variables that can/should be set via parameters to the role.

## Details

### Cluster

- `cluster_name`:  Cluster name.
- `cluster_proto_dist`:  Specify the erlang distributed protocol.
  - **Value:**
    - **inet_tcp**: the default; handles TCP streams with IPv4 addressing.
    - **inet6_tcp**: handles TCP with IPv6 addressing.
    - **inet_tls**: using TLS for Erlang Distribution.

- `cluster_discovery`: Cluster auto-discovery strategy.
  - **Value:**
    - **manual**: Manual join command (default)
    - **static**: Static node list
    - **mcast**:  IP Multicast
    - **dns**:    DNS A Record
    - **etcd**:   etcd
    - **k8s**:    Kubernetes

- `cluster_autoheal`: Enable cluster autoheal from network partition.
  - **Value:**
    - **on** (default)
    - **off**

- `cluster_autoclean`: Autoclean down node. A down node will be removed from the cluster if this value > 0.
  - **Value:** h=hour, m=minutes and s=second (default: 5m).

#### Cluster: using static node list

- `cluster_static_seeds`: Node list of the cluster.
  - **Example:**
    - cluster_static_seeds: emqx1@127.0.0.1,emqx2@127.0.0.1

#### Cluster: using IP Multicast

- `cluster_mcast_addr`: IP Multicast Address.
- `cluster_mcast_ports`: Multicast Ports.
- `cluster_mcast_iface`: Multicast Iface (default: 0.0.0.0).
- `cluster_mcast_ttl`: Multicast Ttl.
  - **Value:** 0-255
- `cluster_mcast_loop`: Multicast loop.
  - **Value:**
    - **on** 
    - **off**

#### Cluster: using DNS A records.
- `cluster_dns_name`: DNS name.
- `cluster_dns_app`: The App name is used to build 'node.name' with IP address.

#### Cluster: using etcd.
- `cluster_etcd_server`: Etcd server list, seperated by ','.
- `cluster_etcd_prefix`: The prefix helps build nodes path in etcd. Each node in the cluster will create a path in etcd: v2/keys/<prefix>/<cluster.name>/<node.name>
- `cluster_etcd_node_ttl`: The TTL for node's path in etcd (default: 1m).
- `cluster_etcd_ssl_keyfile`: Path to a file containing the client's private PEM-encoded key.
- `cluster_etcd_ssl_certfile`: The path to a file containing the client's certificate.
  - **Example:**
    - cluster_etcd_ssl_certfile: /etc/emqx/certs/client-key.pem
- `cluster_etcd_ssl_cacertfile`: Path to the file containing PEM-encoded CA certificates. The CA certificates are used during server authentication and when building the client certificate chain.
  - **Example:**
    - cluster_etcd_ssl_cacertfile: /etc/emqx/certs/ca.pem

#### Cluster: using Kubernetes

- `cluster_k8s_apiserver`: Kubernetes API server list, seperated by ','.
- `cluster_k8s_service_name`: The service name helps lookup EMQ nodes in the cluster.
- `cluster_k8s_address_type`: The address type is used to extract host from k8s service.
- `cluster_k8s_app_name`: The app name helps build 'node.name'.
- `cluster_k8s_suffix`: The suffix added to dns and hostname get from k8s service.
- `cluster_k8s_namespace`: Kubernetes Namespace.

<!--- 
### Node
- `node_name`: emqx@{{ inventory_hostname }}
- `node_cookie`: emqxsecretcookie
- `node_data_dir`: /var/lib/emqx
- `node_heartbeat`: on
- `node_async_threads`: 4
- `node_process_limit`: 2097152
- `node_max_ports`: 1048576
- `node_dist_buffer_size`: 8MB
- `node_max_ets_tables`: 262144
- `node_global_gc_interval`: 15m
- `node_fullsweep_after`: 1000
- `node_crash_dump`: /var/log/emqx/crash.dump
- `node_ssl_dist_optfile`: /etc/emqx/ssl_dist.conf
- `node_dist_net_ticktime`: 120
- `node_dist_listen_min`: 6369
- `node_dist_listen_max`: 6369

### RPC
- `rpc_mode`: async
- `rpc_async_batch_size`: 256
- `rpc_port_discovery`: stateless
- `rpc_tcp_server_port`: 5369
- `rpc_tcp_client_port`: 5369
- `rpc_tcp_client_num`: 1
- `rpc_connect_timeout`: 5s
- `rpc_send_timeout`: 5s
- `rpc_authentication_timeout`: 5s
- `rpc_call_receive_timeout`: 15s
- `rpc_socket_keepalive_idle`: 900s
- `rpc_socket_keepalive_interval`: 75s
- `rpc_socket_keepalive_count`: 9
- `rpc_socket_sndbuf`: 1MB
- `rpc_socket_recbuf`: 1MB
- `rpc_socket_buffer`: 1MB

### Log 
- `log_to`: both
- `log_level`: warning
- `log_dir`: /var/log/emqx
- `log_file`: emqx.log
- `log_chars_limit`: 8192
- `log_rotation`: on
- `log_rotation_size`: 10MB
- `log_rotation_count`: 5
- `log_info_file `: info.log
- `log_error_file`: error.log
- `log_sync_mode_qlen`: 100
- `log_drop_mode_qlen`: 3000
- `log_flush_qlen`: 8000
- `log_overload_kill`: on
- `log_overload_kill_qlen`: 20000
- `log_overload_kill_mem_size`: 30MB
- `log_overload_kill_restart_after`: 5s
- `log_burst_limit`: 20000, 1s

### Authentication/Access Control
- `allow_anonymous`: true
- `acl_nomatch`: allow
- `acl_file`: /etc/emqx/acl.conf
- `enable_acl_cache`: on
- `acl_cache_max_size`: 32
- `acl_cache_ttl`: 1m
- `acl_deny_action`: ignore
- `flapping_detect_policy`: 30, 1m, 5m

### MQTT Protocol
- `mqtt_max_packet_size`: 1MB
- `mqtt_max_clientid_len`: 65535
- `mqtt_max_topic_levels`: 0
- `mqtt_max_qos_allowed`: 2
- `mqtt_max_topic_alias`: 65535
- `mqtt_retain_available`: true
- `mqtt_wildcard_subscription`: true
- `mqtt_shared_subscription`: true
- `mqtt_ignore_loop_deliver`: false
- `mqtt_strict_mode`: false
- `mqtt_response_information`: example

### Zones
#### External Zone
- `zone_external_idle_timeout`: 15s
- `zone_external_enable_acl`: on
- `zone_external_enable_ban`: on
- `zone_external_enable_stats`: on
- `zone_external_acl_deny_action`: ignore
- `zone_external_force_gc_policy`: 16000|16MB
- `zone_external_force_shutdown_policy`: 32000|32MB
- `zone_external_max_packet_size`: 64KB
- `zone_external_max_clientid_len`: 1024
- `zone_external_max_topic_levels`: 7
- `zone_external_max_qos_allowed`: 2
- `zone_external_max_topic_alias`: 65535
- `zone_external_retain_available`: true
- `zone_external_wildcard_subscription`: false
- `zone_external_shared_subscription`: false
- `zone_external_server_keepalive`: 0
- `zone_external_keepalive_backoff`: 0.75
- `zone_external_max_subscriptions`: 0
- `zone_external_upgrade_qos`: off
- `zone_external_max_inflight`: 32
- `zone_external_retry_interval`: 30s
- `zone_external_max_awaiting_rel`: 100
- `zone_external_await_rel_timeout`: 300s
- `zone_external_session_expiry_interval`: 2h
- `zone_external_max_mqueue_len`: 1000
- `zone_external_mqueue_priorities`: none
- `zone_external_mqueue_default_priority`: highest
- `zone_external_mqueue_store_qos0`: true
- `zone_external_enable_flapping_detect`: off
- `zone_external_rate_limit_conn_messages_in`: 100,10s
- `zone_external_rate_limit_conn_bytes_in`: 100KB,10s
- `zone_external_quota_conn_messages_routing`: 100,1s
- `zone_external_quota_overall_messages_routing`: 200000,1s
- `zone_external_mountpoint`: devicebound/
- `zone_external_use_username_as_clientid`: false
- `zone_external_ignore_loop_deliver`: false
- `zone_external_strict_mode`: false
- `zone_external_response_information`: example

#### Internal Zone
- `zone_internal_allow_anonymous`: true
- `zone_internal_enable_stats`: on
- `zone_internal_enable_acl`: off
- `zone_internal_acl_deny_action`: ignore
- `zone_internal_force_gc_policy`: 128000|128MB
- `zone_internal_wildcard_subscription`: true
- `zone_internal_shared_subscription`: true
- `zone_internal_max_subscriptions`: 0
- `zone_internal_max_inflight`: 128
- `zone_internal_max_awaiting_rel`: 1000
- `zone_internal_max_mqueue_len`: 10000
- `zone_internal_mqueue_store_qos0`: true
- `zone_internal_enable_flapping_detect`: off
- `zone_internal_force_shutdown_policy`: 128000|128MB
- `zone_internal_mountpoint`: cloudbound/
- `zone_internal_ignore_loop_deliver`: false
- `zone_internal_strict_mode`: false
- `zone_internal_response_information`: example
- `zone_internal_bypass_auth_plugins`: true

### Listeners
#### MQTT/TCP - External TCP Listener for MQTT Protocol
- `listener_tcp_external: 0.0.0.0`:1883
- `listener_tcp_external_acceptors`: 8
- `listener_tcp_external_max_connections`: 1024000
- `listener_tcp_external_max_conn_rate`: 1000
- `listener_tcp_external_active_n`: 100
- `listener_tcp_external_zone`: external
- `listener_tcp_external_access_1`: allow all
- `listener_tcp_external_proxy_protocol`: on
- `listener_tcp_external_proxy_protocol_timeout`: 3s
- `listener_tcp_external_peer_cert_as_username`: cn
- `listener_tcp_external_backlog`: 1024
- `listener_tcp_external_send_timeout`: 15s
- `listener_tcp_external_send_timeout_close`: on
- `listener_tcp_external_recbuf`: 2KB
- `listener_tcp_external_sndbuf`: 2KB
- `listener_tcp_external_buffer`: 2KB
- `listener_tcp_external_tune_buffer`: off
- `listener_tcp_external_nodelay`: true
- `listener_tcp_external_reuseaddr`: true

#### Internal TCP Listener for MQTT Protocol
- `listener_tcp_internal: 127.0.0.1`:11883
- `listener_tcp_internal_acceptors`: 4
- `listener_tcp_internal_max_connections`: 1024000
- `listener_tcp_internal_max_conn_rate`: 1000
- `listener_tcp_internal_active_n`: 1000
- `listener_tcp_internal_zone`: internal
- `listener_tcp_internal_backlog`: 512
- `listener_tcp_internal_send_timeout`: 5s
- `listener_tcp_internal_send_timeout_close`: on
- `listener_tcp_internal_recbuf`: 64KB
- `listener_tcp_internal_sndbuf`: 64KB
- `listener_tcp_internal_buffer`: 16KB
- `listener_tcp_internal_tune_buffer`: off
- `listener_tcp_internal_nodelay`: false
- `listener_tcp_internal_reuseaddr`: true

#### MQTT/SSL - External SSL Listener for MQTT Protocol
- `listener_ssl_external`: 8883
- `listener_ssl_external_acceptors`: 16
- `listener_ssl_external_max_connections`: 102400
- `listener_ssl_external_max_conn_rate`: 500
- `listener_ssl_external_active_n`: 100
- `listener_ssl_external_zone`: external
- `listener_ssl_external_access_1`: allow all
- `listener_ssl_external_proxy_protocol`: on
- `listener_ssl_external_proxy_protocol_timeout`: 3s
- `listener_ssl_external_tls_versions`: tlsv1.2,tlsv1.1,tlsv1
- `listener_ssl_external_handshake_timeout`: 15s
- `listener_ssl_external_keyfile`: /etc/emqx/certs/key.pem
- `listener_ssl_external_certfile`: /etc/emqx/certs/cert.pem
- `listener_ssl_external_cacertfile`: /etc/emqx/certs/cacert.pem
- `listener_ssl_external_dhfile`: /etc/emqx/certs/dh-params.pem
- `listener_ssl_external_verify`: verify_peer
- `listener_ssl_external_fail_if_no_peer_cert`: true
- `listener_ssl_external_ciphers`: ECDHE-ECDSA-AES256-GCM-SHA384,ECDHE-RSA-AES256-GCM-SHA384,ECDHE-ECDSA-AES256-SHA384,ECDHE-RSA-AES256-SHA384,ECDHE-ECDSA-DES-CBC3-SHA,ECDH-ECDSA-AES256-GCM-SHA384,ECDH-RSA-AES256-GCM-SHA384,ECDH-ECDSA-AES256-SHA384,ECDH-RSA-AES256-SHA384,DHE-DSS-AES256-GCM-SHA384,DHE-DSS-AES256-SHA256,AES256-GCM-SHA384,AES256-SHA256,ECDHE-ECDSA-AES128-GCM-SHA256,ECDHE-RSA-AES128-GCM-SHA256,ECDHE-ECDSA-AES128-SHA256,ECDHE-RSA-AES128-SHA256,ECDH-ECDSA-AES128-GCM-SHA256,ECDH-RSA-AES128-GCM-SHA256,ECDH-ECDSA-AES128-SHA256,ECDH-RSA-AES128-SHA256,DHE-DSS-AES128-GCM-SHA256,DHE-DSS-AES128-SHA256,AES128-GCM-SHA256,AES128-SHA256,ECDHE-ECDSA-AES256-SHA,ECDHE-RSA-AES256-SHA,DHE-DSS-AES256-SHA,ECDH-ECDSA-AES256-SHA,ECDH-RSA-AES256-SHA,AES256-SHA,ECDHE-ECDSA-AES128-SHA,ECDHE-RSA-AES128-SHA,DHE-DSS-AES128-SHA,ECDH-ECDSA-AES128-SHA,ECDH-RSA-AES128-SHA,AES128-SHA
- `listener_ssl_external_psk_ciphers`: PSK-AES128-CBC-SHA,PSK-AES256-CBC-SHA,PSK-3DES-EDE-CBC-SHA,PSK-RC4-SHA
- `listener_ssl_external_secure_renegotiate`: off
- `listener_ssl_external_reuse_sessions`: on
- `listener_ssl_external_honor_cipher_order`: on
- `listener_ssl_external_peer_cert_as_username`: cn
- `listener_ssl_external_backlog`: 1024
- `listener_ssl_external_send_timeout`: 15s
- `listener_ssl_external_send_timeout_close`: on
- `listener_ssl_external_recbuf`: 4KB
- `listener_ssl_external_sndbuf`: 4KB
- `listener_ssl_external_buffer`: 4KB
- `listener_ssl_external_tune_buffer`: off
- `listener_ssl_external_nodelay`: true
- `listener_ssl_external_reuseaddr`: true

#### External WebSocket listener for MQTT protocol
- `listener_ws_external`: 8083
- `listener_ws_external_mqtt_path`: /mqtt
- `listener_ws_external_acceptors`: 4
- `listener_ws_external_max_connections`: 102400
- `listener_ws_external_max_conn_rate`: 1000
- `listener_ws_external_active_n`: 100
- `listener_ws_external_zone`: external
- `listener_ws_external_access_1`: allow all
- `listener_ws_external_verify_protocol_header`: on
- `listener_ws_external_proxy_protocol`: on
- `listener_ws_external_proxy_protocol_timeout`: 3s
- `listener_ws_external_backlog`: 1024
- `listener_ws_external_send_timeout`: 15s
- `listener_ws_external_send_timeout_close`: on
- `listener_ws_external_recbuf`: 2KB
- `listener_ws_external_sndbuf`: 2KB
- `listener_ws_external_buffer`: 2KB
- `listener_ws_external_tune_buffer`: off
- `listener_ws_external_nodelay`: true
- `listener_ws_external_compress`: true
- `listener_ws_external_deflate_opts_level`: default
- `listener_ws_external_deflate_opts_mem_level`: 8
- `listener_ws_external_deflate_opts_strategy`: default
- `listener_ws_external_deflate_opts_server_context_takeover`: takeover
- `listener_ws_external_deflate_opts_client_context_takeover`: takeover
- `listener_ws_external_deflate_opts_server_max_window_bits`: 15
- `listener_ws_external_deflate_opts_client_max_window_bits`: 15
- `listener_ws_external_idle_timeout`: 60s
- `listener_ws_external_max_frame_size`: 0
- `listener_ws_external_mqtt_piggyback`: multiple

#### External WebSocket/SSL listener for MQTT Protocol
- `listener_wss_external`: 8084
- `listener_wss_external_mqtt_path`: /mqtt
- `listener_wss_external_acceptors`: 4
- `listener_wss_external_max_connections`: 16
- `listener_wss_external_max_conn_rate`: 1000
- `listener_wss_external_active_n`: 100
- `listener_wss_external_zone`: external
- `listener_wss_external_access_1`: allow all
- `listener_wss_external_verify_protocol_header`: on
- `listener_wss_external_proxy_protocol`: on
- `listener_wss_external_proxy_protocol_timeout`: 3s
- `listener_wss_external_tls_versions`: tlsv1.2,tlsv1.1,tlsv1
- `listener_wss_external_keyfile`: /etc/emqx/certs/key.pem
- `listener_wss_external_certfile`: /etc/emqx/certs/cert.pem
- `listener_wss_external_cacertfile`: /etc/emqx/certs/cacert.pem
- `listener_ssl_external_dhfile`: /etc/emqx/certs/dh-params.pem
- `listener_wss_external_verify`: verify_peer
- `listener_wss_external_fail_if_no_peer_cert`: true
- `listener_wss_external_ciphers`: ECDHE-ECDSA-AES256-GCM-SHA384,ECDHE-RSA-AES256-GCM-SHA384,ECDHE-ECDSA-AES256-SHA384,ECDHE-RSA-AES256-SHA384,ECDHE-ECDSA-DES-CBC3-SHA,ECDH-ECDSA-AES256-GCM-SHA384,ECDH-RSA-AES256-GCM-SHA384,ECDH-ECDSA-AES256-SHA384,ECDH-RSA-AES256-SHA384,DHE-DSS-AES256-GCM-SHA384,DHE-DSS-AES256-SHA256,AES256-GCM-SHA384,AES256-SHA256,ECDHE-ECDSA-AES128-GCM-SHA256,ECDHE-RSA-AES128-GCM-SHA256,ECDHE-ECDSA-AES128-SHA256,ECDHE-RSA-AES128-SHA256,ECDH-ECDSA-AES128-GCM-SHA256,ECDH-RSA-AES128-GCM-SHA256,ECDH-ECDSA-AES128-SHA256,ECDH-RSA-AES128-SHA256,DHE-DSS-AES128-GCM-SHA256,DHE-DSS-AES128-SHA256,AES128-GCM-SHA256,AES128-SHA256,ECDHE-ECDSA-AES256-SHA,ECDHE-RSA-AES256-SHA,DHE-DSS-AES256-SHA,ECDH-ECDSA-AES256-SHA,ECDH-RSA-AES256-SHA,AES256-SHA,ECDHE-ECDSA-AES128-SHA,ECDHE-RSA-AES128-SHA,DHE-DSS-AES128-SHA,ECDH-ECDSA-AES128-SHA,ECDH-RSA-AES128-SHA,AES128-SHA
- `listener_wss_external_psk_ciphers`: PSK-AES128-CBC-SHA,PSK-AES256-CBC-SHA,PSK-3DES-EDE-CBC-SHA,PSK-RC4-SHA
- `listener_wss_external_secure_renegotiate`: off
- `listener_wss_external_reuse_sessions`: on
- `listener_wss_external_honor_cipher_order`: on
- `listener_wss_external_peer_cert_as_username`: cn
- `listener_wss_external_backlog`: 1024
- `listener_wss_external_send_timeout`: 15s
- `listener_wss_external_send_timeout_close`: on
- `listener_wss_external_recbuf`: 4KB
- `listener_wss_external_sndbuf`: 4KB
- `listener_wss_external_buffer`: 4KB
- `listener_wss_external_nodelay`: true
- `listener_wss_external_compress`: true
- `listener_wss_external_deflate_opts_level`: default
- `listener_wss_external_deflate_opts_mem_level`: 8
- `listener_wss_external_deflate_opts_strategy`: default
- `listener_wss_external_deflate_opts_server_context_takeover`: takeover
- `listener_wss_external_deflate_opts_client_context_takeover`: takeover
- `listener_wss_external_deflate_opts_server_max_window_bits`: 15
- `listener_wss_external_deflate_opts_client_max_window_bits`: 15
- `listener_wss_external_idle_timeout`: 60s
- `listener_wss_external_max_frame_size`: 0
- `listener_wss_external_mqtt_piggyback`: multiple

### Modules
- `modules_loaded_file`: /var/lib/emqx/loaded_modules
#### Presence Module
- `module_presence_qos`: Sets the QoS for presence MQTT message.
  - **Value:**
    - 0
    - 1
    - 2   
#### Subscription Module 
- `module_subscription_1_topic`: Subscribe the Topics automatically when client connected.
- **Example:**
  - module_subscription_1_topic: connected/%c/%u
- `module_subscription_1_qos`: Qos of the proxy subscription.
  - **Value:**
    - 0
    - 1
    - 2   
- `module_subscription_1_nl`:  No Local of the proxy subscription options. This configuration only takes effect in the MQTT V5 protocol.
  - **Value:**
    - 0
    - 1
- `module_subscription_1_rap`: Retain As Published of the proxy subscription options. This configuration only takes effect in the MQTT V5 protocol.
  - **Value:**
    - 0
    - 1
- `module_subscription_1_rh`: Retain Handling of the proxy subscription options. This configuration only takes effect in the MQTT V5 protocol.
  - **Value:**
    - 0
    - 1
    - 2  
#### Rewrite Module
- `module_rewrite_pub_rule_1`: 
  - **Value:** {rewrite, Topic, Re, Dest}
  - **Example:**
    - module_rewrite_pub_rule_1: x/# ^x/y/(.+)$ z/y/$1
- `module_rewrite_sub_rule_1`: 
  - **Value:** {rewrite, Topic, Re, Dest}
  - **Example:**
    - module_rewrite_sub_rule_1: y/+/z/# ^y/(.+)/z/(.+)$ y/z/$2

### Plugins  
- `plugins_etc_dir`: The etc dir for plugins' config.
  - **Example:**
    - plugins_etc_dir: /etc/emqx/plugins/
- `plugins_loaded_file`: /var/lib/emqx/loaded_plugins
- `plugins_expand_plugins_dir`: /var/lib/emqx/plugins/

### Broker
- `broker_sys_interval`: 1m
- `broker_sys_heartbeat`: 30s
- `broker_session_locking_strategy`: quorum
- `broker_shared_subscription_strategy`: random
- `broker_shared_dispatch_ack_enabled`: false
- `broker_route_batch_clean`: off

### System Monitor
- `sysmon_long_gc`: Enable Long GC monitoring. Disable if the value is 0. notice: don't enable the monitor in production for: 
https://github.com/erlang/otp/blob/feb45017da36be78d4c5784d758ede619fa7bfd3/erts/emulator/beam/erl_gc.c#L421
- `sysmon_long_schedule`: 240ms
- `sysmon_large_heap`: 8MB
- `sysmon_busy_port`: false
- `sysmon_busy_dist_port`: true

- `os_mon_cpu_check_interval`: 60s
- `os_mon_cpu_high_watermark`: 80%
- `os_mon_cpu_low_watermark`: 60%
- `os_mon_mem_check_interval`: 60s
- `os_mon_sysmem_high_watermark`: 70%
- `os_mon_procmem_high_watermark`: 5%
- `vm_mon_check_interval`: 30s
- `vm_mon_process_high_watermark`: 80%
- `vm_mon_process_low_watermark`: 60%
- `alarm_actions`: log,publish
- `alarm_size_limit`: 1000
- `alarm_validity_period`: 24h
- `reloader_interval`: 60s
- `reloader_logfile`: reloader_log
- `retainer_storage_type`: ram
- `retainer_max_retained_messages`: 0
- `retainer_max_payload_size`: 1MB
- `retainer_expiry_interval`: 0
- `rule_engine_ignore_sys_message`: on
- `rule_engine_events_client_connected`: off
- `rule_engine_events_client_disconnected`: off
- `rule_engine_events_session_subscribed`: off
- `rule_engine_events_session_unsubscribed`: off
- `rule_engine_events_message_delivered`: off
- `rule_engine_events_message_acked`: off
- `rule_engine_events_message_dropped`: off
- `statsd_push_gateway_server: http://127_0_0_1`:9091
- `statsd_interval`: 15000 --->

### ClientId Authentication Plugin
- `auth_client_password_hash`: Password hash.
  - **Value:** plain | md5 | sha | sha256. 

### HTTP Auth/ACL Plugin
#### Authentication request.

- `auth_http_auth_req`: HTTP URL API path for authentication request
- `auth_http_auth_req_method`: 
  - **Value:**
    - post
    - get
- `auth_http_auth_req_content_type`: It only works when method=post.
  - **Value:**
    - json
    - x-www-form-urlencoded
- `auth_http_auth_req_params`: 
  - **Value:**
    - %u: username
    - %c: clientid
    - %a: ipaddress
    - %r: protocol
    - %P: password
    - %p: sockport of server accepted
    - %C: common name of client TLS cert
    - %d: subject of client TLS cert
  - **Example:**
    - auth_http_auth_req_params = clientid=%c,username=%u,password=%P

<!--- Superuser request. 

#   auth_http_acl_req: http://127.0.0.1:9999/auth
#   auth_http_acl_req_method: post
#   auth_http_acl_req_params: clientid=%c,username=%u,password=%P,token=%u
#   auth_http_request_retry_times: 3
#   auth_http_request_retry_interval: 1s
#   auth_http_request_retry_backoff: 2.0 

### EMQ X Dashboard


- `dashboard_default_user_login`: admin
- `dashboard_default_user_password`: public
#### HTTP Listener
- `dashboard_listener_http`: 18083
- `dashboard_listener_http_acceptors`: 4
- `dashboard_listener_http_max_clients`: 512
- `dashboard_listener_http_inet6`: false
- `dashboard_listener_http_ipv6_v6only`: false

#### HTTPS Listener
- `dashboard_listener_https`: 18084
- `dashboard_listener_https_acceptors`: 2
- `dashboard_listener_https_max_clients`: 512
- `dashboard_listener_https_inet6`: false
- `dashboard_listener_https_ipv6_v6only`: false
- `dashboard_listener_https_keyfile`: etc/certs/key_pem
- `dashboard_listener_https_certfile`: etc/certs/cert_pem
- `dashboard_listener_https_cacertfile`: etc/certs/cacert_pem
- `dashboard_listener_https_dhfile`: {{ platform_etc_dir }}/certs/dh-params_pem
- `dashboard_listener_https_verify`: verify_peer
- `dashboard_listener_https_fail_if_no_peer_cert`: true
- `dashboard_listener_https_tls_versions`: tlsv1_2,tlsv1_1,tlsv1
- `dashboard_listener_https_ciphers`: ECDHE-ECDSA-AES256-GCM-SHA384,ECDHE-RSA-AES256-GCM-SHA384,ECDHE-ECDSA-AES256-SHA384,ECDHE-RSA-AES256-SHA384,ECDHE-ECDSA-DES-CBC3-SHA,ECDH-ECDSA-AES256-GCM-SHA384,ECDH-RSA-AES256-GCM-SHA384,ECDH-ECDSA-AES256-SHA384,ECDH-RSA-AES256-SHA384,DHE-DSS-AES256-GCM-SHA384,DHE-DSS-AES256-SHA256,AES256-GCM-SHA384,AES256-SHA256,ECDHE-ECDSA-AES128-GCM-SHA256,ECDHE-RSA-AES128-GCM-SHA256,ECDHE-ECDSA-AES128-SHA256,ECDHE-RSA-AES128-SHA256,ECDH-ECDSA-AES128-GCM-SHA256,ECDH-RSA-AES128-GCM-SHA256,ECDH-ECDSA-AES128-SHA256,ECDH-RSA-AES128-SHA256,DHE-DSS-AES128-GCM-SHA256,DHE-DSS-AES128-SHA256,AES128-GCM-SHA256,AES128-SHA256,ECDHE-ECDSA-AES256-SHA,ECDHE-RSA-AES256-SHA,DHE-DSS-AES256-SHA,ECDH-ECDSA-AES256-SHA,ECDH-RSA-AES256-SHA,AES256-SHA,ECDHE-ECDSA-AES128-SHA,ECDHE-RSA-AES128-SHA,DHE-DSS-AES128-SHA,ECDH-ECDSA-AES128-SHA,ECDH-RSA-AES128-SHA,AES128-SHA
- `dashboard_listener_https_secure_renegotiate`: off
- `dashboard_listener_https_reuse_sessions`: on
- `dashboard_listener_https_honor_cipher_order`: on

### EMQ X Management Plugin
- `management_max_row_limit`: 10000
- `management_application_default_secret`: public
- `management_default_application_id`: admin
- `management_default_application_secret`: public
- `management_listener_http`: 8081
- `management_listener_http_acceptors`: 2
- `management_listener_http_max_clients`: 512
- `management_listener_http_backlog`: 512
- `management_listener_http_send_timeout`: 15s
- `management_listener_http_send_timeout_close`: on
- `management_listener_http_inet6`: false
- `management_listener_http_ipv6_v6only`: false
- `management_listener_https`: 8081
- `management_listener_https_acceptors`: 2
- `management_listener_https_max_clients`: 512
- `management_listener_https_backlog`: 512
- `management_listener_https_send_timeout`: 15s
- `management_listener_https_send_timeout_close`: on
- `management_listener_https_certfile`: etc/certs/cert_pem
- `management_listener_https_keyfile`: etc/certs/key_pem
- `management_listener_https_cacertfile`: etc/certs/cacert_pem
- `management_listener_https_verify`: verify_peer
- `management_listener_https_tls_versions`: tlsv1_2,tlsv1_1,tlsv1
- `management_listener_https_ciphers`: ECDHE-ECDSA-AES256-GCM-SHA384,ECDHE-RSA-AES256-GCM-SHA384,ECDHE-ECDSA-AES256-SHA384,ECDHE-RSA-AES256-SHA384,ECDHE-ECDSA-DES-CBC3-SHA,ECDH-ECDSA-AES256-GCM-SHA384,ECDH-RSA-AES256-GCM-SHA384,ECDH-ECDSA-AES256-SHA384,ECDH-RSA-AES256-SHA384,DHE-DSS-AES256-GCM-SHA384,DHE-DSS-AES256-SHA256,AES256-GCM-SHA384,AES256-SHA256,ECDHE-ECDSA-AES128-GCM-SHA256,ECDHE-RSA-AES128-GCM-SHA256,ECDHE-ECDSA-AES128-SHA256,ECDHE-RSA-AES128-SHA256,ECDH-ECDSA-AES128-GCM-SHA256,ECDH-RSA-AES128-GCM-SHA256,ECDH-ECDSA-AES128-SHA256,ECDH-RSA-AES128-SHA256,DHE-DSS-AES128-GCM-SHA256,DHE-DSS-AES128-SHA256,AES128-GCM-SHA256,AES128-SHA256,ECDHE-ECDSA-AES256-SHA,ECDHE-RSA-AES256-SHA,DHE-DSS-AES256-SHA,ECDH-ECDSA-AES256-SHA,ECDH-RSA-AES256-SHA,AES256-SHA,ECDHE-ECDSA-AES128-SHA,ECDHE-RSA-AES128-SHA,DHE-DSS-AES128-SHA,ECDH-ECDSA-AES128-SHA,ECDH-RSA-AES128-SHA,AES128-SHA
- `management_listener_https_fail_if_no_peer_cert`: true
- `management_listener_https_inet6`: false --->


### EMQ X monitoring 

#### emqx_prometheus for EMQ X

- `prometheus_push_gateway_server`: The Prometheus Push Gateway URL address, Note: You can comment out this line to disable it.
- `prometheus_interval`:  The metrics data push interval (millisecond) (default: 15000).