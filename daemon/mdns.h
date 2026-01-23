/*
 * Copyright (C) 2016 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#ifndef _DAEMON_MDNS_H_
#define _DAEMON_MDNS_H_

// mDNS advertises the TCP port ADBd is currently listening on for non-encrypted traffic.
void register_adb_tcp_service(int tcp_port);

// mDNS advertises the TLS port ADBd is currently listening on for encrypted traffic.
void register_adb_tls_service(int tls_port);
void unregister_adb_tls_service();

struct AdbdAuthContext;
// Pass the adbd_auth context so mdns operation can be requested from framework
void adbd_mdns_init(AdbdAuthContext* ctx);

// Callback for adbd_auth when the framework connects
void on_framework_connected();

#endif  // _DAEMON_MDNS_H_
