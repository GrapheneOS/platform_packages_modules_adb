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

#include "mdns.h"

#if defined(__ANDROID__)

#include "adb_mdns.h"
#include "adb_trace.h"
#include "sysdeps.h"

#include <dns_sd.h>
#include <endian.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <condition_variable>
#include <map>
#include <mutex>
#include <queue>
#include <random>
#include <string>
#include <thread>
#include <vector>

#include <adbd_auth.h>
#include <android-base/logging.h>
#include <android-base/properties.h>
#include <android-base/thread_annotations.h>
#include <com_android_adbdauth_flags.h>

using namespace std::chrono_literals;

// All mdns operations MUST happen on the mDNS thread. This TU is mono-threaded.
// This is done so operations requested by Frameworks are executed in the order
// they were issued. As a result, there are no mutex to protect the datastructures.

// Bonjour handles for registered services.
static DNSServiceRef mdns_refs[kNumADBDNSServices];

// Depending on how adbd registers services (mdnsd vs NsdManager), the operation can be
// performed right away (mdnsd) or later when the framework starts (NsdManager).
// In the latter case, we store the tcp port until we can request a registration.
static uint16_t adb_wifi_tcp_port = 0;

static AdbdAuthContext* auth_ctx;
void adbd_mdns_init(AdbdAuthContext* ctx) {
    auth_ctx = ctx;
}

static std::string RandomAlphaNumString(size_t len) {
    std::string ret;
    std::random_device rd;
    std::mt19937 mt(rd());
    // Generate values starting with zero and then up to enough to cover numeric
    // digits, small letters and capital letters (26 each).
    std::uniform_int_distribution<uint8_t> dist(0, 61);
    for (size_t i = 0; i < len; ++i) {
        uint8_t val = dist(mt);
        if (val < 10) {
            ret += static_cast<char>('0' + val);
        } else if (val < 36) {
            ret += static_cast<char>('A' + (val - 10));
        } else {
            ret += static_cast<char>('a' + (val - 36));
        }
    }
    return ret;
}

static std::string GenerateDeviceGuid() {
    // The format is adb-<serial_no>-<six-random-alphanum>
    std::string guid = "adb-";

    std::string serial = android::base::GetProperty("ro.serialno", "");
    if (serial.empty()) {
        // Generate 16-bytes of random alphanum string
        serial = RandomAlphaNumString(16);
    }
    guid += serial + '-';
    // Random six-char suffix
    guid += RandomAlphaNumString(6);
    return guid;
}

static std::string ReadDeviceGuid() {
    std::string guid = android::base::GetProperty("persist.adb.wifi.guid", "");
    if (guid.empty()) {
        guid = GenerateDeviceGuid();
        CHECK(!guid.empty());
        android::base::SetProperty("persist.adb.wifi.guid", guid);
    }
    return guid;
}

static void mdns_callback(DNSServiceRef /*ref*/,
                          DNSServiceFlags /*flags*/,
                          DNSServiceErrorType errorCode,
                          const char* /*name*/,
                          const char* /*regtype*/,
                          const char* /*domain*/,
                          void* /*context*/) {
    if (errorCode != kDNSServiceErr_NoError) {
        LOG(ERROR) << "Encountered mDNS registration error (" << errorCode << ").";
    }
}

static std::vector<char> buildTxtRecord() {
    std::map<std::string, std::string> attributes;
    attributes["v"] = std::to_string(ADB_SECURE_SERVICE_VERSION);
    attributes["name"] = android::base::GetProperty("ro.product.model", "");
    attributes["api"] = android::base::GetProperty("ro.build.version.sdk_full", "");

    // See https://tools.ietf.org/html/rfc6763 for the format of DNS TXT record.
    std::vector<char> record;
    for (auto const& [key, val] : attributes) {
        size_t length = key.size() + val.size() + 1;
        if (length > 255) {
            LOG(INFO) << "DNS TXT Record property " << key << "='" << val << "' is too large.";
            continue;
        }
        record.emplace_back(length);
        std::copy(key.begin(), key.end(), std::back_inserter(record));
        record.emplace_back('=');
        std::copy(val.begin(), val.end(), std::back_inserter(record));
    }

    return record;
}

static void register_mdns_service(int index, int port, const std::string& service_name) {
    if (mdns_refs[index] != nullptr) {
        LOG(ERROR) << "Unable to register mDNS service " << service_name << " (slot occupied)";
        return;
    }

    auto txtRecord = buildTxtRecord();
    auto error = DNSServiceRegister(
            &mdns_refs[index], 0, 0, service_name.c_str(), kADBDNSServices[index], nullptr, nullptr,
            htobe16((uint16_t)port), (uint16_t)txtRecord.size(),
            txtRecord.empty() ? nullptr : txtRecord.data(), mdns_callback, nullptr);

    if (error != kDNSServiceErr_NoError) {
        LOG(ERROR) << "Could not register mDNS service " << kADBDNSServices[index] << ", error ("
                   << error << ").";
    } else {
        VLOG(MDNS) << "adbd mDNS service " << kADBDNSServices[index] << " registered";
    }
}

static void unregister_mdns_service(int index) {
    VLOG(MDNS) << "Unregistering TLS service";
    if (mdns_refs[index] == nullptr) {
        return;
    }

    DNSServiceRefDeallocate(mdns_refs[index]);
    mdns_refs[index] = nullptr;
}

/**
 * All mdns operations happen on the same mdns thread.
 * This includes starting mdnsd, registering a service, and unregistering a service.
 * Tasks are pushed onto a FIFO and consumed by the mdns worker thread.
 */
class MdnsWorkerThread {
  public:
    static MdnsWorkerThread& Get() {
        static MdnsWorkerThread* worker = new MdnsWorkerThread();
        return *worker;
    }

    void AddTask(std::function<void()> task) {
        std::lock_guard<std::mutex> lock(worker_lock);
        tasks.push(std::move(task));
        cv.notify_one();
    }

  private:
    MdnsWorkerThread() {
        std::thread(&MdnsWorkerThread::Run, this).detach();

        // TODO Check if this is needed.
        //  If the process exists, all its fds will be closed, mdnsd will detect it and unregister
        //  the services.
        atexit(Teardown);
    }

    // This also tears down any adb secure mDNS services, if they exist.
    static void Teardown() {
        VLOG(MDNS) << "Tearing down mdns";
        MdnsWorkerThread::Get().AddTask([] {
            VLOG(MDNS) << "Unregistering tcp mDNS service";
            unregister_mdns_service(kADBTransportServiceRefIndex);
        });
        MdnsWorkerThread::Get().AddTask([] {
            VLOG(MDNS) << "Unregistering tls mDNS service";
            unregister_mdns_service(kADBSecureConnectServiceRefIndex);
        });
    }

    void EnsureMdnsdStarted() {
#if defined(__ANDROID__)
        if (android::base::GetProperty("init.svc.mdnsd", "") == "running") {
            return;
        }

        android::base::SetProperty("ctl.start", "mdnsd");

        if (!android::base::WaitForProperty("init.svc.mdnsd", "running", 5s)) {
            LOG(ERROR) << "Could not start mdnsd.";
        }
#endif
    }

    void Run() {
        // Make sure the adb wifi guid is generated.
        std::string guid = ReadDeviceGuid();
        CHECK(!guid.empty());

        while (true) {
            std::function<void()> task;
            {
                std::unique_lock<std::mutex> lock(worker_lock);
                android::base::ScopedLockAssertion assume_locked(worker_lock);
                cv.wait(lock, [this]() REQUIRES(worker_lock) { return !tasks.empty(); });
                task = tasks.front();
                tasks.pop();
            }

            EnsureMdnsdStarted();
            task();
        }
    }

    std::mutex worker_lock;
    std::condition_variable cv GUARDED_BY(worker_lock);
    std::queue<std::function<void()>> tasks GUARDED_BY(worker_lock);
};

// Public interface/////////////////////////////////////////////////////////////

void register_adb_tcp_service(int tcp_port) {
    // If we register service with framework, we defer registration until framework is started.
    // We will need to "remember" what tcp port was registered. We save it here.
    adb_wifi_tcp_port = tcp_port;

    if (com_android_adbdauth_flags_use_tls_lifecycle()) {
        return;
    }
    MdnsWorkerThread::Get().AddTask([tcp_port] {
        std::string hostname = ReadDeviceGuid();
        VLOG(MDNS) << "Registering tcp service on port: " << tcp_port;
        register_mdns_service(kADBTransportServiceRefIndex, tcp_port, hostname);
    });
}

void register_adb_tls_service(int tls_port) {
    auto service_name = ReadDeviceGuid();
    if (service_name.empty()) {
        LOG(WARNING) << "Unable to register TLS: DeviceGUID is empty";
        return;
    }

    if (com_android_adbdauth_flags_use_tls_lifecycle()) {
        if (__builtin_available(android 37, *)) {
            LOG(INFO) << "Registering TLS with framework '" << service_name << "'";
            adbd_auth_register_service(auth_ctx, service_name.c_str(),
                                       kADBDNSServices[kADBSecureConnectServiceRefIndex], tls_port);
            return;
        }
    }

    // Fallback to registering with mdnsd
    MdnsWorkerThread::Get().AddTask([=] {
        VLOG(MDNS) << "Registering tls service (" << service_name << ") on port: " << tls_port;
        register_mdns_service(kADBSecureConnectServiceRefIndex, tls_port, service_name);
    });
}

void unregister_adb_tls_service() {
    auto service_name = ReadDeviceGuid();
    if (service_name.empty()) {
        LOG(WARNING) << "Unable to unregister TLS: DeviceGUID is empty";
        return;
    }

    if (com_android_adbdauth_flags_use_tls_lifecycle()) {
        if (__builtin_available(android 37, *)) {
            adbd_auth_unregister_service(auth_ctx, service_name.c_str(),
                                         kADBDNSServices[kADBSecureConnectServiceRefIndex]);
            return;
        }
    }

    // Fallback to unregistering with mdnsd
    MdnsWorkerThread::Get().AddTask([] {
        VLOG(MDNS) << "Unregistering tls service";
        unregister_mdns_service(kADBSecureConnectServiceRefIndex);
    });
}

void on_framework_connected() {
    if (com_android_adbdauth_flags_use_tls_lifecycle() && adb_wifi_tcp_port != 0) {
        // This callback runs on adbd_auth thread. Since we are calling back into it, it is a good
        // idea to run on the mdns thread in order to avoid deadlocks.
        MdnsWorkerThread::Get().AddTask([] {
            auto service_name = ReadDeviceGuid();
            if (service_name.empty()) {
                LOG(WARNING) << "Unable to register TCP: DeviceGUID is empty";
                return;
            }

            if (__builtin_available(android 37, *)) {
                LOG(INFO) << "Registering TCP with framework '" << service_name << "'";
                adbd_auth_register_service(auth_ctx, service_name.c_str(),
                                           kADBDNSServices[kADBTransportServiceRefIndex],
                                           adb_wifi_tcp_port);
            }
        });
    }
}
#else
void register_adb_tcp_service(int tcp_port) {}
void register_adb_tls_service(int tls_port) {}
void unregister_adb_tls_service() {}
void adbd_mdns_init(AdbdAuthContext* ctx) {}
void on_framework_connected() {}
#endif  // defined(__ANDROID__)