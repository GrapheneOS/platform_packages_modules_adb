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

#include "socket_spec.h"

#include <string>

#include <unistd.h>

#ifdef __linux__
#include <linux/vm_sockets.h>
#endif

#include <android-base/file.h>
#include <android-base/properties.h>
#include <android-base/stringprintf.h>
#include <gtest/gtest.h>

// If the socket spec is incorrectly specified (i.e w/o a "tcp:" prefix),
// check for the contents of the returned error string.
TEST(socket_spec, parse_tcp_socket_spec_failure_error_check) {
    std::string hostname, error, serial;
    int port;

    // spec needs to be prefixed with "tcp:"
    const std::string spec("sneakernet:5037");
    EXPECT_FALSE(parse_tcp_socket_spec(spec, &hostname, &port, &serial, &error));
    EXPECT_TRUE(error.find("sneakernet") != std::string::npos);
    EXPECT_EQ(error, "specification is not tcp: " + spec);
}

TEST(socket_spec, parse_tcp_socket_spec_just_port_success) {
    std::string hostname, error, serial;
    int port;
    EXPECT_TRUE(parse_tcp_socket_spec("tcp:5037", &hostname, &port, &serial, &error));
    EXPECT_EQ("", hostname);
    EXPECT_EQ(5037, port);
    EXPECT_EQ("", serial);
}

TEST(socket_spec, parse_tcp_socket_spec_bad_ports_failure) {
    std::string hostname, error, serial;
    int port;
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:", &hostname, &port, &serial, &error));
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:-1", &hostname, &port, &serial, &error));
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:65536", &hostname, &port, &serial, &error));
}

TEST(socket_spec, parse_tcp_socket_spec_host_and_port_success) {
    std::string hostname, error, serial;
    int port;
    EXPECT_TRUE(parse_tcp_socket_spec("tcp:localhost:1234", &hostname, &port, &serial, &error));
    EXPECT_EQ("localhost", hostname);
    EXPECT_EQ(1234, port);
    EXPECT_EQ("localhost:1234", serial);
}

TEST(socket_spec, parse_tcp_socket_spec_host_no_port_success) {
    std::string hostname, error, serial;
    int port;
    EXPECT_TRUE(parse_tcp_socket_spec("tcp:localhost", &hostname, &port, &serial, &error));
    EXPECT_EQ("localhost", hostname);
    EXPECT_EQ(5555, port);
    EXPECT_EQ("localhost:5555", serial);
}

TEST(socket_spec, parse_tcp_socket_spec_host_ipv4_no_port_success) {
    std::string hostname, error, serial;
    int port;
    EXPECT_TRUE(parse_tcp_socket_spec("tcp:127.0.0.1", &hostname, &port, &serial, &error));
    EXPECT_EQ("127.0.0.1", hostname);
    EXPECT_EQ(5555, port);
    EXPECT_EQ("127.0.0.1:5555", serial);
}

TEST(socket_spec, parse_tcp_socket_spec_host_bad_ports_failure) {
    std::string hostname, error, serial;
    int port;
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:localhost:", &hostname, &port, &serial, &error));
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:localhost:-1", &hostname, &port, &serial, &error));
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:localhost:65536", &hostname, &port, &serial, &error));
}

TEST(socket_spec, parse_tcp_socket_spec_host_ipv4_bad_ports_failure) {
    std::string hostname, error, serial;
    int port;
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:127.0.0.1:", &hostname, &port, &serial, &error));
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:127.0.0.1:-1", &hostname, &port, &serial, &error));
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:127.0.0.1:65536", &hostname, &port, &serial, &error));
}

TEST(socket_spec, parse_tcp_socket_spec_host_ipv6_bad_ports_failure) {
    std::string hostname, error, serial;
    int port;
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:2601:644:8e80:620:c63:50c9:8a91:8efa:", &hostname,
                                       &port, &serial, &error));
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:2601:644:8e80:620:c63:50c9:8a91:8efa:-1", &hostname,
                                       &port, &serial, &error));
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:2601:644:8e80:620:c63:50c9:8a91:8efa:65536", &hostname,
                                       &port, &serial, &error));
}

TEST(socket_spec, parse_tcp_socket_spec_ipv6_and_port_success) {
    std::string hostname, error, serial;
    int port;
    EXPECT_TRUE(parse_tcp_socket_spec("tcp:[::1]:1234", &hostname, &port, &serial, &error));
    EXPECT_EQ("::1", hostname);
    EXPECT_EQ(1234, port);
    EXPECT_EQ("[::1]:1234", serial);

    // Repeat with different format of ipv6
    EXPECT_TRUE(parse_tcp_socket_spec("tcp:[2601:644:8e80:620::fbbc]:2345", &hostname, &port,
                                      &serial, &error));
    EXPECT_EQ("2601:644:8e80:620::fbbc", hostname);
    EXPECT_EQ(2345, port);
    EXPECT_EQ("[2601:644:8e80:620::fbbc]:2345", serial);
}

TEST(socket_spec, parse_tcp_socket_spec_ipv6_no_port_success) {
    std::string hostname, error, serial;
    int port;
    EXPECT_TRUE(parse_tcp_socket_spec("tcp:::1", &hostname, &port, &serial, &error));
    EXPECT_EQ("::1", hostname);
    EXPECT_EQ(5555, port);
    EXPECT_EQ("[::1]:5555", serial);

    // Repeat with other supported formats of ipv6.
    EXPECT_TRUE(parse_tcp_socket_spec("tcp:2601:644:8e80:620::fbbc", &hostname, &port, &serial,
                                      &error));
    EXPECT_EQ("2601:644:8e80:620::fbbc", hostname);
    EXPECT_EQ(5555, port);
    EXPECT_EQ("[2601:644:8e80:620::fbbc]:5555", serial);

    EXPECT_TRUE(parse_tcp_socket_spec("tcp:2601:644:8e80:620:c63:50c9:8a91:8efa", &hostname, &port,
                                      &serial, &error));
    EXPECT_EQ("2601:644:8e80:620:c63:50c9:8a91:8efa", hostname);
    EXPECT_EQ(5555, port);
    EXPECT_EQ("[2601:644:8e80:620:c63:50c9:8a91:8efa]:5555", serial);

    EXPECT_TRUE(parse_tcp_socket_spec("tcp:2601:644:8e80:620:2d0e:b944:5288:97df", &hostname, &port,
                                      &serial, &error));
    EXPECT_EQ("2601:644:8e80:620:2d0e:b944:5288:97df", hostname);
    EXPECT_EQ(5555, port);
    EXPECT_EQ("[2601:644:8e80:620:2d0e:b944:5288:97df]:5555", serial);
}

TEST(socket_spec, parse_tcp_socket_spec_ipv6_bad_ports_failure) {
    std::string hostname, error, serial;
    int port;
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:[::1]", &hostname, &port, &serial, &error));
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:[::1]:", &hostname, &port, &serial, &error));
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:[::1]:-1", &hostname, &port, &serial, &error));

    EXPECT_TRUE(parse_tcp_socket_spec("tcp:2601:644:8e80:620:2d0e:b944:5288:97df", &hostname, &port,
                                      &serial, &error));
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:2601:644:8e80:620:2d0e:b944:5288:97df:", &hostname,
                                       &port, &serial, &error));
    EXPECT_FALSE(parse_tcp_socket_spec("tcp:2601:644:8e80:620:2d0e:b944:5288:97df:-1", &hostname,
                                       &port, &serial, &error));
}

TEST(socket_spec, get_host_socket_spec_port_success) {
    std::string error;
    EXPECT_EQ(5555, get_host_socket_spec_port("tcp:5555", &error));
    EXPECT_EQ(5555, get_host_socket_spec_port("tcp:localhost:5555", &error));
    EXPECT_EQ(5555, get_host_socket_spec_port("tcp:[::1]:5555", &error));
}

TEST(socket_spec, get_host_socket_spec_port_vsock_success) {
    std::string error;
#ifdef __linux__  // vsock is only supported on linux
    EXPECT_EQ(5555, get_host_socket_spec_port("vsock:5555", &error));
#else
    GTEST_SKIP() << "vsock is only supported on linux";
#endif
}

TEST(socket_spec, get_host_socket_spec_port_no_port) {
    std::string error;
    EXPECT_EQ(5555, get_host_socket_spec_port("tcp:localhost", &error));
    EXPECT_EQ(-1, get_host_socket_spec_port("vsock:localhost", &error));
}

TEST(socket_spec, get_host_socket_spec_port_bad_ports) {
    std::string error;
    EXPECT_EQ(-1, get_host_socket_spec_port("tcp:65536", &error));
    EXPECT_EQ(-1, get_host_socket_spec_port("tcp:-5", &error));

    // The following two expectations happen to fail on non-linux anyway(for
    // different reasons than "vsock is only supported on linux").
    EXPECT_EQ(-1, get_host_socket_spec_port("vsock:-5", &error));
    EXPECT_EQ(-1, get_host_socket_spec_port("vsock:5:5555", &error));
}

TEST(socket_spec, get_host_socket_spec_port_bad_string) {
    std::string error;
    EXPECT_EQ(-1, get_host_socket_spec_port("tcpz:5555", &error));
    EXPECT_EQ(-1, get_host_socket_spec_port("vsockz:5555", &error));
    EXPECT_EQ(-1, get_host_socket_spec_port("abcd:5555", &error));
    EXPECT_EQ(-1, get_host_socket_spec_port("abcd", &error));
}

TEST(socket_spec, socket_spec_listen_connect_tcp) {
    std::string error, serial;
    int port;
    unique_fd server_fd, client_fd;
    EXPECT_FALSE(socket_spec_connect(&client_fd, "tcp:localhost:7777", &port, &serial, &error));
    server_fd.reset(socket_spec_listen("tcp:7777", &error, &port));
    EXPECT_NE(server_fd.get(), -1);
    EXPECT_TRUE(socket_spec_connect(&client_fd, "tcp:localhost:7777", &port, &serial, &error));
    EXPECT_NE(client_fd.get(), -1);
}

TEST(socket_spec, socket_spec_listen_connect_vsock_success) {
#ifndef __linux__
    GTEST_SKIP() << "vsock is only supported on Linux";
#else
    std::string error, serial;
    int port = 0;
    unique_fd server_fd, client_fd;

    // Check if the port is available before trying to listen on it.
    // On cuttlefish devices, there is already a vsock server, for adb, running on port 5555.
    // So there's no need to setup another one (which would fail).
    sockaddr_vm addr{};
    addr.svm_family = AF_VSOCK;
    addr.svm_port = 5555;
#if ADB_HOST
    addr.svm_cid = 2;
#else
    addr.svm_cid = 1;
#endif
    socklen_t addr_len = sizeof(addr);
    unique_fd check_fd(socket(AF_VSOCK, SOCK_STREAM, 0));
    EXPECT_TRUE(check_fd.get() != -1);
    if (!bind(check_fd.get(), reinterpret_cast<struct sockaddr*>(&addr), addr_len)) {
        check_fd.reset();
        // No existing vsock server on port 5555, so create one (testing on a physical device).
        server_fd.reset(socket_spec_listen("vsock:5555", &error, &port));
        ASSERT_NE(server_fd.get(), -1) << error;
        ASSERT_EQ(port, 5555);
    }
#if ADB_HOST
    // Test with port passed as an argument.
    // On a Linux host, the CID for the host is 2 (VMADDR_CID_HOST).
    port = 5555;
    bool connected = socket_spec_connect(&client_fd, "vsock:2", &port, &serial, &error);
    // On old kernels, either vsock entirely, or the host CID, is not supported. Check for
    // "Connection refused" or "No such device", which indicate this case. Skip the test
    // case since it's not possible on the device under test.
    if (!connected && (errno == ECONNREFUSED || errno == ENODEV)) {
        GTEST_SKIP() << "vsock host not supported on this kernel";
    }

    EXPECT_NE(client_fd.get(), -1);
    client_fd.reset();

    // Test with port passed in the spec string.
    port = 0;
    EXPECT_TRUE(socket_spec_connect(&client_fd, "vsock:2:5555", &port, &serial, &error))
            << errno << ": " << strerror(errno);
    EXPECT_NE(client_fd.get(), -1);

    // On the host, any vsock port is allowed.
    server_fd.reset(socket_spec_listen("vsock:1234", &error, &port));
    port = 1234;
    EXPECT_TRUE(socket_spec_connect(&client_fd, "vsock:2", &port, &serial, &error))
            << errno << ": " << strerror(errno);
    EXPECT_NE(client_fd.get(), -1);
#else
    // On the device, only the loopback CID 1 will work, but only on new enough kernels and only on
    // Android S and above.
    if (android::base::GetIntProperty("ro.build.version.sdk", 0) <= 30) {
        GTEST_SKIP() << "vsock loopback not supported on Android R and below";
    }
    // Test with port passed as an argument.
    port = 5555;
    // On old kernels, either vsock entirely, or the loopback CID, is not supported. Check for
    // "Connection refused" or "No such device", which indicate this case. Skip the test
    // case since it's not possible on the device under test.
    bool connected = socket_spec_connect(&client_fd, "vsock:1", &port, &serial, &error);
    if (!connected) {
      if (errno == ENODEV || errno == EPFNOSUPPORT || errno == EAFNOSUPPORT) {
        GTEST_SKIP() << "vsock not supported on this kernel";
      }
      if (errno == ECONNREFUSED) {
        GTEST_SKIP() << "vsock loopback not supported on this kernel";
      }
      if (errno == ETIMEDOUT) {
        GTEST_SKIP() << "connection is flaky on this device, skip the test instead of flaking";
      }
    }

    EXPECT_TRUE(connected) << errno << ": " << strerror(errno);
    EXPECT_NE(client_fd.get(), -1);
    client_fd.reset();

    // Test with port passed in the spec string.
    port = 0;
    connected = socket_spec_connect(&client_fd, "vsock:1:5555", &port, &serial, &error);
    if (!connected && errno == ETIMEDOUT) {
        GTEST_SKIP() << "connection is flaky on this device, skip the test instead of flaking";
    }

    EXPECT_TRUE(connected) << errno << ": " << strerror(errno);
    EXPECT_NE(client_fd.get(), -1);
#endif  // ADB_HOST
#endif  // __linux__
}

TEST(socket_spec, socket_spec_listen_connect_vsock_failure) {
#ifndef __linux__
    GTEST_SKIP() << "vsock is only supported on Linux";
#else
#if ADB_HOST
    GTEST_SKIP() << "socket adb port check is skipped on host";
#else
    std::string error, serial;
    int port = 0;
    unique_fd server_fd, client_fd;

    server_fd.reset(socket_spec_listen("vsock:1234", &error, &port));
    ASSERT_NE(server_fd.get(), -1) << error;
    ASSERT_EQ(port, 1234);

    // Test with port passed as an argument.
    // On a Linux host, the CID for the host is 2 (VMADDR_CID_HOST).
    port = 1234;
    EXPECT_FALSE(socket_spec_connect(&client_fd, "vsock:2", &port, &serial, &error));

    // Test with port passed in the spec string.
    port = 0;
    EXPECT_FALSE(socket_spec_connect(&client_fd, "vsock:2:1234", &port, &serial, &error));
#endif  // ADB_HOST
#endif  // __linux__
}

TEST(socket_spec, socket_spec_connect_failure) {
    std::string error, serial;
    int port;
    unique_fd client_fd;
    EXPECT_FALSE(socket_spec_connect(&client_fd, "tcp:", &port, &serial, &error));
    EXPECT_FALSE(socket_spec_connect(&client_fd, "acceptfd:", &port, &serial, &error));
    EXPECT_FALSE(socket_spec_connect(&client_fd, "vsock:", &port, &serial, &error));
    EXPECT_FALSE(socket_spec_connect(&client_fd, "vsock:x", &port, &serial, &error));
    EXPECT_FALSE(socket_spec_connect(&client_fd, "vsock:5", &port, &serial, &error));
    EXPECT_FALSE(socket_spec_connect(&client_fd, "vsock:5:x", &port, &serial, &error));
    EXPECT_FALSE(socket_spec_connect(&client_fd, "sneakernet:", &port, &serial, &error));
    EXPECT_FALSE(socket_spec_connect(&client_fd, "vsock:5:4321", &port, &serial, &error));
}

TEST(socket_spec, socket_spec_listen_connect_localfilesystem) {
    std::string error, serial;
    int port;
    unique_fd server_fd, client_fd;
    TemporaryDir sock_dir;

    // Only run this test if the created directory is writable.
    int result = access(sock_dir.path, W_OK);
    if (result == 0) {
        std::string sock_addr =
                android::base::StringPrintf("localfilesystem:%s/af_unix_socket", sock_dir.path);
        EXPECT_FALSE(socket_spec_connect(&client_fd, sock_addr, &port, &serial, &error));
        server_fd.reset(socket_spec_listen(sock_addr, &error, &port));

        EXPECT_NE(server_fd.get(), -1);
        EXPECT_TRUE(socket_spec_connect(&client_fd, sock_addr, &port, &serial, &error));
        EXPECT_NE(client_fd.get(), -1);
    }
}

TEST(socket_spec, is_socket_spec) {
    EXPECT_TRUE(is_socket_spec("tcp:blah"));
    EXPECT_TRUE(is_socket_spec("acceptfd:blah"));
    EXPECT_TRUE(is_socket_spec("local:blah"));
    EXPECT_TRUE(is_socket_spec("localreserved:blah"));
    EXPECT_TRUE(is_socket_spec("vsock:123:456"));
}

TEST(socket_spec, is_local_socket_spec) {
    EXPECT_TRUE(is_local_socket_spec("local:blah"));
    EXPECT_TRUE(is_local_socket_spec("tcp:localhost"));
    EXPECT_FALSE(is_local_socket_spec("tcp:www.google.com"));
}
