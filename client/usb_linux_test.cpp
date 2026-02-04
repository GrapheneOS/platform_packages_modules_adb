/*
 * Copyright (C) 2026 The Android Open Source Project
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

#include <gtest/gtest.h>
#include <string>
#include <unordered_map>
#include <vector>

#include "usb_linux_netlink.h"

TEST(NetLinkMessage, SimpleUpdate) {
    const char buffer[] =
            "add@/devices/pci0000:00/usb4/4-1\0"
            "ACTION=add\0"
            "SUBSYSTEM=usb\0"
            "MAJOR=189\0"
            "DEVNAME=bus/usb/004/126\0";

    NetlinkMessage msg(buffer, sizeof(buffer));

    // Test basic attribute retrieval
    EXPECT_EQ(msg.attr("ACTION"), "add");
    EXPECT_EQ(msg.attr("SUBSYSTEM"), "usb");
    EXPECT_EQ(msg.attr("MAJOR"), "189");
    EXPECT_EQ(msg.attr("DEVNAME"), "bus/usb/004/126");

    // Test has_attr with string_view
    EXPECT_TRUE(msg.has_attr("ACTION", "add"));
    EXPECT_TRUE(msg.has_attr("MAJOR", "189"));

    // Test non-existent attributes
    EXPECT_EQ(msg.attr("NON_EXISTENT"), "");
    EXPECT_FALSE(msg.has_attr("ACTION", "remove"));
    EXPECT_FALSE(msg.has_attr("MINOR", "509"));
}

TEST(NetLinkMessage, EmptyBuffer) {
    const char* empty = "";
    NetlinkMessage msg(empty, 0);

    EXPECT_EQ(msg.attr("ACTION"), "");
    EXPECT_FALSE(msg.has_attr("ACTION", "add"));
}

TEST(NetLinkMessage, MalformedPairs) {
    // Buffer with a header but malformed KV pairs (missing '=')
    const char buffer[] =
            "remove@/sys/block/sda\0"
            "MALFORMED_DATA_WITHOUT_EQUALS\0"
            "VALID=yes\0";

    NetlinkMessage msg(buffer, sizeof(buffer));

    EXPECT_TRUE(msg.has_attr("VALID", "yes"));
    // Depending on implementation, "MALFORMED_DATA_WITHOUT_EQUALS"
    // should likely be ignored or stored as an empty value.
    EXPECT_EQ(msg.attr("MALFORMED_DATA_WITHOUT_EQUALS"), "");
}

TEST(NetLinkMessage, EdgeCaseAttributes) {
    const char buffer[] =
            "change@/devices/virtual/test\0"
            "EMPTY_VAL=\0"
            "=MISSING_KEY\0"
            "MULTI_EQUALS=part1=part2\0";

    NetlinkMessage msg(buffer, sizeof(buffer));

    EXPECT_EQ(msg.attr("EMPTY_VAL"), "");
    EXPECT_TRUE(msg.has_attr("EMPTY_VAL", ""));

    // Case: =VALUE
    // Testing that the value "MISSING_KEY" isn't accidentally mapped to a valid key.
    EXPECT_EQ(msg.attr(""), "");

    // Case: KEY=VAL=UE
    // Standard behavior is to split at the first '='.
    EXPECT_EQ(msg.attr("MULTI_EQUALS"), "part1=part2");
}

TEST(NetLinkMessage, LargeBufferWithMultipleNulls) {
    const char buffer[] =
            "add@/sys/class/net/eth0\0"
            "INTERFACE=eth0\0"
            "\0"  // Extra null
            "STATE=up\0"
            "\0\0";  // Multiple trailing nulls

    NetlinkMessage msg(buffer, sizeof(buffer));

    EXPECT_EQ(msg.attr("INTERFACE"), "eth0");
    EXPECT_EQ(msg.attr("STATE"), "up");
}