/*
 * Copyright (C) 2025 The Android Open Source Project
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

#include "discovered_services.h"

using namespace mdns;

const IPv4Address kV4LoopbackAddress{127, 0, 0, 1};
const IPv6Address kV6LoopbackAddress{0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1};

TEST(DiscoveredServicesTest, simpleUpdate) {
    DiscoveredServices services;

    ServiceInfo service;
    service.instance = "foo";
    service.service = "bar";

    services.ServiceCreated(service);
    auto s = services.FindInstance(service.service, service.instance);

    ASSERT_TRUE(s.has_value());
    ASSERT_EQ("foo", s.value().instance);
    ASSERT_EQ("bar", s.value().service);

    service.v4_address = kV4LoopbackAddress;
    auto updated = services.ServiceUpdated(service);
    ASSERT_TRUE(updated);
}

TEST(DiscoveredServicesTest, NonUpdateV4) {
    DiscoveredServices services;

    ServiceInfo service;
    service.instance = "foo";
    service.service = "bar";
    service.v4_address = kV4LoopbackAddress;

    services.ServiceCreated(service);
    auto updated = services.ServiceUpdated(service);
    ASSERT_FALSE(updated);
}

TEST(DiscoveredServicesTest, NonUpdateV6) {
    DiscoveredServices services;

    ServiceInfo service;
    service.instance = "foo";
    service.service = "bar";
    service.v6_addresses = {kV6LoopbackAddress};

    services.ServiceCreated(service);
    auto updated = services.ServiceUpdated(service);
    ASSERT_FALSE(updated);
}

TEST(DiscoveredServicesTest, NonUpdateV6WithDifferentSet) {
    DiscoveredServices services;

    ServiceInfo service;
    service.instance = "foo";
    service.service = "bar";
    service.v6_addresses = {kV6LoopbackAddress};

    services.ServiceCreated(service);
    auto updated = services.ServiceUpdated(service);
    ASSERT_FALSE(updated);

    ServiceInfo service_update;
    service_update.instance = "foo";
    service_update.service = "bar";
    updated = services.ServiceUpdated(service_update);
    ASSERT_FALSE(updated);
}