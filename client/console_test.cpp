#include <gtest/gtest.h>

#include <android-base/file.h>

#include "client/console.cpp"

// Mock adb_query to avoid linking adb_client in the tests.
bool adb_query(const std::string&, std::string*, std::string*, bool) {
    return true;
}

TEST(console, adb_construct_auth_command) {
    TemporaryDir temp_dir;

    std::string auth_file =
            std::string(temp_dir.path) + OS_PATH_SEPARATOR + ".emulator_console_auth_token";

    // Test with no file
    EXPECT_EQ(adb_construct_auth_command(temp_dir.path), "");

    // Test with an empty file
    android::base::WriteStringToFile("", auth_file);
    EXPECT_EQ(adb_construct_auth_command(temp_dir.path), "");

    // Test with a whitespace-only file
    android::base::WriteStringToFile("   \r\n ", auth_file);
    EXPECT_EQ(adb_construct_auth_command(temp_dir.path), "");

    // Test with a normal token
    android::base::WriteStringToFile("my_token", auth_file);
    EXPECT_EQ(adb_construct_auth_command(temp_dir.path), "auth my_token\n");

    // Test with a token and trailing newline
    android::base::WriteStringToFile("my_token\n", auth_file);
    EXPECT_EQ(adb_construct_auth_command(temp_dir.path), "auth my_token\n");

    // Test with a token, trailing newline, and spaces
    android::base::WriteStringToFile("  my_token \r\n", auth_file);
    EXPECT_EQ(adb_construct_auth_command(temp_dir.path), "auth my_token\n");
}
