#pragma once
#include <stdexcept>
#include <string>

namespace pwf_policy {
inline constexpr char Origin[] = "https://pwfauth.com";
// The same license server under a second name, tried only when pwfauth.com gives no reply at all
// (some networks block the name: Etisalat in the UAE answers "no such domain"). Fixed here, never
// configurable, so an app can never be pointed at another server.
inline constexpr char BackupOrigin[] = "https://pwfauth.net";
inline constexpr const char* Origins[] = { Origin, BackupOrigin };
inline constexpr int OriginCount = 2;
inline void ValidateOrigin(std::string origin) {
    while (!origin.empty() && origin.back() == '/') origin.pop_back();
    if (origin != Origin)
        throw std::invalid_argument("PWF Auth requires the fixed HTTPS production origin.");
}
}
