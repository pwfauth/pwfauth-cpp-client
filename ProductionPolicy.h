#pragma once
#include <stdexcept>
#include <string>

namespace pwf_policy {
inline constexpr char Origin[] = "https://pwfauth.com";
inline void ValidateOrigin(std::string origin) {
    while (!origin.empty() && origin.back() == '/') origin.pop_back();
    if (origin != Origin)
        throw std::invalid_argument("PWF Auth requires the fixed HTTPS production origin.");
}
}
