// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <functional>

namespace mpss::utils {
    class ScopeGuard {
    private:
        std::function<void()> on_exit_;

    public:
        ScopeGuard() = delete;

        ScopeGuard(std::function<void()> on_exit)
        {
            on_exit_ = on_exit;
        }

        ~ScopeGuard()
        {
            on_exit_();
        }
    };
} // namespace mpss::utils

// These are helpers for correct expansion of __LINE__ macro
#define SCOPE_GUARD_CONCATENATE_DIRECT(s1, s2) s1##s2
#define SCOPE_GUARD_CONCATENATE(s1, s2) SCOPE_GUARD_CONCATENATE_DIRECT(s1, s2)

// Execute a piece of code when SCOPE_GUARD goes out of scope
#define SCOPE_GUARD(...) mpss::utils::ScopeGuard SCOPE_GUARD_CONCATENATE(scopeGuard, __LINE__)([&]() { __VA_ARGS__; })
