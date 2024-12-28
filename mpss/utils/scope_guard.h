// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include <functional>

namespace mpss
{
    namespace utils
    {
        class ScopeGuard
        {
        private:
            std::function<void()> _on_exit;

        public:
            ScopeGuard() = delete;

            ScopeGuard(std::function<void()> on_exit)
            {
                _on_exit = on_exit;
            }

            ~ScopeGuard()
            {
                _on_exit();
            }
        };
    }
}

// Execute a piece of code when SCOPE_GUARD goes out of scope
#define SCOPE_GUARD(...) mpss::utils::ScopeGuard scopeGuard##__LINE__([&]() { __VA_ARGS__; })
