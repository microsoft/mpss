// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#pragma once

#include "tests/compat_env.h"
#include <cstdlib>
#include <optional>
#include <string>
#include <string_view>
#include <utility>

namespace mpss::tests
{

/**
 * @brief Saves an environment variable on construction and restores it on destruction.
 *
 * A test can set or clear the variable freely without leaking the change into later tests. The
 * test process reads and writes its environment from one thread at a time, which is what makes the
 * unsynchronized access safe.
 */
class ScopedEnvironmentVariable
{
  public:
    explicit ScopedEnvironmentVariable(std::string name) : name_{std::move(name)}
    {
        const char *value = std::getenv(name_.c_str()); // NOLINT(concurrency-mt-unsafe) - single-threaded tests.
        if (nullptr != value)
        {
            saved_ = value;
        }
    }

    ~ScopedEnvironmentVariable()
    {
        if (saved_)
        {
            set(*saved_);
        }
        else
        {
            unset();
        }
    }

    ScopedEnvironmentVariable(const ScopedEnvironmentVariable &) = delete;
    ScopedEnvironmentVariable &operator=(const ScopedEnvironmentVariable &) = delete;
    ScopedEnvironmentVariable(ScopedEnvironmentVariable &&) = delete;
    ScopedEnvironmentVariable &operator=(ScopedEnvironmentVariable &&) = delete;

    void set(std::string_view value) const
    {
        const std::string terminated{value};
        setenv(name_.c_str(), terminated.c_str(), 1); // NOLINT(concurrency-mt-unsafe) - single-threaded tests.
    }

    void unset() const
    {
        unsetenv(name_.c_str()); // NOLINT(concurrency-mt-unsafe) - single-threaded tests.
    }

    /** @brief The value the variable had when this object was constructed, if it was set. */
    [[nodiscard]]
    const std::optional<std::string> &saved() const noexcept
    {
        return saved_;
    }

  private:
    std::string name_;
    std::optional<std::string> saved_;
};

} // namespace mpss::tests
