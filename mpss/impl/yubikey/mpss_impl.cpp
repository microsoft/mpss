// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/impl/backend_registry.h"
#include "mpss/impl/yubikey/yk_backend.h"
#include <memory>

namespace mpss::impl
{

// Explicit registration function for YubiKey backend.
void register_yubikey_backend()
{
    auto backend = std::make_shared<yubikey::YubiKeyBackend>();
    register_backend(backend);
}

} // namespace mpss::impl
