// Copyright(c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT license.

#include "mpss/mpss.h"
#include <iostream>

namespace mpss {
    void myfun()
    {
    #ifdef MPSS_DEBUG_BUILD
        std::cout << "Debug build" << std::endl;
    #endif
	    std::cout << "Hello world" << std::endl;
    }
} // namespace mpss
