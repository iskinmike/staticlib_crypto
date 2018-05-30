/*
 * Copyright 2018, mike at myasnikov.mike@gmail.com
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/*
 * File:   sha1.hpp
 * Author: mike
 *
 * Created on May 30, 2018, 17:51 PM
 */

#ifndef STATICLIB_CRYPTO_SHA1_HPP
#define STATICLIB_CRYPTO_SHA1_HPP

#include <string>
#include <openssl/sha.h>

std::string sha1_encode(const std::string data){
    const size_t size = 20;
    unsigned char out[size];
    char *ptr = static_cast<char*>(static_cast<void *>(out));

    SHA1(reinterpret_cast<const unsigned char*>(data.c_str()), data.length(), out);

    return std::string{ptr, size};
}

#endif /* STATICLIB_CRYPTO_SHA1_HPP */


