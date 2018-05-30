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
 * Created on May 30, 2018, 17:53 PM
 */

#ifndef STATICLIB_CRYPTO_BASE64_HPP
#define STATICLIB_CRYPTO_BASE64_HPP

#include <string>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

std::string base64_encode(const std::string& encoded_string){
    BIO *bio_memory_buffer, *bio_base64_buffer;
    BUF_MEM *buffer_ptr;

    bio_base64_buffer = BIO_new(BIO_f_base64());
    bio_memory_buffer = BIO_new(BIO_s_mem());
    bio_memory_buffer = BIO_push(bio_base64_buffer, bio_memory_buffer);

    BIO_set_flags(bio_memory_buffer, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio_memory_buffer, encoded_string.c_str(), encoded_string.length());
    (void) BIO_flush(bio_memory_buffer);
    BIO_get_mem_ptr(bio_memory_buffer, &buffer_ptr);
    (void) BIO_set_close(bio_memory_buffer, BIO_NOCLOSE);
    BIO_free_all(bio_memory_buffer);

    return std::string{(*buffer_ptr).data, (*buffer_ptr).length};
}

std::string base64_decode(const std::string& decoded_string){
    BIO *bio_memory_buffer, *bio_base64_buffer;

    bio_memory_buffer = BIO_new_mem_buf(decoded_string.c_str(), -1);
    bio_base64_buffer = BIO_new(BIO_f_base64());
    bio_memory_buffer = BIO_push(bio_base64_buffer, bio_memory_buffer);

    char tmp_buffer[decoded_string.length()]; // alloc memory equal to length

    BIO_set_flags(bio_memory_buffer, BIO_FLAGS_BASE64_NO_NL);
    size_t length = BIO_read(bio_memory_buffer, tmp_buffer, decoded_string.length());
    BIO_free_all(bio_memory_buffer);

    return std::string{tmp_buffer, length};
}

#endif /* STATICLIB_CRYPTO_BASE64_HPP */
