#pragma once

#include <cstddef>
#include <array>
#include <span>

namespace openssl_crypto {
    using data_type = std::span<std::byte>;

    constexpr int aes_128_block_size = 16;
    constexpr int aes_128_key_size = aes_128_block_size;

    using aes_128_key_type = std::array<std::byte, aes_128_key_size>;;

    data_type cbc_aes_128_decrypt(data_type input, aes_128_key_type &key);
    data_type ctr_aes_128_decrypt(data_type input, aes_128_key_type &key);
}
