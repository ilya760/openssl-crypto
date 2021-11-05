#include "single-block-crypto.h"

#include <openssl/evp.h>
#include <openssl/err.h>

#include <iostream>

namespace openssl_crypto {

    namespace {
        using evp_context_ptr = std::unique_ptr<EVP_CIPHER_CTX, decltype(&EVP_CIPHER_CTX_free)>;

        constexpr data_type empty_result;

        void log_openssl_error() {
            std::cerr << "OpenSSL error: " << ERR_error_string(ERR_get_error(), nullptr) << '\n';
        }

        evp_context_ptr create_evp_context_ptr() {
            return {EVP_CIPHER_CTX_new(), &EVP_CIPHER_CTX_free};
        }

        auto setup_aes_128_ecb_decrypt(evp_context_ptr &context, const aes_128_key_type &key) {

            auto return_code = EVP_DecryptInit_ex(context.get(), EVP_aes_128_ecb(), nullptr,
                                                  reinterpret_cast<const unsigned char *>(key.data()),
                                                  nullptr);

            if (!return_code) {
                return return_code;
            }

            // Setup zero padding because we will remove it manually
            return EVP_CIPHER_CTX_set_padding(context.get(), false);
        }

        auto setup_aes_128_ecb_encrypt(evp_context_ptr &context, const aes_128_key_type &key) {

            auto return_code = EVP_EncryptInit_ex(context.get(), EVP_aes_128_ecb(), nullptr,
                                                  reinterpret_cast<const unsigned char *>(key.data()),
                                                  nullptr);

            if (!return_code) {
                return return_code;
            }

            // Setup zero padding
            return EVP_CIPHER_CTX_set_padding(context.get(), false);
        }

        template<typename Iterator, typename Iterator2>
        void apply_xor(Iterator block_to_transform_begin, Iterator block_to_transform_end,
                       Iterator2 rhs_begin) noexcept {
            std::transform(block_to_transform_begin, block_to_transform_end, rhs_begin,
                           block_to_transform_begin,
                           [](std::byte lhs, std::byte rhs) { return lhs ^ rhs; });
        }

        auto aes_128_cbc_single_iteration(evp_context_ptr &context,
                                          std::byte *block_to_decrypt_begin,
                                          std::byte *prev_block_begin) {
            int bytes_written = aes_128_block_size;

            auto return_code = EVP_DecryptUpdate(context.get(),
                                                 reinterpret_cast<unsigned char *>(block_to_decrypt_begin),
                                                 &bytes_written,
                                                 reinterpret_cast<const unsigned char *>(block_to_decrypt_begin),
                                                 aes_128_block_size);

            if (return_code) {
                apply_xor(block_to_decrypt_begin, std::next(block_to_decrypt_begin, aes_128_block_size),
                          prev_block_begin);
            }

            return return_code;
        }


        struct ctr_counter_state final {

            const data_type::reverse_iterator counter_begin{};
            const data_type::reverse_iterator counter_end{};
            data_type::reverse_iterator current_byte{counter_begin};

            ctr_counter_state &operator++() noexcept {

                static constexpr auto max_value = ~std::byte{};
                static constexpr auto zero_value = std::byte{};

                while (*current_byte == max_value) {
                    if (++current_byte == counter_end) {
                        current_byte = counter_begin;
                        std::fill(counter_begin, counter_end, zero_value);
                    }
                }
                *current_byte = static_cast<std::byte>(static_cast<unsigned char>(*current_byte) + 1);

                return *this;
            }

        };


        auto aes_128_ctr_single_iteration(evp_context_ptr &context,
                                          data_type &block_to_decrypt,
                                          const data_type &counter_block) {
            int bytes_written = aes_128_block_size;

            std::array<std::byte, aes_128_block_size> encrypted_counter{};

            auto return_code = EVP_EncryptUpdate(context.get(),
                                                 reinterpret_cast<unsigned char *>(encrypted_counter.data()),
                                                 &bytes_written,
                                                 reinterpret_cast<unsigned char *>(counter_block.data()),
                                                 counter_block.size());

            if (return_code) {
                apply_xor(block_to_decrypt.begin(), block_to_decrypt.end(), encrypted_counter.begin());
            }

            return return_code;

        }

        bool remove_pkcs5_padding(data_type &input) {
            auto padding_size = static_cast<int>(input.back());

            if (input.size() < padding_size) {
                return false;
            } else {
                input = input.subspan(0, input.size() - padding_size);
                return true;
            }
        }

    } // namespace

    data_type cbc_aes_128_decrypt(data_type input, aes_128_key_type &key) {

        // 1. We check the length of input buffer to be longer than 2 blocks
        // and to be a multiple of block size
        if (input.size() < aes_128_block_size && (input.size() % aes_128_block_size != 0)) {
            return empty_result;
        }

        // 2. Create simple ecb context and setup it (remember to set padding value to zero)
        auto context = create_evp_context_ptr();
        if (!context) {
            return log_openssl_error(), empty_result;
        }

        if (setup_aes_128_ecb_decrypt(context, key) == 0) {
            return log_openssl_error(), empty_result;
        }

        // 3. Setup CBC cycle. It starts on last block and ends on second block (block coming after IV block).
        // We need two pointers: one pointer for block that will be decrypted on current iteration
        // and one pointer for previous block (that will be decrypted on next iteration)

        auto *current_block_begin = std::prev(std::next(input.data(), input.size()), aes_128_block_size);
        auto *prev_block_begin = std::prev(current_block_begin, aes_128_block_size);

        do {
            if (!aes_128_cbc_single_iteration(context, current_block_begin, prev_block_begin)) {
                return log_openssl_error(), empty_result;
            }

            current_block_begin = prev_block_begin;
            prev_block_begin = std::prev(current_block_begin, aes_128_block_size);

        } while (current_block_begin != input.data());

        // 4. Remove padding manually
        if (!remove_pkcs5_padding(input)) {
            return empty_result;
        }

        return input.subspan(aes_128_block_size);
    }

    data_type ctr_aes_128_decrypt(data_type input, aes_128_key_type &key) {

        // 1. We check the length of input buffer to be longer than 1 block.
        if (input.size() < aes_128_block_size) {
            return empty_result;
        }

        // 2. Create simple ecb context and setup it (remember to set padding value to zero)
        auto context = create_evp_context_ptr();

        if (!context) {
            return log_openssl_error(), empty_result;
        }

        if (setup_aes_128_ecb_encrypt(context, key) == 0) {
            return log_openssl_error(), empty_result;
        }

        // 3. Prepare decryption cycle. Wrap first block (IV) into "counter" struct to perform incrementation
        auto counter_block = input.first(aes_128_block_size);
        ctr_counter_state counter{counter_block.rbegin(), counter_block.rend()};

        auto setup_next_iteration = [](const auto &remaining_data) {
            if (remaining_data.size() < aes_128_block_size) {
                return std::make_tuple(remaining_data.first(remaining_data.size()), empty_result);
            } else {
                return std::make_tuple(remaining_data.first(aes_128_block_size),
                                       remaining_data.subspan(aes_128_block_size));
            }
        };

        auto remaining_data = input.subspan(aes_128_block_size);
        auto current_block = empty_result;

        // 4. On every iteration:
        do {
            // 4.1 Setup next block to decrypt
            std::tie(current_block, remaining_data) = setup_next_iteration(remaining_data);

            // 4.2 Encrypt "counter" value and xor it with current block
            if (!aes_128_ctr_single_iteration(context, current_block, counter_block)) {
                return log_openssl_error(), empty_result;
            }

            if (remaining_data.empty()) {
                break;
            }

            ++counter;
        } while (true);

        return input.subspan(aes_128_block_size);
    }
}
