
#include "crypto.hpp"

#include <algorithm>
#include <functional>
#include <iostream>
#include <iterator>
#include <random>
#include <tuple>

namespace {

void test_box()
{
    crypto::box_public_key alice_public, bob_public;
    crypto::box_secret_key alice_secret, bob_secret;
    auto nonce = crypto::random_generate<crypto::box_nonce>();

    std::tie(alice_public, alice_secret) = crypto::box_keypair();
    std::tie(bob_public, bob_secret) = crypto::box_keypair();

    const auto& msg = "This is a test string";

    auto ciphertext = crypto::box(msg, nonce, alice_public, bob_secret);

    std::cout << ciphertext << std::endl;

    auto out_msg = crypto::box_open(ciphertext, nonce, bob_public, alice_secret);

    if (!out_msg) {
        std::cerr << "Error unboxing message\n";
    }

    std::cout << *out_msg << std::endl;
}

void test_boxnm()
{
    crypto::box_public_key alice_public, bob_public;
    crypto::box_secret_key alice_secret, bob_secret;
    auto nonce = crypto::random_generate<crypto::box_nonce>();

    std::tie(alice_public, alice_secret) = crypto::box_keypair();
    std::tie(bob_public, bob_secret) = crypto::box_keypair();

    auto alice_shared = crypto::box_beforenm(bob_public, alice_secret);

    const auto& msg = "This is a test message";

    auto cipher = crypto::box_afternm(msg, nonce, alice_shared);

    //if (!cipher) {
    //    std::cerr << "Error constructing ciphertext";
    //    return;
    //}

    std::cout << cipher << std::endl;

    auto bob_shared = crypto::box_beforenm(alice_public, bob_secret);

    assert(alice_shared == bob_shared);

    auto out_msg = crypto::box_open_afternm(cipher, nonce, bob_shared);

    if (!out_msg) {
        std::cerr << "Error unboxing ciphertext";
        return;
    }

    std::cout << *out_msg << std::endl;

    assert(*out_msg == msg);
}

void test_secretbox()
{
    auto nonce = crypto::random_generate<crypto::secretbox_nonce>();
    auto key = crypto::random_generate<crypto::secretbox_key>();
    auto msg = "This is a test message";

    auto cipher = crypto::secretbox(msg, nonce, key);
    if (!cipher) {
        std::cerr << "Error boxing message\n";
        return;
    }

    std::cout << *cipher << std::endl;

    auto out_msg = crypto::secretbox_open(*cipher, nonce, key);

    if (!out_msg) {
        std::cerr << "Error unboxing message\n";
        return;
    }

    std::cout << *out_msg << std::endl;
}

void test_sign()
{
    crypto::sign_public_key pk;
    crypto::sign_secret_key sk;

    std::tie(pk, sk) = crypto::sign_keypair();

    const auto msg = "This is a test signed message";

    auto signed_msg = crypto::sign(msg, sk);

    std::cout << signed_msg << std::endl;

    auto out_msg = crypto::sign_open(signed_msg, pk);

    assert(bool(out_msg));

    std::cout << *out_msg << std::endl;
}

void test_stream()
{
    auto nonce = crypto::random_generate<crypto::stream_nonce>();
    auto key = crypto::random_generate<crypto::stream_key>();

    auto msg = "This is a test message";

    auto ciphertext = crypto::stream_xor(msg, nonce, key);

    std::cout << ciphertext << std::endl;

    auto out_msg = crypto::stream_xor(ciphertext, nonce, key);

    std::cout << msg << std::endl;

    assert(msg == out_msg);
}

void test_onetimeauth()
{
    auto key = crypto::random_generate<crypto::onetimeauth_key>();

    auto msg = "This is a test message";

    auto mac = crypto::onetimeauth(msg, key);

    assert(crypto::onetimeauth_verify(mac, msg, key));
}

}

int main()
{
    test_box();
    test_boxnm();
    test_secretbox();
    test_sign();
    test_stream();
    test_onetimeauth();
}