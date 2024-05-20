#include <chrono>
#include <cstdlib>
#include <iostream>
#include <random>

#include "caf/actor_ostream.hpp"
#include "caf/actor_system.hpp"
#include "caf/behavior.hpp"
#include "caf/caf_main.hpp"
#include "caf/event_based_actor.hpp"
#include "caf/io/middleman.hpp"
#include "caf/openssl/all.hpp"
#include "caf/io/all.hpp"
#include "caf/openssl/manager.hpp"

using namespace caf;

struct dual_common_config : actor_system_config {
    dual_common_config() {
        load<caf::io::middleman>();
        load<caf::openssl::manager>();
        // set("caf.scheduler.policy", "sharing");
        set("caf.openssl.certificate", "server.crt");
        set("caf.openssl.key", "server.key");
    }
};

behavior test_impl(event_based_actor *self) {
  return {
    [](int x) {
      return x+1;
    }
  };
}

void caf_main(actor_system& sys, const dual_common_config& cfg) {
  auto a = sys.spawn(test_impl);
  openssl::publish(a, 13999);
}

CAF_MAIN(io::middleman, openssl::manager)

// #include <openssl/ssl.h>
// #include <openssl/err.h>
// #include <iostream>

// int main() {
//   const SSL_METHOD* method = TLS_method();
//   SSL_CTX* ctx = SSL_CTX_new(method);

//   if (!ctx) {
//       std::cerr << "Unable to create SSL context" << std::endl;
//       ERR_print_errors_fp(stderr);
//       exit(EXIT_FAILURE);
//   }
//   SSL* ssl = SSL_new(ctx);

//   if (!ssl) {
//       std::cerr << "Unable to create SSL object" << std::endl;
//       ERR_print_errors_fp(stderr);
//       return 1;
//   }

//   // Get the list of all supported ciphers
//   STACK_OF(SSL_CIPHER)* ciphers = SSL_get_ciphers(ssl);

//   if (!ciphers) {
//       std::cerr << "Unable to get ciphers" << std::endl;
//       ERR_print_errors_fp(stderr);
//       SSL_free(ssl);
//       return 1;
//   }

//   // Iterate over the ciphers and print TLS 1.3 ciphers
//   for (int i = 0; i < sk_SSL_CIPHER_num(ciphers); ++i) {
//     const SSL_CIPHER* cipher = sk_SSL_CIPHER_value(ciphers, i);

//         std::cout << SSL_CIPHER_get_name(cipher) << ": "
//                   << SSL_CIPHER_get_version(cipher) << std::endl;
//     // Filter for TLS 1.3 ciphers
//     // if (strcmp(SSL_CIPHER_get_version(cipher), "TLSv1.3") == 0) {
//     //     std::cout << SSL_CIPHER_get_name(cipher) << ": "
//     //               << SSL_CIPHER_get_version(cipher) << std::endl;
//     // }
//   }

//   SSL_free(ssl);
// }