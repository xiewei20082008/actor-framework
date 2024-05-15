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
        set("caf.openssl.key", "private.key");
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
