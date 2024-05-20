#include <cstdio>
#include <string>
#include <iostream>

#include "caf/actor_ostream.hpp"
#include "caf/actor_system.hpp"
#include "caf/caf_main.hpp"
#include "caf/event_based_actor.hpp"
#include "caf/openssl/all.hpp"
#include "caf/openssl/remote_actor.hpp"
#include "caf/scoped_actor.hpp"
#include "caf/timespan.hpp"
#include "caf/io/all.hpp"

using namespace caf;


struct dual_common_config : actor_system_config {
    dual_common_config() {
        load<caf::io::middleman>();
        load<caf::openssl::manager>();
        // set("caf.scheduler.policy", "sharing");
        // set("caf.openssl.certificate", "server.crt");
        // set("caf.openssl.key", "private.key");
    }
};

void caf_main(actor_system& sys, const dual_common_config& cfg) {
  auto a_exp = openssl::remote_actor<actor>(sys, "127.0.0.1", 13999);
  auto a = *a_exp;

  scoped_actor sc {sys};
  sc->request(a, caf::infinite, 1).receive(
    [=](int x) {
      printf("received: %d", x);
    },
    [=](caf::error &e) {

    }
  );
}

CAF_MAIN(io::middleman, openssl::manager)