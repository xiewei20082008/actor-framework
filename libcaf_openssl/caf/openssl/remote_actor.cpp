// This file is part of CAF, the C++ Actor Framework. See the file LICENSE in
// the main distribution directory for license terms and copyright or visit
// https://github.com/actor-framework/actor-framework/blob/main/LICENSE.

#include "caf/openssl/remote_actor.hpp"

#include "caf/openssl/manager.hpp"

#include "caf/expected.hpp"
#include "caf/log/openssl.hpp"
#include "caf/scoped_actor.hpp"
#include "caf/sec.hpp"

namespace caf::openssl {

/// Establish a new connection to the actor at `host` on given `port`.
/// @param host Valid hostname or IP address.
/// @param port TCP port.
/// @returns An `actor` to the proxy instance representing
///          a remote actor or an `error`.
expected<strong_actor_ptr> remote_actor(actor_system& sys,
                                        const std::set<std::string>& mpi,
                                        std::string host, uint16_t port) {
  auto lg = log::openssl::trace("mpi = {}, host = {}, port = {}", mpi, host,
                                port);
  expected<strong_actor_ptr> res{strong_actor_ptr{nullptr}};
  auto self = scoped_actor{sys};
  auto x = self->mail(connect_atom_v, std::move(host), port)
             .request(sys.openssl_manager().actor_handle(), infinite)
             .receive();
  if (!x)
    return std::move(x.error());
  auto& tup = *x;
  auto& ptr = get<1>(tup);
  if (!ptr)
    return sec::no_actor_published_at_port;
  auto& found_mpi = get<2>(tup);
  if (sys.assignable(found_mpi, mpi))
    return std::move(ptr);
  return sec::unexpected_actor_messaging_interface;
}

expected<strong_actor_ptr> remote_actor(actor_system& sys,
                                        const std::set<std::string>& mpi,
                                        std::string ip, std::string sni, uint16_t port) {
  auto lg = log::openssl::trace("mpi = {}, ip = {}, sni={} port = {}", mpi, ip, sni,
                                port);
  expected<strong_actor_ptr> res{strong_actor_ptr{nullptr}};
  auto self = scoped_actor{sys};
  auto x = self->mail(connect_atom_v, std::move(ip), std::move(sni), port)
             .request(sys.openssl_manager().actor_handle(), infinite)
             .receive();
  if (!x)
    return std::move(x.error());
  auto& tup = *x;
  auto& ptr = get<1>(tup);
  if (!ptr)
    return sec::no_actor_published_at_port;
  auto& found_mpi = get<2>(tup);
  if (sys.assignable(found_mpi, mpi))
    return std::move(ptr);
  return sec::unexpected_actor_messaging_interface;
}



} // namespace caf::openssl
