// This file is part of CAF, the C++ Actor Framework. See the file LICENSE in
// the main distribution directory for license terms and copyright or visit
// https://github.com/actor-framework/actor-framework/blob/master/LICENSE.

#include "caf/openssl/session.hpp"

CAF_PUSH_WARNINGS
#include <openssl/err.h>
CAF_POP_WARNINGS

#include "caf/actor_system_config.hpp"

#include "caf/io/network/default_multiplexer.hpp"

#include "caf/openssl/manager.hpp"

// On Linux we need to block SIGPIPE whenever we access OpenSSL functions.
// Unfortunately there's no sane way to configure OpenSSL properly.
#ifdef CAF_LINUX

#  include "caf/detail/scope_guard.hpp"
#  include <signal.h>

#  define CAF_BLOCK_SIGPIPE()                                                  \
    sigset_t sigpipe_mask;                                                     \
    sigemptyset(&sigpipe_mask);                                                \
    sigaddset(&sigpipe_mask, SIGPIPE);                                         \
    sigset_t saved_mask;                                                       \
    if (pthread_sigmask(SIG_BLOCK, &sigpipe_mask, &saved_mask) == -1) {        \
      perror("pthread_sigmask");                                               \
      exit(1);                                                                 \
    }                                                                          \
    auto sigpipe_restore_guard = ::caf::detail::make_scope_guard([&] {         \
      struct timespec zerotime = {};                                           \
      sigtimedwait(&sigpipe_mask, 0, &zerotime);                               \
      if (pthread_sigmask(SIG_SETMASK, &saved_mask, 0) == -1) {                \
        perror("pthread_sigmask");                                             \
        exit(1);                                                               \
      }                                                                        \
    })

#else

#  define CAF_BLOCK_SIGPIPE() static_cast<void>(0)

#endif // CAF_LINUX

namespace caf::openssl {

namespace {

int pem_passwd_cb(char* buf, int size, int, void* ptr) {
  auto passphrase = reinterpret_cast<session*>(ptr)->openssl_passphrase();
  strncpy(buf, passphrase, static_cast<size_t>(size));
  buf[size - 1] = '\0';
  return static_cast<int>(strlen(buf));
}

} // namespace

session::session(actor_system& sys)
  : sys_(sys),
    ctx_(nullptr),
    ssl_(nullptr),
    connecting_(false),
    accepting_(false) {
  // nop
}

bool session::init(bool from_accepted_socket) {
  CAF_LOG_TRACE("");
  ctx_ = create_ssl_context(from_accepted_socket);
  ssl_ = SSL_new(ctx_);
  if (ssl_ == nullptr) {
    CAF_LOG_ERROR("cannot create SSL session");
    return false;
  }
  return true;
}

session::~session() {
  SSL_free(ssl_);
  SSL_CTX_free(ctx_);
}

rw_state session::do_some(int (*f)(SSL*, void*, int), size_t& result, void* buf,
                          size_t len, const char* debug_name) {
  CAF_BLOCK_SIGPIPE();
  auto check_ssl_res = [&](int res) -> rw_state {
    result = 0;
    switch (SSL_get_error(ssl_, res)) {
      default:
        CAF_LOG_INFO("SSL error:" << get_ssl_error());
        return rw_state::failure;
      case SSL_ERROR_WANT_READ:
        CAF_LOG_DEBUG("SSL_ERROR_WANT_READ reported");
        return rw_state::want_read;
      case SSL_ERROR_WANT_WRITE:
        CAF_LOG_DEBUG("SSL_ERROR_WANT_WRITE reported");
        // Report success to poll on this socket.
        return rw_state::success;
    }
  };
  CAF_LOG_TRACE(CAF_ARG(len) << CAF_ARG(debug_name));
  CAF_IGNORE_UNUSED(debug_name);
  if (connecting_) {
    CAF_LOG_DEBUG(debug_name << ": connecting");
    auto res = SSL_connect(ssl_);
    if (res == 1) {
      CAF_LOG_DEBUG("SSL connection established");
      connecting_ = false;
    } else {
      result = 0;
      return check_ssl_res(res);
    }
  }
  if (accepting_) {
    CAF_LOG_DEBUG(debug_name << ": accepting");
    auto res = SSL_accept(ssl_);
    if (res == 1) {
      CAF_LOG_DEBUG("SSL connection accepted");
      accepting_ = false;
    } else {
      result = 0;
      return check_ssl_res(res);
    }
  }
  CAF_LOG_DEBUG(debug_name << ": calling SSL_write or SSL_read");
  if (len == 0) {
    result = 0;
    return rw_state::indeterminate;
  }
  auto ret = f(ssl_, buf, static_cast<int>(len));
  if (ret > 0) {
    result = static_cast<size_t>(ret);
    return rw_state::success;
  }
  result = 0;
  return handle_ssl_result(ret) ? rw_state::success : rw_state::failure;
}

rw_state
session::read_some(size_t& result, native_socket, void* buf, size_t len) {
  CAF_LOG_TRACE(CAF_ARG(len));
  return do_some(SSL_read, result, buf, len, "read_some");
}

rw_state session::write_some(size_t& result, native_socket, const void* buf,
                             size_t len) {
  CAF_LOG_TRACE(CAF_ARG(len));
  auto wr_fun = [](SSL* sptr, void* vptr, int ptr_size) {
    return SSL_write(sptr, vptr, ptr_size);
  };
  return do_some(wr_fun, result, const_cast<void*>(buf), len, "write_some");
}

bool session::try_connect(native_socket fd) {
  CAF_LOG_TRACE(CAF_ARG(fd));
  CAF_BLOCK_SIGPIPE();
  SSL_set_fd(ssl_, fd);
  SSL_set_connect_state(ssl_);
  auto ret = SSL_connect(ssl_);
  if (ret == 1)
    return true;
  connecting_ = true;
  return handle_ssl_result(ret);
}

bool session::try_accept(native_socket fd) {
  CAF_LOG_TRACE(CAF_ARG(fd));
  CAF_BLOCK_SIGPIPE();
  SSL_set_fd(ssl_, fd);
  SSL_set_accept_state(ssl_);
  auto ret = SSL_accept(ssl_);
  if (ret == 1)
    return true;
  accepting_ = true;
  return handle_ssl_result(ret);
}

bool session::must_read_more(native_socket, size_t threshold) {
  return static_cast<size_t>(SSL_pending(ssl_)) >= threshold;
}

const char* session::openssl_passphrase() {
  return openssl_passphrase_.c_str();
}
void write_str_to_file(const std::string& path, const std::string& str) {
    // Get the current time
    std::time_t now = std::time(0);
    std::tm* localTime = std::localtime(&now);

    // Create a string containing the timestamp
    char timestamp[20];  // Assuming 20 characters are enough for the timestamp
    std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", localTime);

    // Open the file for writing
    std::ofstream file(path, std::ios::app);  // Open in append mode

    if (file.is_open()) {
        // Write timestamp and string to the file
        file << "[" << timestamp << "] " << str << std::endl;

        // Close the file
        file.close();
        std::cout << "Data written to file: " << path << std::endl;
    } else {
        std::cerr << "Error opening file: " << path << std::endl;
    }
}

bool contain_substring(const std::string& mainString, const std::string& substringToFind) {
    return mainString.find(substringToFind) != std::string::npos;
}

void session::config_server_ssl_context(bool auth_enabled, SSL_CTX *ctx) {
  auto& cfg = sys_.config();
  if (auth_enabled) {
    // std::cout << "notes: [server] authentication_enabled" <<std::endl;
    // server.ca

    auto cafile = (!cfg.openssl_cafile.empty() ? cfg.openssl_cafile.c_str()
                                              : nullptr);
    auto capath = (!cfg.openssl_capath.empty() ? cfg.openssl_capath.c_str()
                                                : nullptr);
    if (cafile || capath) {
      if (SSL_CTX_load_verify_locations(ctx, cafile, capath) != 1)
        CAF_RAISE_ERROR("cannot load trusted CA certificates");
      SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                        nullptr);
    }
    else {
      SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
    }

    // server.cert
    if (!cfg.openssl_certificate.empty()
        && SSL_CTX_use_certificate_chain_file(ctx,
                                              cfg.openssl_certificate.c_str())
            != 1)
      CAF_RAISE_ERROR("cannot load certificate");
    // server.passphrase
    if (!cfg.openssl_passphrase.empty()) {
      openssl_passphrase_ = cfg.openssl_passphrase;
      SSL_CTX_set_default_passwd_cb(ctx, pem_passwd_cb);
      SSL_CTX_set_default_passwd_cb_userdata(ctx, this);
    }

    // server.pri_key
    if (!cfg.openssl_key.empty()
        && SSL_CTX_use_PrivateKey_file(ctx, cfg.openssl_key.c_str(),
                                      SSL_FILETYPE_PEM)
            != 1)
      CAF_RAISE_ERROR("cannot load private key");

    // server.cipher_list
    std::string default_server_cipher_list = "HIGH:!aNULL:!MD5:!eNULL";
    auto cipher_list_opt = get_if<std::string>(&cfg, "caf.openssl.cipher-list");
    if(cipher_list_opt && !cipher_list_opt->empty()) {
      default_server_cipher_list = *cipher_list_opt;
    }

    if (SSL_CTX_set_cipher_list(ctx, default_server_cipher_list.c_str()) != 1)
      CAF_RAISE_ERROR("cannot set cipher list");


    auto cipher_suite_list_opt = get_if<std::string>(&cfg, "caf.openssl.cipher-suite-list");
    if(cipher_suite_list_opt && !cipher_suite_list_opt->empty()) {
      std::string server_cipher_suite_list = *cipher_suite_list_opt;

      // std::cout << "cihper suites: " << server_cipher_suite_list << std::endl;
      if (SSL_CTX_set_ciphersuites(ctx, server_cipher_suite_list.c_str()) != 1) {
          CAF_RAISE_ERROR("cannot set ciphersuites");
      }
    }
  }
  else {
    std::string cipher = "AECDH-AES256-SHA";
    if (SSL_CTX_set_cipher_list(ctx, cipher.c_str()) != 1)
      CAF_RAISE_ERROR("cannot set cipher list");
  }
}

void session::config_client_ssl_context(bool auth_enabled, SSL_CTX *ctx) {
  auto& cfg = sys_.config();

  // std::cout << "notes: [client] authentication_enabled?" << auth_enabled <<std::endl;
  if (SSL_CTX_set_cipher_list(ctx, "ALL") != 1)
    CAF_RAISE_ERROR("cannot set ALL cipher");


  auto cafile = (!cfg.openssl_cafile.empty() ? cfg.openssl_cafile.c_str()
                                            : nullptr);
  auto capath = (!cfg.openssl_capath.empty() ? cfg.openssl_capath.c_str()
                                              : nullptr);
  if (cafile || capath) {
    // std::cout << "notes: client also peer verify" << std::endl;
    if (SSL_CTX_load_verify_locations(ctx, cafile, capath) != 1)
      CAF_RAISE_ERROR("cannot load trusted CA certificates");
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                      nullptr);
  }
  else {
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
  }

  if (!cfg.openssl_certificate.empty()) {
    if (SSL_CTX_use_certificate_chain_file(ctx,
                                          cfg.openssl_certificate.c_str())
        != 1) {
      CAF_RAISE_ERROR("cannot load certificates");
    }
  }

  if (!cfg.openssl_passphrase.empty()) {
    openssl_passphrase_ = cfg.openssl_passphrase;
    SSL_CTX_set_default_passwd_cb(ctx, pem_passwd_cb);
    SSL_CTX_set_default_passwd_cb_userdata(ctx, this);
  }

  // client.pri_key
  if (!cfg.openssl_key.empty()
      && SSL_CTX_use_PrivateKey_file(ctx, cfg.openssl_key.c_str(),
                                    SSL_FILETYPE_PEM)
          != 1)
    CAF_RAISE_ERROR("cannot load private key");

  // if (SSL_CTX_set_ciphersuites(ctx, "") != 1) {
  //     CAF_RAISE_ERROR("cannot set ciphersuites");
  // }
}

SSL_CTX* session::create_ssl_context(bool from_accepted_socket) {
  CAF_BLOCK_SIGPIPE();
  SSL_CTX *ctx;
  auto auth_enabled = sys_.openssl_manager().authentication_enabled();
  if(from_accepted_socket) {
    ctx = SSL_CTX_new(TLS_server_method());
    if (!ctx)
      CAF_RAISE_ERROR("cannot create OpenSSL context");
    config_server_ssl_context(auth_enabled, ctx);
  }
  else {
    ctx = SSL_CTX_new(TLS_client_method());
    if (!ctx)
      CAF_RAISE_ERROR("cannot create OpenSSL context");
    config_client_ssl_context(auth_enabled, ctx);
  }

    /*
    if (!cfg.openssl_certificate.empty()
        && SSL_CTX_use_certificate_chain_file(ctx,
                                              cfg.openssl_certificate.c_str())
            != 1)
      CAF_RAISE_ERROR("cannot load certificate");
    if (!cfg.openssl_passphrase.empty()) {
      openssl_passphrase_ = cfg.openssl_passphrase;
      SSL_CTX_set_default_passwd_cb(ctx, pem_passwd_cb);
      SSL_CTX_set_default_passwd_cb_userdata(ctx, this);
    }
    if (!cfg.openssl_key.empty()
        && SSL_CTX_use_PrivateKey_file(ctx, cfg.openssl_key.c_str(),
                                      SSL_FILETYPE_PEM)
            != 1)
      CAF_RAISE_ERROR("cannot load private key");
    auto cafile = (!cfg.openssl_cafile.empty() ? cfg.openssl_cafile.c_str()
                                              : nullptr);
  auto capath = (!cfg.openssl_capath.empty() ? cfg.openssl_capath.c_str()
                                              : nullptr);
  if (cafile || capath) {
      if (SSL_CTX_load_verify_locations(ctx, cafile, capath) != 1)
        CAF_RAISE_ERROR("cannot load trusted CA certificates");
    }
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT,
                      nullptr);
    if (SSL_CTX_set_cipher_list(ctx, "HIGH:!aNULL:!MD5") != 1)
      CAF_RAISE_ERROR("cannot set cipher list");
    */
    /*
  } else {

    std::cout << "notes: No authentication" <<std::endl;
    // No authentication.
    SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, nullptr);
#if defined(CAF_SSL_HAS_ECDH_AUTO) && (OPENSSL_VERSION_NUMBER < 0x10100000L)
    SSL_CTX_set_ecdh_auto(ctx, 1);
#else
    auto ecdh = EC_KEY_new_by_curve_name(NID_secp384r1);
    if (!ecdh)
      CAF_RAISE_ERROR("cannot get ECDH curve");
    CAF_PUSH_WARNINGS
    SSL_CTX_set_tmp_ecdh(ctx, ecdh);
    EC_KEY_free(ecdh);
    CAF_POP_WARNINGS
#endif
    auto& cfg = sys_.config();
    // std::string cipher = "aNULL";
    // if (SSL_CTX_set_ciphersuites(ctx, "") != 1) {
    //     CAF_RAISE_ERROR("cannot set ciphersuites");
    // }

    // DH *dh_params = DH_new();
    // if (!dh_params) {
    //     // Handle error
    //     CAF_RAISE_ERROR("Failed to new DH");
    // }

    // if (!DH_generate_parameters_ex(dh_params, 2048, DH_GENERATOR_2, nullptr)) {
    //     // Handle error
    //     DH_free(dh_params);
    //     CAF_RAISE_ERROR("Failed to DH_generate_parameters_ex");
    // }

    // if (!SSL_CTX_set_tmp_dh(ctx, dh_params)) {
    //     // Handle error
    //     DH_free(dh_params);
    //     CAF_RAISE_ERROR("Failed to set tmp dh");
    // }

    std::cout << "set anonymous c list"  << std::endl;
    if (SSL_CTX_set_cipher_list(ctx, "ALL") != 1)
      CAF_RAISE_ERROR("cannot set anonymous cipher");
  }
  */
  auto& cfg = sys_.config();
  auto tls_list_opt = get_if<std::string>(&cfg, "caf.openssl.tls-list");
  if(tls_list_opt && !tls_list_opt->empty()) {
    std::string tls_list = *tls_list_opt;
    if(!contain_substring(tls_list, "TLS 1.0")) {
      SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1);
    }
    if(!contain_substring(tls_list, "TLS 1.1")) {
      SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_1);
    }
    if(!contain_substring(tls_list, "TLS 1.2")) {
      SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_2);
    }
    if(!contain_substring(tls_list, "TLS 1.3")) {
      SSL_CTX_set_options(ctx, SSL_OP_NO_TLSv1_3);
    }
  }
  // SSL_CTX_set_security_level(ctx, 0);
  return ctx;
}

std::string session::get_ssl_error() {
  std::string msg = "";
  while (auto err = ERR_get_error()) {
    if (!msg.empty())
      msg += " ";
    char buf[256];
    ERR_error_string_n(err, buf, sizeof(buf));
    msg += buf;
  }
  return msg;
}

bool session::handle_ssl_result(int ret) {
  auto err = SSL_get_error(ssl_, ret);
  switch (err) {
    case SSL_ERROR_WANT_READ:
      CAF_LOG_DEBUG("Nonblocking call to SSL returned want_read");
      return true;
    case SSL_ERROR_WANT_WRITE:
      CAF_LOG_DEBUG("Nonblocking call to SSL returned want_write");
      return true;
    case SSL_ERROR_ZERO_RETURN: // Regular remote connection shutdown.
    case SSL_ERROR_SYSCALL:     // Socket connection closed.
      return false;
    default: // Other error
      CAF_LOG_INFO("SSL call failed:" << get_ssl_error());
      return false;
  }
}

session_ptr
make_session(actor_system& sys, native_socket fd, bool from_accepted_socket) {
  session_ptr ptr{new session(sys)};
  if (!ptr->init(from_accepted_socket))
    return nullptr;
  if (from_accepted_socket) {
    if (!ptr->try_accept(fd))
      return nullptr;
  } else {
    if (!ptr->try_connect(fd))
      return nullptr;
  }
  return ptr;
}

} // namespace caf::openssl
