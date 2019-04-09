/*
 * librdkafka - Apache Kafka C library
 *
 * Copyright (c) 2019, Magnus Edenhill
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice,
 *    this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 *    this list of conditions and the following disclaimer in the documentation
 *    and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN
 * CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include <iostream>
#include <cstring>
#include <cstdlib>
#include <fstream>
#include <streambuf>
#include "testcpp.h"
#include "tinycthread.h"

/**
 * @name SslCertVerifyCb verification.
 *
 * Requires security.protocol=*SSL
 */

class TestVerifyCb : public RdKafka::SslCertificateVerifyCb {
 public:
  bool verify_ok;
  int cnt; //< Verify callbacks triggered.
  mtx_t lock;

  TestVerifyCb(bool verify_ok): verify_ok(verify_ok), cnt(0) {
    mtx_init(&lock, mtx_plain);
  }

  ~TestVerifyCb() {
    mtx_destroy(&lock);
  }

  bool ssl_cert_verify_cb (const std::string &broker_name,
                           int32_t broker_id,
                           bool preverify_ok,
                           void *x509_ctx,
                           int depth,
                           const char *buf, size_t size,
                           std::string &errstr) {

    mtx_lock(&lock);

    Test::Say(tostr() << "ssl_cert_verify_cb #" << cnt <<
              ": broker_name=" << broker_name <<
              ", broker_id=" << broker_id <<
              ", preverify_ok=" << preverify_ok <<
              ", x509_ctx=" << x509_ctx << ", depth=" << depth <<
              ", buf size=" << size << ", verify_ok=" << verify_ok << "\n");

    cnt++;
    mtx_unlock(&lock);

    if (verify_ok)
      return true;

    errstr = "This test triggered a verification failure";
    return false;
  }
};


static void conf_location_to_pem (RdKafka::Conf *conf,
                                  std::string loc_prop,
                                  std::string pem_prop) {
  std::string loc;


  if (conf->get(loc_prop, loc) != RdKafka::Conf::CONF_OK)
    Test::Fail("Failed to get " + loc_prop);

  std::string errstr;
  if (conf->set(loc_prop, "", errstr) != RdKafka::Conf::CONF_OK)
    Test::Fail("Failed to reset " + loc_prop);

  /* Read file */
  std::ifstream ifs(loc.c_str());
  std::string pem((std::istreambuf_iterator<char>(ifs)),
                  std::istreambuf_iterator<char>());

  if (conf->set(pem_prop, pem, errstr) != RdKafka::Conf::CONF_OK)
    Test::Fail("Failed to set " + pem_prop);
}



static void do_test_verify (bool verify_ok) {
  /*
   * Create any type of client
   */

  Test::Say(tostr() << "SSL cert verify: verify_ok=" << verify_ok << "\n");

  RdKafka::Conf *conf;
  Test::conf_init(&conf, NULL, 10);

  std::string val;
  if (conf->get("ssl.key.location", val) != RdKafka::Conf::CONF_OK ||
      val.empty()) {
    Test::Skip("Test requires SSL to be configured\n");
    delete conf;
    return;
  }

  /* Get ssl.key.location, read its contents, and replace with
   * ssl.key.pem. Same with ssl.certificate.location -> ssl.certificate.pem. */
  conf_location_to_pem(conf, "ssl.key.location", "ssl.key.pem");
  conf_location_to_pem(conf, "ssl.certificate.location", "ssl.certificate.pem");

  std::string errstr;
  conf->set("debug", "security", errstr);

  TestVerifyCb verifyCb(verify_ok);
  if (conf->set("ssl_cert_verify_cb", &verifyCb, errstr) !=
      RdKafka::Conf::CONF_OK)
    Test::Fail("Failed to set verifyCb: " + errstr);

  RdKafka::Producer *p = RdKafka::Producer::create(conf, errstr);
  if (!p)
    Test::Fail("Failed to create producer: " + errstr);
  delete conf;

  bool run = true;
  for (int i = 0 ; run && i < 10 ; i++) {
    p->poll(1000);

    mtx_lock(&verifyCb.lock);
    if ((verify_ok && verifyCb.cnt > 0) ||
        (!verify_ok && verifyCb.cnt > 3))
      run = false;
    mtx_unlock(&verifyCb.lock);
  }

  mtx_lock(&verifyCb.lock);
  if (!verifyCb.cnt)
      Test::Fail("Expected at least one verifyCb invocation");
  mtx_unlock(&verifyCb.lock);

  delete p;
}

extern "C" {
  int main_0097_ssl_verify (int argc, char **argv) {
    do_test_verify(true);
    do_test_verify(false);
    return 0;
  }
}
