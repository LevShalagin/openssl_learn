#include <napi.h>

#include "opensslv.h"
// #include <openssl/opensslv.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/x509.h>
#include <openssl/err.h>

#include <iostream> 
#include <string>
#include <fstream>

using namespace Napi;


void OpensslVersion(const Napi::CallbackInfo& info) {
  printf("Version OpenSSL: %s\nRelease date: %s\n", OPENSSL_VERSION_STR, OPENSSL_RELEASE_DATE);
}


void OpensslHashHelp(const Napi::CallbackInfo& info) {
  
  printf("Hash functions list:\n");

  OpenSSL_add_all_algorithms();
  
  int nid = 1;
  while (const char *sn = OBJ_nid2sn(nid)) {
    if(strstr(sn, "SHA") || strstr(sn, "MD")) {
      printf("  - %s\n", sn);
    }
    nid++;
  }
}


void GenRSA(const Napi::CallbackInfo& info) {

  unsigned int bits = 2048;
  unsigned int primeCount = 2;
  unsigned long e = RSA_F4; // RSA_F4 is 65537
  
  BIGNUM *bNum = BN_new();
  RSA *rsa = RSA_new();

  BN_set_word(bNum, e);

  int result = RSA_generate_key_ex(rsa, bits, bNum, NULL);
  if(result != 1) { goto free_all; }

  BIO *publicKeyFile = BIO_new_file("keys/public.pem", "w+");
  BIO *privateKeyFile = BIO_new_file("keys/private.pem", "w+");

  PEM_write_bio_RSAPublicKey(publicKeyFile, rsa);
  BIO_free_all(publicKeyFile);

  PEM_write_bio_RSAPrivateKey(privateKeyFile, rsa, NULL, NULL, 0, NULL, NULL);
  BIO_free_all(privateKeyFile);

  free_all:
    RSA_free(rsa);
    BN_free(bNum);
}

void GenRequest() {
  
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set(Napi::String::New(env, "opensslVersion"), Napi::Function::New(env, OpensslVersion));
  exports.Set(Napi::String::New(env, "opensslHashHelp"), Napi::Function::New(env, OpensslHashHelp));
  exports.Set(Napi::String::New(env, "GenRSA"), Napi::Function::New(env, GenRSA));
  return exports;
}

NODE_API_MODULE(addon, Init)

