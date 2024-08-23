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

void GetCertificate(const Napi::CallbackInfo& info) {

  OpenSSL_add_all_algorithms();
  ERR_load_BIO_strings();
  ERR_load_crypto_strings();

  const char *country = (const char*) malloc (1000);
  const char *org = (const char*) malloc (1000);
  const char *domen = (const char*) malloc (1000);
  
  country = info[0].As<Napi::String>().Utf8Value().c_str();
  org = info[1].As<Napi::String>().Utf8Value().c_str();
  domen = info[2].As<Napi::String>().Utf8Value().c_str();

  FILE *rsaFile = fopen("keys/private.pem", "r");
  if (!rsaFile) {
    GenRSA(info);
    FILE *rsaFile = fopen("keys/private.pem", "r");
  }
  
  EVP_PKEY *pkay = PEM_read_PrivateKey(rsaFile, NULL, NULL, NULL);
  fclose(rsaFile);

  X509_REQ *req = X509_REQ_new();
  X509_NAME *name = X509_NAME_new();

  X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)country, -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)org, -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)domen, -1, -1, 0);

  X509_REQ_set_subject_name(req, name);
  
  X509 *cert = X509_new();
  
  X509_set_version(cert, 2);
  X509_set_pubkey(cert, pkay);
  X509_REQ_sign(req, pkay, EVP_sha256());

  BIO* bio = BIO_new(BIO_s_file());
  BIO_set_fp(bio, fopen("certificates/certificate.csr", "wb"), BIO_NOCLOSE);
  PEM_write_bio_X509_REQ(bio, req);
  
  free_all:
    free(&country);
    free(&org);
    free(&domen);

    BIO_free(bio);
    X509_REQ_free(req);
    X509_NAME_free(name);
    X509_free(cert);

}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set(Napi::String::New(env, "opensslVersion"), Napi::Function::New(env, OpensslVersion));
  exports.Set(Napi::String::New(env, "opensslHashHelp"), Napi::Function::New(env, OpensslHashHelp));
  exports.Set(Napi::String::New(env, "GenRSA"), Napi::Function::New(env, GenRSA));
  exports.Set(Napi::String::New(env, "GetCertificate"), Napi::Function::New(env, GetCertificate));
  return exports;
}

NODE_API_MODULE(addon, Init)

