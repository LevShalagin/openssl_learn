#include <napi.h>

#include "opensslv.h"
// #include <openssl/opensslv.h>

#include <openssl/evp.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/bio.h>
#include <openssl/bn.h>
#include <openssl/x509.h>

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


void getCertificate(const Napi::CallbackInfo& info) {

  char *country = (char*) malloc(100);
  char *org = (char*) malloc(100);
  char *domen = (char*) malloc(100);

  // получение имён для запроса на сертификат
  strcpy(country, info[0].ToString().Utf8Value().c_str());
  strcpy(org, info[1].ToString().Utf8Value().c_str());
  strcpy(domen, info[2].ToString().Utf8Value().c_str());

  printf("----------------\n%s %s %s\n----------------", country, org, domen);

  X509_REQ *req = X509_REQ_new();
  X509_NAME *name = X509_NAME_new();

  // получение открытого ключа
  FILE *publicKeyFile = fopen("keys/public.pem", "r");
  EVP_PKEY *publicKey = PEM_read_PrivateKey(publicKeyFile, NULL, NULL, NULL);
  fclose(publicKeyFile);

  // добавление имён для запроса получения сертификата
  X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (const unsigned char*)country, -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (const unsigned char*)org, -1, -1, 0);
  X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (const unsigned char*)domen, -1, -1, 0);

  // запрос на сертификат
  X509_REQ_set_subject_name(req, name);
  X509_REQ_set_pubkey(req, publicKey);
  X509_REQ_sign(req, publicKey, EVP_sha256());

  // создание сертификата
  X509* certificate = X509_new();
  X509_set_version(certificate, 2);
  ASN1_INTEGER_set(X509_get_serialNumber(certificate), 1);
  X509_gmtime_adj(X509_get_notBefore(certificate), 0);
  X509_gmtime_adj(X509_get_notAfter(certificate), 24 * 60 * 60);
  X509_set_subject_name(certificate, name);
  X509_set_issuer_name(certificate, name);
  X509_set_pubkey(certificate, publicKey);
  X509_sign(certificate, publicKey, EVP_sha256());

  char *crtFileName = (char*) malloc(100);
  sprintf(crtFileName, "certificates/%s.crt", &domen);
  FILE* fileCertificate = fopen(crtFileName, "w+");
  PEM_write_X509(fileCertificate, certificate);
  fclose(fileCertificate);

  free_all:
    X509_free(certificate); 
    X509_REQ_free(req);
    EVP_PKEY_free(publicKey);
    X509_NAME_free(name);

    free(country);
    free(org);
    free(domen);
    free(crtFileName);
}


Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set(Napi::String::New(env, "opensslVersion"), Napi::Function::New(env, OpensslVersion));
  exports.Set(Napi::String::New(env, "opensslHashHelp"), Napi::Function::New(env, OpensslHashHelp));
  exports.Set(Napi::String::New(env, "GenRSA"), Napi::Function::New(env, GenRSA));
  exports.Set(Napi::String::New(env, "GetCertificate"), Napi::Function::New(env, getCertificate));
  return exports;
}

NODE_API_MODULE(addon, Init)

