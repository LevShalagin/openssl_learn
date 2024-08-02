#include <napi.h>

#include "opensslv.h"
// #include <openssl/opensslv.h>
#include <openssl/evp.h>

#include <iostream> 
#include <string>
#include <fstream>

using namespace Napi;

void OpensslVersion(const Napi::CallbackInfo& info) {
  printf("Version OpenSSL: %s\nRelease date: %s\n", OPENSSL_VERSION_STR, OPENSSL_RELEASE_DATE);
}

void OpensslHashHelp(const Napi::CallbackInfo& info) {
  // FILE *Output = fopen("OBJ_nid2sn_Output.txt", "w");
  printf("Hash functions list:\n");

  OpenSSL_add_all_algorithms();
  
  int nid = 1;
  while (const char *sn = OBJ_nid2sn(nid)) {
    if(strstr(sn, "SHA") || strstr(sn, "MD")) printf("  - %s\n", sn);
    // fprintf(Output, "NID: %d, Short Name: %s\n", nid, sn);
    nid++;
  }
  // fclose(Output);
}

Napi::Object Init(Napi::Env env, Napi::Object exports) {
  exports.Set(Napi::String::New(env, "opensslVersion"), Napi::Function::New(env, OpensslVersion));
  exports.Set(Napi::String::New(env, "opensslHashHelp"), Napi::Function::New(env, OpensslHashHelp));
  return exports;
}

NODE_API_MODULE(addon, Init)

