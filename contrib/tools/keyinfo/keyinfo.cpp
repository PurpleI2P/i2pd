#include "Identity.h"
#include <iostream>
#include <fstream>
#include <string>
#include <vector>
#include <unistd.h>

int main(int argc, char * argv[])
{
  if(argc == 1) {
    std::cout << "usage: " << argv[0] << " [-v] [-d] privatekey.dat" << std::endl;
    return -1;
  }
  int opt;
  bool print_full = false;
  bool verbose = false;
  while((opt = getopt(argc, argv, "vd"))!=-1) {
    switch(opt){ 
    case 'v':
      verbose = true;
      break;
    case 'd':
      print_full = true;
      break;
    default:
      std::cout << "usage: " << argv[0] << " [-v] [-d] privatekey.dat" << std::endl;
      return -1;
    }
  }
  std::string fname(argv[optind]);
  i2p::data::PrivateKeys keys;
  {
    std::vector<uint8_t> buff;
    std::ifstream inf;
    inf.open(fname);
    if (!inf.is_open()) {
      std::cout << "cannot open private key file " << fname << std::endl;
      return 2;
    }
    inf.seekg(0, std::ios::end);
    const std::size_t len = inf.tellg();
    inf.seekg(0, std::ios::beg);
    buff.resize(len);
    inf.read((char*)buff.data(), buff.size());
    if (!keys.FromBuffer(buff.data(), buff.size())) {
      std::cout << "bad key file format" << std::endl;
      return 3;
    }
  }
  auto dest = keys.GetPublic();
  if(!dest) {
    std::cout << "failed to extract public key" << std::endl;
    return 3;
  }
  
  const auto & ident = dest->GetIdentHash();
  if (verbose) {
    std::cout << "Destination: " << dest->ToBase64() << std::endl;
    std::cout << "Destination Hash: " << ident.ToBase64() << std::endl;
    std::cout << "B32 Address: " << ident.ToBase32() << ".b32.i2p" << std::endl;
    std::cout << "Signature Type: " << (int) dest->GetSigningKeyType() << std::endl;
    std::cout << "Encryption Type: " << (int) dest->GetCryptoKeyType() << std::endl;
  } else {
    if(print_full) {
      std::cout << dest->ToBase64() << std::endl;
    } else {
      std::cout << ident.ToBase32() << ".b32.i2p" << std::endl;
    }
  }
}
