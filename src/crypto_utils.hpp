#pragma once

#define NOMINMAX
#include "deps/cryptopp/aes.h"
#include "deps/cryptopp/base64.h"
#include "deps/cryptopp/dh.h"
#include "deps/cryptopp/files.h"
#include "deps/cryptopp/filters.h"
#include "deps/cryptopp/gcm.h"
#include "deps/cryptopp/hex.h"
#include "deps/cryptopp/hkdf.h"
#include "deps/cryptopp/integer.h"
#include "deps/cryptopp/nbtheory.h"
#include "deps/cryptopp/osrng.h"
#include "deps/cryptopp/pwdbased.h"
#include "deps/cryptopp/secblock.h"
#include "deps/cryptopp/sha.h"

#include <algorithm>
#include <chrono>
#include <cctype>
#include <cstdlib>
#include <cstring>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>
#include <string>
#include <thread>
#include <unordered_map>
#include <utility>
#include <vector>

#ifdef _WIN32
#include <windows.h>
#endif

#include "deps/json/single_include/nlohmann/json.hpp"

using namespace std;
using namespace std::chrono;
using json = nlohmann::json;

inline constexpr size_t AES_KEY_SIZE = 32;
inline constexpr size_t AES_IV_SIZE = 12;
inline constexpr size_t MAX_FILE_SIZE = 50 * 1024 * 1024;

inline const string SERVER_PEPPER = "Project2_Chuoi_Bi_Mat_Trong_Server_@123xyz";
inline const string SCHEME_PREFIX = "secure-note://view?t=";

string toHex(const CryptoPP::byte* data, size_t size);
string toHex(const CryptoPP::SecByteBlock& block);
string fromHex(const string& input);

string toBase64(const CryptoPP::byte* data, size_t size);
string toBase64(const CryptoPP::SecByteBlock& block);
string fromBase64(const string& input);

string integerToString(const CryptoPP::Integer& i);
CryptoPP::Integer stringToInteger(const string& s);

string readFileBytes(const string& path);
void writeFileBytes(const string& path, const string& data);

string generateSalt();
string sha256_hash(const string& data);

json loadJSON(const string& filename);
void saveJSON(const string& filename, const json& j);

string aes_encrypt(
    const string& plaintext,
    const CryptoPP::SecByteBlock& key,
    const CryptoPP::SecByteBlock& iv);

string aes_decrypt(
    const string& ciphertext,
    const CryptoPP::SecByteBlock& key,
    const CryptoPP::SecByteBlock& iv);
