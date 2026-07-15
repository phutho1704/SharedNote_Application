#include "crypto_utils.hpp"

string toHex(const CryptoPP::byte* data, size_t size) {
    string output;
    CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(output));
    encoder.Put(data, size);
    encoder.MessageEnd();
    return output;
}

string toHex(const CryptoPP::SecByteBlock& block) {
    return toHex(block.BytePtr(), block.SizeInBytes());
}

string fromHex(const string& input) {
    string output;
    try {
        CryptoPP::HexDecoder decoder(new CryptoPP::StringSink(output));
        decoder.Put(reinterpret_cast<const CryptoPP::byte*>(input.data()), input.size());
        decoder.MessageEnd();
    } catch (...) {
        return "";
    }
    return output;
}

string toBase64(const CryptoPP::byte* data, size_t size) {
    string output;
    CryptoPP::Base64Encoder encoder(new CryptoPP::StringSink(output), false);
    encoder.Put(data, size);
    encoder.MessageEnd();
    return output;
}

string toBase64(const CryptoPP::SecByteBlock& block) {
    return toBase64(block.BytePtr(), block.SizeInBytes());
}

string fromBase64(const string& input) {
    string output;
    try {
        string fixed = input;
        replace(fixed.begin(), fixed.end(), ' ', '+');
        CryptoPP::Base64Decoder decoder(new CryptoPP::StringSink(output));
        decoder.Put(reinterpret_cast<const CryptoPP::byte*>(fixed.data()), fixed.size());
        decoder.MessageEnd();
    } catch (...) {
        return "";
    }
    return output;
}

string integerToString(const CryptoPP::Integer& i) {
    stringstream ss;
    ss << i;
    string s = ss.str();
    if (!s.empty() && s.back() == '.') {
        s.pop_back();
    }
    return s;
}

CryptoPP::Integer stringToInteger(const string& s) {
    if (s.empty()) {
        return CryptoPP::Integer::Zero();
    }
    return CryptoPP::Integer(s.c_str());
}

string readFileBytes(const string& path) {
    ifstream fileCheck(path, ios::binary | ios::ate);
    if (!fileCheck) {
        throw runtime_error("Khong the mo tep tin " + path);
    }
    if (fileCheck.tellg() > static_cast<streamoff>(MAX_FILE_SIZE)) {
        throw runtime_error("Tep tin qua lon (>50MB)");
    }
    fileCheck.close();

    ifstream file(path, ios::binary);
    stringstream buffer;
    buffer << file.rdbuf();
    return buffer.str();
}

void writeFileBytes(const string& path, const string& data) {
    ofstream file(path, ios::binary);
    if (!file) {
        throw runtime_error("Khong the ghi tep tin " + path);
    }
    file.write(data.data(), static_cast<streamsize>(data.size()));
}

string generateSalt() {
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::SecByteBlock salt(16);
    rng.GenerateBlock(salt, salt.size());
    return toHex(salt);
}

string sha256_hash(const string& data) {
    string digest;
    CryptoPP::SHA256 hash;
    CryptoPP::StringSource(
        data,
        true,
        new CryptoPP::HashFilter(
            hash,
            new CryptoPP::HexEncoder(new CryptoPP::StringSink(digest))));
    return digest;
}

json loadJSON(const string& filename) {
    ifstream f(filename);
    if (!f.is_open()) {
        return json::object();
    }

    json j;
    try {
        f >> j;
    } catch (...) {
        return json::object();
    }
    return j;
}

void saveJSON(const string& filename, const json& j) {
    ofstream f(filename);
    f << j.dump(4);
}

string aes_encrypt(
    const string& plaintext,
    const CryptoPP::SecByteBlock& key,
    const CryptoPP::SecByteBlock& iv) {
    string ciphertext;
    try {
        CryptoPP::GCM<CryptoPP::AES>::Encryption e;
        e.SetKeyWithIV(key, key.size(), iv, iv.size());
        CryptoPP::StringSource(
            plaintext,
            true,
            new CryptoPP::AuthenticatedEncryptionFilter(
                e,
                new CryptoPP::StringSink(ciphertext),
                false,
                16));
    } catch (...) {
        return "";
    }
    return ciphertext;
}

string aes_decrypt(
    const string& ciphertext,
    const CryptoPP::SecByteBlock& key,
    const CryptoPP::SecByteBlock& iv) {
    string plaintext;
    try {
        CryptoPP::GCM<CryptoPP::AES>::Decryption d;
        d.SetKeyWithIV(key, key.size(), iv, iv.size());
        CryptoPP::StringSource(
            ciphertext,
            true,
            new CryptoPP::AuthenticatedDecryptionFilter(
                d,
                new CryptoPP::StringSink(plaintext),
                CryptoPP::AuthenticatedDecryptionFilter::DEFAULT_FLAGS,
                16));
    } catch (...) {
        return "";
    }
    return plaintext;
}
