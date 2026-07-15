#include "client.hpp"

#include "crypto_utils.hpp"

CryptoPP::SecByteBlock Client::deriveMasterKey(const string& saltHex) {
    CryptoPP::SecByteBlock master(32);
    CryptoPP::PKCS5_PBKDF2_HMAC<CryptoPP::SHA256> pbkdf;
    string salt = fromHex(saltHex);
    pbkdf.DeriveKey(
        master,
        master.size(),
        0,
        reinterpret_cast<CryptoPP::byte*>(password_cache.data()),
        password_cache.size(),
        reinterpret_cast<CryptoPP::byte*>(salt.data()),
        salt.size(),
        10000);
    return master;
}

void Client::saveKeystore() {
    json j;
    for (auto& [id, key] : key_store) {
        j[id] = toHex(key);
    }

    if (!privDH.empty() && !pubDH.empty()) {
        j["__DH_PRIV__"] = toHex(privDH);
        j["__DH_PUB__"] = toHex(pubDH);
    }

    string plaintext = j.dump();
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::SecByteBlock iv(AES_IV_SIZE);
    prng.GenerateBlock(iv, iv.size());

    string saltHex = generateSalt();
    CryptoPP::SecByteBlock master = deriveMasterKey(saltHex);
    string ciphertext = aes_encrypt(plaintext, master, iv);
    ofstream f("keystore_" + username + ".enc");
    f << saltHex << ":" << toHex(iv) << ":"
      << toHex(reinterpret_cast<const CryptoPP::byte*>(ciphertext.data()), ciphertext.size());
}

void Client::loadKeystore() {
    ifstream f("keystore_" + username + ".enc");
    if (!f.is_open()) {
        return;
    }

    string line;
    getline(f, line);
    size_t firstDel = line.find(':');
    if (firstDel == string::npos) {
        return;
    }

    size_t secondDel = line.find(':', firstDel + 1);
    if (secondDel == string::npos) {
        return;
    }

    string saltHex = line.substr(0, firstDel);
    string ivHex = line.substr(firstDel + 1, secondDel - firstDel - 1);
    string cipherHex = line.substr(secondDel + 1);

    CryptoPP::SecByteBlock iv(AES_IV_SIZE);
    string ivRaw = fromHex(ivHex);
    memcpy(iv.BytePtr(), ivRaw.data(), min(iv.size(), ivRaw.size()));

    CryptoPP::SecByteBlock master = deriveMasterKey(saltHex);
    string cipherRaw = fromHex(cipherHex);
    string plaintext = aes_decrypt(cipherRaw, master, iv);

    if (!plaintext.empty()) {
        try {
            json j = json::parse(plaintext);
            for (auto& el : j.items()) {
                string keyName = el.key();
                string kRaw = fromHex(el.value());
                if (keyName == "__DH_PRIV__") {
                    privDH.Assign(reinterpret_cast<const CryptoPP::byte*>(kRaw.data()), kRaw.size());
                    dh_loaded = true;
                } else if (keyName == "__DH_PUB__") {
                    pubDH.Assign(reinterpret_cast<const CryptoPP::byte*>(kRaw.data()), kRaw.size());
                } else {
                    CryptoPP::SecByteBlock key(
                        reinterpret_cast<const CryptoPP::byte*>(kRaw.data()),
                        kRaw.size());
                    key_store[keyName] = key;
                }
            }
        } catch (...) {
        }
    }
}

void Client::loadInboxHistory() {
    db_inbox_history = loadJSON("inbox_" + username + ".json");
    if (db_inbox_history.is_null()) {
        db_inbox_history = json::object();
    }
}

void Client::addToInboxHistory(string noteID, string sender) {
    db_inbox_history[noteID] = {{"sender", sender}, {"received_at", static_cast<long long>(time(0))}};
    saveJSON("inbox_" + username + ".json", db_inbox_history);
}

void Client::cleanupLocalKeys() {
    json allNotes = server.getAllNotes();
    vector<string> removeList;

    for (auto& kv : key_store) {
        const string& noteID = kv.first;
        if (!allNotes.contains(noteID)) {
            removeList.push_back(noteID);
        }
    }
    for (auto& id : removeList) {
        key_store.erase(id);
    }
    saveKeystore();
}

void Client::cleanupInboxHistory() {
    json allNotes = server.getAllNotes();
    vector<string> removeList;
    for (auto& el : db_inbox_history.items()) {
        string id = el.key();
        if (!allNotes.contains(id)) {
            removeList.push_back(id);
        }
    }
    for (auto& id : removeList) {
        db_inbox_history.erase(id);
    }
    saveJSON("inbox_" + username + ".json", db_inbox_history);
}

Client::Client(string u, Server& s) : username(std::move(u)), server(s) {
    loadInboxHistory();
}

string Client::doRegister(string pass) {
    string res = server.registerUser(username, pass);

    if (res == "SUCCESS") {
        password_cache = pass;
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::Integer p;
        CryptoPP::Integer q;
        CryptoPP::Integer g;
        server.getDHParams(p, q, g);
        dh.AccessGroupParameters().Initialize(p, q, g);
        privDH.resize(dh.PrivateKeyLength());
        pubDH.resize(dh.PublicKeyLength());
        dh.GenerateKeyPair(rng, privDH, pubDH);
        dh_loaded = true;
        server.uploadDHKey(username, toHex(pubDH));
        saveKeystore();
        return "[+] Dang ky thanh cong.";
    }

    if (res == "ERR_NAME_LEN") {
        return "[!] Loi: Ten phai co it nhat 2 ky tu.";
    }
    if (res == "ERR_NAME_FORMAT") {
        return "[!] Loi: Ten chi duoc chua chu cai, so va khong co khoang trang.";
    }
    if (res == "ERR_PASS_LEN") {
        return "[!] Loi: Mat khau phai co it nhat 3 ky tu.";
    }
    if (res == "ERR_PASS_SPACE") {
        return "[!] Loi: Mat khau khong duoc chi chua khoang trang.";
    }
    if (res == "ERR_USER_EXIST") {
        return "[!] Loi: Nguoi dung da ton tai.";
    }

    return "[!] Dang ky that bai: " + res;
}

bool Client::doLogin(string pass, string& msg) {
    sessionToken = server.login(username, pass);
    if (!sessionToken.empty()) {
        password_cache = pass;
        CryptoPP::Integer p;
        CryptoPP::Integer q;
        CryptoPP::Integer g;
        server.getDHParams(p, q, g);
        try {
            dh.AccessGroupParameters().Initialize(p, q, g);
        } catch (...) {
            msg = "[!] Loi khoi tao tham so bao mat.";
            return false;
        }

        loadKeystore();
        loadInboxHistory();

        cleanupLocalKeys();
        cleanupInboxHistory();

        if (!privDH.empty() && !pubDH.empty()) {
            dh_loaded = true;
            server.uploadDHKey(username, toHex(pubDH));
        } else {
            CryptoPP::AutoSeededRandomPool rng;
            privDH.resize(dh.PrivateKeyLength());
            pubDH.resize(dh.PublicKeyLength());
            dh.GenerateKeyPair(rng, privDH, pubDH);
            dh_loaded = true;
            server.uploadDHKey(username, toHex(pubDH));
            saveKeystore();
            msg = "[+] Da tao moi va dong bo khoa E2E.";
        }
        return true;
    }
    return false;
}

string Client::getUser() const {
    return username;
}

string Client::listMyNotes() {
    auto list = server.listNotes(sessionToken);
    if (list.empty()) {
        return "              (Danh sach trong)             ";
    }

    stringstream ss;
    ss << "          --- DANH SACH GHI CHU ---\n";
    for (auto& p : list) {
        ss << "[+]  " << p << "\n";
    }
    return ss.str();
}

string Client::uploadText(string content) {
    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::SecByteBlock key(AES_KEY_SIZE);
    prng.GenerateBlock(key, key.size());
    CryptoPP::SecByteBlock iv(AES_IV_SIZE);
    prng.GenerateBlock(iv, iv.size());
    string enc = aes_encrypt(content, key, iv);
    string b64 = toBase64(reinterpret_cast<const CryptoPP::byte*>(enc.data()), enc.size());
    string id = server.uploadNote(sessionToken, b64, toHex(iv));
    if (id.find("ERROR") == string::npos) {
        key_store[id] = key;
        saveKeystore();
        return "[+] Tai len thanh cong. ID: " + id;
    }
    return "[!] Loi tai len.";
}

string Client::uploadFile(string path) {
    try {
        string content = readFileBytes(path);

        CryptoPP::AutoSeededRandomPool prng;
        CryptoPP::SecByteBlock key(AES_KEY_SIZE);
        prng.GenerateBlock(key, key.size());
        CryptoPP::SecByteBlock iv(AES_IV_SIZE);
        prng.GenerateBlock(iv, iv.size());
        string enc = aes_encrypt(content, key, iv);
        string b64 = toBase64(reinterpret_cast<const CryptoPP::byte*>(enc.data()), enc.size());
        string id = server.uploadNote(sessionToken, b64, toHex(iv));
        if (id.find("ERROR") == string::npos) {
            key_store[id] = key;
            saveKeystore();
            return "[+] Tai len FILE thanh cong. ID: " + id;
        }
    } catch (const exception& e) {
        return string("[!] Loi doc tep tin: ") + e.what();
    }
    return "[!] Loi tai len tep tin.";
}

string Client::readNote(string id, bool saveToFile, string saveName) {
    json note = server.downloadNote(id);
    if (note == nullptr) {
        return "[!] Ghi chu khong ton tai hoac da bi xoa.";
    }
    if (!key_store.count(id)) {
        return "[!] Ban khong co khoa giai ma.";
    }

    CryptoPP::SecByteBlock key = key_store[id];
    string enc = fromBase64(note["data"]);
    string ivRaw = fromHex(note["iv"]);
    CryptoPP::SecByteBlock iv(
        reinterpret_cast<const CryptoPP::byte*>(ivRaw.data()),
        ivRaw.size());
    string dec = aes_decrypt(enc, key, iv);
    if (dec.empty()) {
        return "[!] Giai ma that bai.";
    }

    if (saveToFile) {
        if (saveName.find('.') == string::npos) {
            saveName += ".txt";
        }
        try {
            writeFileBytes(saveName, dec);
            return "[+] Da luu tep tin: " + saveName;
        } catch (const exception& e) {
            return string("[!] Loi ghi tep tin: ") + e.what();
        }
    }

    return "[+] Noi dung: " + dec;
}

string Client::deleteMyNote(string id) {
    if (server.deleteNote(sessionToken, id)) {
        key_store.erase(id);
        saveKeystore();
        return "[+] Da xoa thanh cong.";
    }
    return "[!] Xoa that bai.";
}

string Client::createLink(string id, int seconds) {
    if (!key_store.count(id)) {
        return "[!] Thieu khoa giai ma.";
    }

    string pin;
    cout << "PIN bao ve (Enter de bo qua): ";
    getline(cin, pin);

    string token = server.createShareToken(sessionToken, id, seconds, pin);
    if (token.empty()) {
        return "[!] Loi tao lien ket (hoac khong phai chu so huu).";
    }

    string keyB64 = toBase64(key_store[id]);
    string url = SCHEME_PREFIX + token;

    stringstream ss;
    ss << "[+] TAO LIEN KET THANH CONG!\n";
    ss << "    1. Link: " << url << "\n";
    ss << "    2. Key:  " << keyB64 << "\n";
    if (!pin.empty()) {
        ss << "    3. PIN:  " << pin << " (Hay gui PIN nay cho nguoi nhan)\n";
    }
    ss << "    (Bao mat: Can Link + Key + PIN de xem noi dung)";
    return ss.str();
}

string Client::shareE2E(string targetUser, string noteID) {
    if (!key_store.count(noteID)) {
        return "[!] Khong tim thay khoa giai ma cua ghi chu nay.";
    }

    string bobPubHex = server.getDHKey(targetUser);
    if (bobPubHex.empty()) {
        return "[!] LOI: Nguoi dung '" + targetUser + "' chua kich hoat tinh nang chia se.";
    }

    try {
        string bobPubRaw = fromHex(bobPubHex);
        CryptoPP::SecByteBlock bobPubBlock(
            reinterpret_cast<const CryptoPP::byte*>(bobPubRaw.data()),
            bobPubRaw.size());

        if (privDH.empty()) {
            return "[!] Loi: Tai khoan mat Private Key. Hay dang nhap lai.";
        }

        CryptoPP::SecByteBlock sharedSecret(dh.AgreedValueLength());
        if (!dh.Agree(sharedSecret, privDH, bobPubBlock)) {
            return "[!] DH Agreement Failed.";
        }

        CryptoPP::SecByteBlock sessionKey(AES_KEY_SIZE);
        CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
        hkdf.DeriveKey(
            sessionKey,
            sessionKey.size(),
            sharedSecret,
            sharedSecret.size(),
            nullptr,
            0,
            nullptr,
            0);

        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::SecByteBlock iv(AES_IV_SIZE);
        rng.GenerateBlock(iv, iv.size());

        string noteKeyRaw(
            reinterpret_cast<const char*>(key_store[noteID].BytePtr()),
            key_store[noteID].size());
        string encryptedKey = aes_encrypt(noteKeyRaw, sessionKey, iv);

        json msgPayload;
        msgPayload["note_id"] = noteID;
        msgPayload["iv"] = toHex(iv);
        msgPayload["key_enc"] =
            toBase64(reinterpret_cast<const CryptoPP::byte*>(encryptedKey.data()), encryptedKey.size());

        bool success = server.sendE2EMessage(sessionToken, targetUser, msgPayload.dump());
        if (success) {
            return "[+] Da gui khoa bao mat cho " + targetUser;
        }
        return "[!] Gui that bai: Ban khong phai chu so huu ghi chu hoac ghi chu khong ton tai.";
    } catch (const exception& e) {
        return string("[!] Loi ngoai le: ") + e.what();
    }
}

string Client::shareURL_E2E(string targetUser, string noteID, int seconds, string inputPin) {
    if (!key_store.count(noteID)) {
        return "[!] Khong tim thay khoa giai ma cua ghi chu nay.";
    }

    string bobPubHex = server.getDHKey(targetUser);
    if (bobPubHex.empty()) {
        return "[!] LOI: Nguoi dung '" + targetUser + "' chua kich hoat tinh nang chia se.";
    }

    try {
        string token = server.createShareToken(sessionToken, noteID, seconds, inputPin);
        if (token.empty()) {
            return "[!] Loi tao lien ket (hoac khong phai chu so huu).";
        }

        string url = SCHEME_PREFIX + token;
        string bobPubRaw = fromHex(bobPubHex);
        CryptoPP::SecByteBlock bobPubBlock(
            reinterpret_cast<const CryptoPP::byte*>(bobPubRaw.data()),
            bobPubRaw.size());

        if (privDH.empty()) {
            return "[!] Loi: Mat Private Key. Hay dang nhap lai.";
        }

        CryptoPP::SecByteBlock sharedSecret(dh.AgreedValueLength());
        if (!dh.Agree(sharedSecret, privDH, bobPubBlock)) {
            return "[!] DH Agreement Failed.";
        }

        CryptoPP::SecByteBlock sessionKey(AES_KEY_SIZE);
        CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
        hkdf.DeriveKey(
            sessionKey,
            sessionKey.size(),
            sharedSecret,
            sharedSecret.size(),
            nullptr,
            0,
            nullptr,
            0);

        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::SecByteBlock iv(AES_IV_SIZE);
        rng.GenerateBlock(iv, iv.size());

        string noteKeyRaw(
            reinterpret_cast<const char*>(key_store[noteID].BytePtr()),
            key_store[noteID].size());
        string encryptedNoteKey = aes_encrypt(noteKeyRaw, sessionKey, iv);

        json msgPayload;
        msgPayload["type"] = "KEY_SHARE_ONLY";
        msgPayload["note_id"] = noteID;
        msgPayload["pin"] = inputPin;
        msgPayload["iv"] = toHex(iv);
        msgPayload["key_enc"] = toBase64(
            reinterpret_cast<const CryptoPP::byte*>(encryptedNoteKey.data()),
            encryptedNoteKey.size());

        bool success = server.sendE2EMessage(sessionToken, targetUser, msgPayload.dump());
        if (success) {
            stringstream ss;
            ss << "[+] Da gui goi bao mat (PIN + Key) cho " << targetUser << ".\n";
            ss << "[+] URL: " << url << "\n";
            return ss.str();
        }
        return "[!] Gui that bai.";
    } catch (const exception& e) {
        return string("[!] Loi: ") + e.what();
    }
}

string Client::checkInbox() {
    auto msgs = server.checkMailbox(sessionToken);
    int new_count = 0;

    struct E2EMsgDisplay {
        string sender;
        string pin;
        string key;
    };
    vector<E2EMsgDisplay> new_e2e_msgs;

    for (auto& m : msgs) {
        string sender = m.first;
        string rawJson = m.second;

        try {
            json payload = json::parse(rawJson);
            string senderPubHex = server.getDHKey(sender);
            if (senderPubHex.empty()) {
                continue;
            }

            string senderPubRaw = fromHex(senderPubHex);
            CryptoPP::SecByteBlock senderPubBlock(
                reinterpret_cast<const CryptoPP::byte*>(senderPubRaw.data()),
                senderPubRaw.size());

            CryptoPP::SecByteBlock sharedSecret(dh.AgreedValueLength());
            if (dh.Agree(sharedSecret, privDH, senderPubBlock)) {
                CryptoPP::SecByteBlock sessionKey(AES_KEY_SIZE);
                CryptoPP::HKDF<CryptoPP::SHA256> hkdf;
                hkdf.DeriveKey(
                    sessionKey,
                    sessionKey.size(),
                    sharedSecret,
                    sharedSecret.size(),
                    nullptr,
                    0,
                    nullptr,
                    0);

                if (payload.contains("type") && payload["type"] == "KEY_SHARE_ONLY") {
                    string ivRaw = fromHex(payload["iv"]);
                    CryptoPP::SecByteBlock iv(
                        reinterpret_cast<const CryptoPP::byte*>(ivRaw.data()),
                        ivRaw.size());
                    string encKey = fromBase64(payload["key_enc"]);

                    string decryptedNoteKey = aes_decrypt(encKey, sessionKey, iv);
                    string keyBase64 = toBase64(
                        reinterpret_cast<const CryptoPP::byte*>(decryptedNoteKey.data()),
                        decryptedNoteKey.size());
                    string pin = payload["pin"];

                    new_e2e_msgs.push_back({sender, pin, keyBase64});
                    new_count++;
                } else {
                    string noteID = payload.contains("note_id") ? payload["note_id"] : "";
                    string ivRaw = fromHex(payload["iv"]);
                    CryptoPP::SecByteBlock iv(
                        reinterpret_cast<const CryptoPP::byte*>(ivRaw.data()),
                        ivRaw.size());
                    string encKey = fromBase64(payload["key_enc"]);
                    string noteKeyRaw = aes_decrypt(encKey, sessionKey, iv);

                    if (!noteKeyRaw.empty() && !noteID.empty()) {
                        CryptoPP::SecByteBlock finalKey(
                            reinterpret_cast<const CryptoPP::byte*>(noteKeyRaw.data()),
                            noteKeyRaw.size());
                        key_store[noteID] = finalKey;
                        saveKeystore();
                        addToInboxHistory(noteID, sender);
                        new_count++;
                    }
                }
            }
        } catch (...) {
            continue;
        }
    }

    cleanupLocalKeys();
    cleanupInboxHistory();

    stringstream ss;
    if (new_count > 0) {
        ss << "[+] Da nhan " << new_count << " tin nhan moi.\n";
    }

    if (db_inbox_history.empty() && new_e2e_msgs.empty()) {
        ss << "                (Hop thu trong)             ";
    } else {
        ss << "---------------   HOP THU   ----------------\n";
        ss << left << setw(15) << "ID" << " | " << setw(15) << "Nguoi gui" << " | Noi dung\n";
        ss << "--------------------------------------------\n";

        for (auto& el : db_inbox_history.items()) {
            string id = el.key();
            string sender = el.value()["sender"];
            ss << left << setw(15) << id << " | " << setw(15) << sender << " | \n";
        }

        for (auto& msg : new_e2e_msgs) {
            ss << left << setw(15) << "" << " | " << setw(15) << msg.sender << " | 1. KEY: " << msg.key
               << "\n";
            ss << left << setw(15) << "" << " | " << setw(15) << "" << " | 2. PIN: " << msg.pin << "\n";
        }
        ss << "\n(Voi ID: Dung chuc nang 7 | Voi PIN/KEY: Dung chuc nang 14)\n";
    }
    return ss.str();
}

string Client::accessLink(string url, string keyB64) {
    size_t tPos = url.find("t=");
    if (tPos == string::npos) {
        return "[!] Lien ket hong hoac thieu tham so.";
    }

    string t = url.substr(tPos + 2);

    string pin;
    cout << "    Nhap ma PIN (Neu co, Enter de bo qua): ";
    getline(cin, pin);

    string noteID = server.validateShareToken(t, pin);
    if (noteID == "NOT_FOUND") {
        return "[!] Lien ket loi: Khong tim thay.";
    }
    if (noteID == "EXPIRED") {
        return "[!] Lien ket loi: Da het han.";
    }
    if (noteID == "LIMIT_REACHED") {
        return "[!] Lien ket loi: Het luot truy cap.";
    }
    if (noteID == "WRONG_PIN") {
        return "[!] Truy cap bi tu choi: Sai ma PIN.";
    }

    json note = server.downloadNote(noteID);
    if (note == nullptr) {
        return "[!] Ghi chu goc da bi xoa.";
    }

    string kRaw = fromBase64(keyB64);
    if (kRaw.size() != AES_KEY_SIZE) {
        return "[!] Khoa giai ma khong hop le (Sai kich thuoc).";
    }

    CryptoPP::SecByteBlock sharedKey(
        reinterpret_cast<const CryptoPP::byte*>(kRaw.data()),
        kRaw.size());
    string enc = fromBase64(note["data"]);
    string ivRaw = fromHex(note["iv"]);
    CryptoPP::SecByteBlock iv(
        reinterpret_cast<const CryptoPP::byte*>(ivRaw.data()),
        ivRaw.size());

    string plaintext = aes_decrypt(enc, sharedKey, iv);
    if (plaintext.empty()) {
        return "[!] Giai ma that bai (Sai khoa).";
    }

    return "[+] Noi dung chia se: " + plaintext;
}

string Client::revokeLink(string url) {
    size_t tPos = url.find("t=");
    if (tPos == string::npos) {
        return "[!] URL khong hop le.";
    }

    string sub = url.substr(tPos + 2);
    size_t endPos = sub.find('&');
    string tokenStr = (endPos == string::npos) ? sub : sub.substr(0, endPos);
    if (server.revokeShareToken(sessionToken, tokenStr)) {
        return "[+] Da thu hoi lien ket.";
    }
    return "[!] Thu hoi that bai.";
}
