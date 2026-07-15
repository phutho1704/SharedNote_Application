#include "server.hpp"

#include "crypto_utils.hpp"

Server::Server() {
    db_users = loadJSON("users.json");
    db_notes = loadJSON("notes.json");
    db_tokens = loadJSON("tokens.json");
    db_pubkeys = loadJSON("pubkeys.json");

    if (db_users.is_null()) {
        db_users = json::object();
    }
    if (db_notes.is_null()) {
        db_notes = json::object();
    }
    if (db_tokens.is_null()) {
        db_tokens = json::object();
    }
    if (db_pubkeys.is_null()) {
        db_pubkeys = json::object();
    }

    cleanup();

    json db_params = loadJSON("dh_params.json");
    if (!db_params.is_null() && db_params.contains("p") && db_params.contains("g")) {
        dh_p = stringToInteger(db_params["p"]);
        dh_q = stringToInteger(db_params["q"]);
        dh_g = stringToInteger(db_params["g"]);
    } else {
        CryptoPP::AutoSeededRandomPool rng;
        CryptoPP::PrimeAndGenerator pg;
        pg.Generate(1, rng, 1024, 160);
        dh_p = pg.Prime();
        dh_q = pg.SubPrime();
        dh_g = pg.Generator();
        db_params["p"] = integerToString(dh_p);
        db_params["q"] = integerToString(dh_q);
        db_params["g"] = integerToString(dh_g);
        saveJSON("dh_params.json", db_params);
    }
}

string Server::registerUser(const string& user, const string& pass) {
    if (user.length() < 2) {
        return "ERR_NAME_LEN";
    }
    for (char c : user) {
        if (!isalnum(static_cast<unsigned char>(c))) {
            return "ERR_NAME_FORMAT";
        }
    }

    if (pass.length() < 3) {
        return "ERR_PASS_LEN";
    }

    bool onlySpaces = true;
    for (char c : pass) {
        if (!isspace(static_cast<unsigned char>(c))) {
            onlySpaces = false;
            break;
        }
    }
    if (onlySpaces) {
        return "ERR_PASS_SPACE";
    }

    if (db_users.contains(user)) {
        return "ERR_USER_EXIST";
    }

    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::SecByteBlock salt(16);
    prng.GenerateBlock(salt, salt.size());
    string saltHex = toHex(salt);
    string hash = sha256_hash(pass + saltHex + SERVER_PEPPER);

    db_users[user] = {{"salt", saltHex}, {"hash", hash}};
    saveJSON("users.json", db_users);

    if (!db_pubkeys.contains(user)) {
        db_pubkeys[user] = "";
        saveJSON("pubkeys.json", db_pubkeys);
    }
    return "SUCCESS";
}

vector<string> Server::getListUsers() {
    vector<string> users;
    for (auto& el : db_users.items()) {
        users.push_back(el.key());
    }
    return users;
}

string Server::login(const string& user, const string& pass) {
    if (!db_users.contains(user)) {
        return "";
    }

    string salt = db_users[user]["salt"];
    string storedHash = db_users[user]["hash"];
    if (sha256_hash(pass + salt + SERVER_PEPPER) == storedHash) {
        return createJWT(user);
    }
    return "";
}

string Server::uploadNote(const string& token, string b64Data, string ivHex) {
    string user = verifyJWT(token);
    if (user.empty()) {
        return "ERROR_AUTH";
    }

    int i = 1;
    while (true) {
        string id = user + "-NOTE-" + to_string(i);
        if (!db_notes.contains(id)) {
            db_notes[id] = {{"owner", user}, {"data", b64Data}, {"iv", ivHex}};
            saveJSON("notes.json", db_notes);
            return id;
        }
        i++;
    }
}

json Server::downloadNote(const string& noteID) {
    if (!db_notes.contains(noteID)) {
        return nullptr;
    }
    return db_notes[noteID];
}

vector<string> Server::listNotes(const string& token) {
    string user = verifyJWT(token);
    vector<string> res;
    if (user.empty()) {
        return res;
    }

    for (auto& [id, val] : db_notes.items()) {
        if (val["owner"] == user) {
            res.push_back(id);
        }
    }
    return res;
}

bool Server::deleteNote(const string& token, const string& noteID) {
    string user = verifyJWT(token);
    if (user.empty()) {
        return false;
    }

    if (db_notes.contains(noteID) && db_notes[noteID]["owner"] == user) {
        db_notes.erase(noteID);
        saveJSON("notes.json", db_notes);
        return true;
    }
    return false;
}

string Server::createShareToken(
    const string& token,
    const string& noteID,
    int seconds,
    const string& pin) {
    string user = verifyJWT(token);
    if (user.empty()) {
        return "";
    }

    if (!db_notes.contains(noteID) || db_notes[noteID]["owner"] != user) {
        return "";
    }

    CryptoPP::AutoSeededRandomPool prng;
    CryptoPP::SecByteBlock rnd(12);
    prng.GenerateBlock(rnd, rnd.size());
    string shareToken = toHex(rnd);
    long long exp = duration_cast<std::chrono::seconds>(system_clock::now().time_since_epoch()).count() +
                    seconds;

    string pinHash;
    if (!pin.empty()) {
        pinHash = sha256_hash(pin);
    }

    db_tokens[shareToken] = {
        {"note_id", noteID},
        {"expiry", exp},
        {"max", 10},
        {"curr", 0},
        {"owner", user},
        {"pin_hash", pinHash},
    };
    saveJSON("tokens.json", db_tokens);
    return shareToken;
}

bool Server::revokeShareToken(const string& token, const string& shareToken) {
    string user = verifyJWT(token);
    if (user.empty()) {
        return false;
    }

    if (!db_tokens.contains(shareToken)) {
        return false;
    }
    if (db_tokens[shareToken]["owner"] == user) {
        db_tokens.erase(shareToken);
        saveJSON("tokens.json", db_tokens);
        return true;
    }
    return false;
}

string Server::validateShareToken(const string& stoken, const string& inputPin) {
    if (!db_tokens.contains(stoken)) {
        return "NOT_FOUND";
    }
    auto& t = db_tokens[stoken];

    long long now = duration_cast<std::chrono::seconds>(system_clock::now().time_since_epoch()).count();
    if (now > t["expiry"]) {
        return "EXPIRED";
    }
    if (t["curr"] >= t["max"]) {
        return "LIMIT_REACHED";
    }

    string storedHash = t.contains("pin_hash") ? t["pin_hash"].get<string>() : "";
    if (!storedHash.empty()) {
        string inputHash = sha256_hash(inputPin);
        if (inputHash != storedHash) {
            return "WRONG_PIN";
        }
    }

    t["curr"] = t["curr"].get<int>() + 1;
    return t["note_id"];
}

void Server::getDHParams(CryptoPP::Integer& p, CryptoPP::Integer& q, CryptoPP::Integer& g) {
    p = dh_p;
    q = dh_q;
    g = dh_g;
}

void Server::uploadDHKey(const string& user, const string& pubKeyHex) {
    db_pubkeys[user] = pubKeyHex;
    saveJSON("pubkeys.json", db_pubkeys);
}

string Server::getDHKey(const string& targetUser) {
    if (db_pubkeys.contains(targetUser)) {
        return db_pubkeys[targetUser];
    }
    return "";
}

bool Server::sendE2EMessage(const string& token, const string& toUser, const string& msg) {
    string sender = verifyJWT(token);
    if (sender.empty()) {
        return false;
    }

    string noteID;
    try {
        json j = json::parse(msg);
        if (j.contains("note_id")) {
            noteID = j["note_id"];
        }
    } catch (...) {
        return false;
    }

    if (!db_notes.contains(noteID)) {
        return false;
    }
    if (db_notes[noteID]["owner"] != sender) {
        return false;
    }

    e2e_mailbox[toUser].push_back({sender, msg});
    return true;
}

vector<pair<string, string>> Server::checkMailbox(const string& token) {
    string user = verifyJWT(token);
    if (user.empty()) {
        return {};
    }

    auto res = e2e_mailbox[user];
    e2e_mailbox[user].clear();
    return res;
}

json Server::getAllNotes() {
    return db_notes;
}

void Server::cleanup() {
    long long now = duration_cast<std::chrono::seconds>(system_clock::now().time_since_epoch()).count();

    vector<string> tok_delete;
    for (auto& it : db_tokens.items()) {
        string tok = it.key();
        json data = it.value();
        long long expiry = data.contains("expiry") ? data["expiry"].get<long long>() : 0;
        int curr = data.contains("curr") ? data["curr"].get<int>() : 0;
        int maxv = data.contains("max") ? data["max"].get<int>() : 0;
        if (expiry < now || curr >= maxv) {
            tok_delete.push_back(tok);
        }
    }
    for (auto& t : tok_delete) {
        db_tokens.erase(t);
    }
    if (!tok_delete.empty()) {
        saveJSON("tokens.json", db_tokens);
    }

    vector<string> note_delete;
    for (auto& it : db_notes.items()) {
        string id = it.key();
        json data = it.value();
        string owner = data.contains("owner") ? data["owner"].get<string>() : string();
        if (!owner.empty() && !db_users.contains(owner)) {
            note_delete.push_back(id);
        }
    }
    for (auto& id : note_delete) {
        db_notes.erase(id);
    }
    if (!note_delete.empty()) {
        saveJSON("notes.json", db_notes);
    }
}

string Server::createJWT(const string& username) {
    CryptoPP::AutoSeededRandomPool rng;
    CryptoPP::SecByteBlock raw(24);
    rng.GenerateBlock(raw, raw.size());

    string token = toHex(raw);
    long long expiry =
        duration_cast<std::chrono::seconds>((system_clock::now() + hours{1}).time_since_epoch())
            .count();
    sessions[token] = {username, expiry};
    return token;
}

string Server::verifyJWT(const string& token) {
    auto it = sessions.find(token);
    if (it == sessions.end()) {
        return "";
    }

    long long now = duration_cast<std::chrono::seconds>(system_clock::now().time_since_epoch()).count();
    if (now > it->second.second) {
        sessions.erase(it);
        return "";
    }

    return it->second.first;
}
