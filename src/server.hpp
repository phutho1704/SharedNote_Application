#pragma once

#include "crypto_utils.hpp"

class Server {
private:
    json db_users;
    json db_notes;
    json db_tokens;
    json db_pubkeys;
    unordered_map<string, vector<pair<string, string>>> e2e_mailbox;
    unordered_map<string, pair<string, long long>> sessions;
    CryptoPP::Integer dh_p;
    CryptoPP::Integer dh_q;
    CryptoPP::Integer dh_g;

public:
    Server();

    string registerUser(const string& user, const string& pass);
    vector<string> getListUsers();
    string login(const string& user, const string& pass);
    string uploadNote(const string& token, string b64Data, string ivHex);
    json downloadNote(const string& noteID);
    vector<string> listNotes(const string& token);
    bool deleteNote(const string& token, const string& noteID);
    string createShareToken(const string& token, const string& noteID, int seconds, const string& pin);
    bool revokeShareToken(const string& token, const string& shareToken);
    string validateShareToken(const string& stoken, const string& inputPin);
    void getDHParams(CryptoPP::Integer& p, CryptoPP::Integer& q, CryptoPP::Integer& g);
    void uploadDHKey(const string& user, const string& pubKeyHex);
    string getDHKey(const string& targetUser);
    bool sendE2EMessage(const string& token, const string& toUser, const string& msg);
    vector<pair<string, string>> checkMailbox(const string& token);
    json getAllNotes();
    void cleanup();

private:
    string createJWT(const string& username);
    string verifyJWT(const string& token);
};
