#pragma once

#include "server.hpp"

class Client {
private:
    string username;
    string password_cache;
    string sessionToken;
    Server& server;
    unordered_map<string, CryptoPP::SecByteBlock> key_store;
    json db_inbox_history;

    CryptoPP::DH dh;
    CryptoPP::SecByteBlock privDH;
    CryptoPP::SecByteBlock pubDH;
    bool dh_loaded = false;

    CryptoPP::SecByteBlock deriveMasterKey(const string& saltHex);
    void saveKeystore();
    void loadKeystore();
    void loadInboxHistory();
    void addToInboxHistory(string noteID, string sender);
    void cleanupLocalKeys();
    void cleanupInboxHistory();

public:
    Client(string u, Server& s);

    string doRegister(string pass);
    bool doLogin(string pass, string& msg);
    string getUser() const;
    string listMyNotes();
    string uploadText(string content);
    string uploadFile(string path);
    string readNote(string id, bool saveToFile = false, string saveName = "");
    string deleteMyNote(string id);
    string createLink(string id, int seconds);
    string shareE2E(string targetUser, string noteID);
    string shareURL_E2E(string targetUser, string noteID, int seconds, string inputPin);
    string checkInbox();
    string accessLink(string url, string keyB64);
    string revokeLink(string url);
};
