#include "app.hpp"

#include "client.hpp"

int runApp() {
#ifdef _WIN32
    SetConsoleOutputCP(65001);
#endif

    try {
        Server server;

        unique_ptr<Client> currentClient;
        string lastMessage = "           (Chua co hoat dong nao)          ";
        string inputStr;
        int choice = -1;

        while (true) {
            printDashboard(currentClient ? currentClient->getUser() : "", lastMessage);
            if (!getline(cin, inputStr) || inputStr.empty()) {
                continue;
            }

            try {
                choice = stoi(inputStr);
            } catch (...) {
                choice = -1;
            }

            if (choice == 0) {
                break;
            }

            lastMessage = "Dang xu ly...";

            switch (choice) {
                case 1: {
                    string u, p;
                    cout << "\nNhap Username: ";
                    getline(cin, u);
                    cout << "Nhap Password: ";
                    getline(cin, p);
                    Client t(u, server);
                    lastMessage = t.doRegister(p);
                    break;
                }
                case 2: {
                    string u, p, warn;
                    cout << "\nNhap Username: ";
                    getline(cin, u);
                    cout << "Nhap Password: ";
                    getline(cin, p);
                    auto c = make_unique<Client>(u, server);
                    if (c->doLogin(p, warn)) {
                        currentClient = move(c);
                        lastMessage = "[+] Dang nhap thanh cong. " + warn;
                    } else {
                        lastMessage = "[!] Sai ten dang nhap hoac mat khau.";
                    }
                    break;
                }
                case 3: {
                    if (!currentClient) {
                        lastMessage = "[!] Can dang nhap.";
                        break;
                    }

                    auto users = server.getListUsers();
                    cout << "------------ DANH SACH USER KHAC -----------\n";
                    for (auto& u : users) {
                        if (u != currentClient->getUser()) {
                            cout << "[+] " << u << "\n";
                        }
                    }

                    string u, p, warn;
                    cout << "Chon User: ";
                    getline(cin, u);
                    if (u == currentClient->getUser()) {
                        lastMessage = "User dang hoat dong.";
                        break;
                    }
                    cout << "Nhap Password: ";
                    getline(cin, p);
                    auto c = make_unique<Client>(u, server);
                    if (c->doLogin(p, warn)) {
                        currentClient = move(c);
                        lastMessage = "[+] Da chuyen nguoi dung. " + warn;
                    } else {
                        lastMessage = "[!] That bai.";
                    }
                    break;
                }
                case 4: {
                    lastMessage = currentClient ? currentClient->listMyNotes() : "[!] Can dang nhap.";
                    break;
                }
                case 5: {
                    if (!currentClient) {
                        lastMessage = "[!] Can dang nhap.";
                        break;
                    }

                    string c;
                    cout << "\nNhap noi dung: ";
                    getline(cin, c);
                    lastMessage = currentClient->uploadText(c);
                    break;
                }
                case 6: {
                    if (!currentClient) {
                        lastMessage = "[!] Can dang nhap.";
                        break;
                    }

                    string p;
                    cout << "\nNhap duong dan tep tin: ";
                    getline(cin, p);
                    lastMessage = currentClient->uploadFile(p);
                    break;
                }
                case 7: {
                    if (!currentClient) {
                        lastMessage = "[!] Can dang nhap.";
                        break;
                    }

                    string i;
                    cout << "\nNhap ID ghi chu: ";
                    getline(cin, i);
                    lastMessage = currentClient->readNote(i);
                    break;
                }
                case 8: {
                    if (!currentClient) {
                        lastMessage = "[!] Can dang nhap.";
                        break;
                    }

                    string i, n;
                    cout << "\nNhap ID ghi chu: ";
                    getline(cin, i);
                    cout << "Ten tep tin luu: ";
                    getline(cin, n);
                    lastMessage = currentClient->readNote(i, true, n);
                    break;
                }
                case 9: {
                    if (!currentClient) {
                        lastMessage = "[!] Can dang nhap.";
                        break;
                    }

                    string i;
                    cout << "\nNhap ID xoa: ";
                    getline(cin, i);
                    lastMessage = currentClient->deleteMyNote(i);
                    break;
                }
                case 10: {
                    if (!currentClient) {
                        lastMessage = "[!] Can dang nhap.";
                        break;
                    }

                    string i, s_str;
                    int s;
                    cout << "\nNhap ID ghi chu: ";
                    getline(cin, i);
                    cout << "Thoi gian (giay): ";
                    getline(cin, s_str);
                    try {
                        s = stoi(s_str);
                        lastMessage = currentClient->createLink(i, s);
                    } catch (...) {
                        lastMessage = "Loi nhap thoi gian.";
                    }
                    break;
                }
                case 11: {
                    if (!currentClient) {
                        lastMessage = "[!] Can dang nhap.";
                        break;
                    }

                    string u, i;
                    cout << "\nNguoi dung nhan: ";
                    getline(cin, u);
                    cout << "ID ghi chu: ";
                    getline(cin, i);
                    lastMessage = currentClient->shareE2E(u, i);
                    break;
                }
                case 12: {
                    if (!currentClient) {
                        lastMessage = "[!] Can dang nhap.";
                        break;
                    }

                    string u, i, s_str, userPin;
                    int s;

                    cout << "Nguoi dung nhan: ";
                    getline(cin, u);
                    cout << "Nhap ID ghi chu: ";
                    getline(cin, i);
                    cout << "Thoi gian (giay): ";
                    getline(cin, s_str);
                    cout << "PIN bao ve (Enter de bo qua): ";
                    getline(cin, userPin);

                    try {
                        s = stoi(s_str);
                        lastMessage = currentClient->shareURL_E2E(u, i, s, userPin);
                    } catch (...) {
                        lastMessage = "Loi nhap thoi gian.";
                    }
                    break;
                }
                case 13: {
                    lastMessage = currentClient ? currentClient->checkInbox() : "[!] Can dang nhap.";
                    break;
                }
                case 14: {
                    string l, k;
                    cout << "\nNhap URL: ";
                    getline(cin, l);
                    cout << "Nhap KEY giai ma: ";
                    getline(cin, k);

                    Client g("guest", server);
                    lastMessage = g.accessLink(l, k);
                    break;
                }
                case 15: {
                    if (!currentClient) {
                        lastMessage = "[!] Can dang nhap.";
                        break;
                    }

                    string l;
                    cout << "\nNhap URL: ";
                    getline(cin, l);
                    lastMessage = currentClient->revokeLink(l);
                    break;
                }
                default:
                    lastMessage = "Lua chon khong hop le.";
            }
        }
    } catch (const exception& e) {
        cerr << "LOI: " << e.what() << endl;
    }

    return 0;
}
