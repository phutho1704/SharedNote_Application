#include "app.hpp"

void clearScreen() {
#ifdef _WIN32
    system("cls");
#else
    system("clear");
#endif
}

void printDashboard(const string& user, const string& lastMsg) {
    clearScreen();
    cout << " Nguoi dung: " << (user.empty() ? "[An danh]" : user) << endl;
    cout << "--------------------------------------------" << endl;
    cout << " 1. Dang ky moi                    9. Xoa ghi chu" << endl;
    cout << " 2. Dang nhap                     10. Chia se bang URL (cong khai)" << endl;
    cout << " 3. Chuyen nguoi dung             11. Chia se ghi chu (E2E)" << endl;
    cout << " 4. Liet ke ghi chu cua toi       12. Chia se bang URL (bi mat)" << endl;
    cout << " 5. Them ghi chu (Text)           13. Kiem tra hop thu" << endl;
    cout << " 6. Them ghi chu (File)           14. Truy cap Link URL" << endl;
    cout << " 7. Xem noi dung ghi chu          15. Thu hoi Link URL" << endl;
    cout << " 8. Tai ghi chu ve tep tin        0. Thoat" << endl;
    cout << "--------------------------------------------" << endl;
    cout << " KET QUA / THONG BAO:" << endl;
    if (!lastMsg.empty()) {
        cout << lastMsg << endl;
    } else {
        cout << "           (Chua co hoat dong nao)          " << endl;
    }
    cout << "--------------------------------------------" << endl;
    cout << " Lua chon cua ban: ";
}
