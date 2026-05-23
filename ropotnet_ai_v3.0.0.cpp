#include <iostream>
#include <string>
#include <sqlite3.h>
#include <vector>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <thread>
#include <cstring>

// موجهات نظام التشغيل للحصول على وظائف قراءة لوحة المفاتيح الصامتة وإخفاء الباسورد
#if defined(_WIN32) || defined(_WIN64)
    #define ROPOTNET_OS "Windows"
    #define ROPOTNET_DEVICE "PC (Desktop)"
    #include <windows.h>
    #include <winsock2.h>
    #include <ws2tcpip.h>
    #pragma comment(lib, "ws2_32.lib")
#elif defined(__ANDROID__)
    #define ROPOTNET_OS "Android"
    #define ROPOTNET_DEVICE "Mobile Handset"
    #include <termios.h>
    #include <unistd.h>
#elif defined(__APPLE__)
    #include <TargetConditionals.h>
    #include <termios.h>
    #include <unistd.h>
    #if TARGET_OS_IPHONE
        #define ROPOTNET_OS "iOS"
        #define ROPOTNET_DEVICE "Mobile Handset"
    #else
        #define ROPOTNET_OS "macOS"
        #define ROPOTNET_DEVICE "PC (Desktop)"
    #endif
#elif defined(__linux__)
    #define ROPOTNET_OS "Linux"
    #define ROPOTNET_DEVICE "PC (Desktop)"
    #include <termios.h>
    #include <unistd.h>
    #include <sys/socket.h>
    #include <arpa/inet.h>
#else
    #define ROPOTNET_OS "Unknown OS"
    #define ROPOTNET_DEVICE "Generic Device"
#endif

using namespace std;

// ==========================================
// ألوان الـ ANSI السيبرانية المتقدمة
// ==========================================
#define CLR_RESET   "\033[0m"
#define CLR_BOLD    "\033[1m"
#define CLR_CYAN    "\033[38;5;39m"    // أزرق كمي فخم
#define CLR_GREEN   "\033[38;5;84m"    // أخضر نيون نشط
#define CLR_GRAY    "\033[38;5;244m"   // رمادي مطفأ للهوامش
#define CLR_RED     "\033[38;5;203m"   // أحمر تحذيري
#define CLR_YELLOW  "\033[38;5;220m"   // أصفر للتنبيهات والـ IP
#define CLR_PURPLE  "\033[38;5;141m"   // بنفسجي كلاسيكي للروبوت
#define CLR_BG_DARK "\033[48;5;234m"   // خلفية داكنة مخصصة

enum Language { EN, AR };
Language currentLang = EN;

struct Session {
    string agentName = "Agent";
    string agentEmail = "name@ropotnet.com";
    string masterHash = "";
    string activeSessionKey = "";
};

Session currentSession;

// ==========================================
// دوال التشفير والتحقق الأمني (نفس قوة النواة)
// ==========================================

string secureHash(const string& str) {
    unsigned long long hash = 14695981039346656037ULL;
    for (char c : str) {
        hash ^= static_cast<unsigned char>(c);
        hash *= 1099511628211ULL;
    }
    stringstream ss;
    ss << hex << hash;
    return ss.str();
}

bool constantTimeCompare(const string& hash_a, const string& hash_b) {
    if (hash_a.length() != hash_b.length()) return false; 
    int result = 0;
    for (size_t i = 0; i < hash_a.length(); ++i) {
        result |= (hash_a[i] ^ hash_b[i]);
    }
    return result == 0;
}

string dbCipher(const string& data, const string& key) {
    string actual_key = key.empty() ? "RopotnetFallbackKey2026" : key;
    string output = data;
    for (size_t i = 0; i < data.size(); i++) {
        output[i] = data[i] ^ actual_key[i % actual_key.size()]; 
    }
    return output;
}

// ==========================================
// إدارة قاعدة البيانات SQLite3
// ==========================================

void initDatabase(sqlite3* db) {
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS system_config (config_key TEXT PRIMARY KEY, config_val TEXT);", NULL, NULL, NULL);
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS secure_brain (id INTEGER PRIMARY KEY AUTOINCREMENT, pattern TEXT, response TEXT);", NULL, NULL, NULL);
}

void saveConfig(sqlite3* db, const string& key, const string& val) {
    sqlite3_stmt* st;
    string sql = "INSERT OR REPLACE INTO system_config (config_key, config_val) VALUES (?, ?);";
    sqlite3_prepare_v2(db, sql.c_str(), -1, &st, NULL);
    sqlite3_bind_text(st, 1, key.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_bind_text(st, 2, val.c_str(), -1, SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

string getConfig(sqlite3* db, const string& key) {
    sqlite3_stmt* st;
    string sql = "SELECT config_val FROM system_config WHERE config_key = ?;";
    string val = "";
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &st, NULL) == SQLITE_OK) {
        sqlite3_bind_text(st, 1, key.c_str(), -1, SQLITE_TRANSIENT);
        if (sqlite3_step(st) == SQLITE_ROW) {
            val = (const char*)sqlite3_column_text(st, 0);
        }
    }
    sqlite3_finalize(st);
    return val;
}

// ==========================================
// فحص النظام وتحديد الـ IP صامتاً
// ==========================================

#ifdef _WIN32
bool initSockets() { WSADATA w; return WSAStartup(MAKEWORD(2,2), &w) == 0; }
void cleanupSockets() { WSACleanup(); }
#else
bool initSockets() { return true; }
void cleanupSockets() {}
#endif

string getSilentIP() {
    if (!initSockets()) return "127.0.0.1";
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) { cleanupSockets(); return "127.0.0.1"; }

    sockaddr_in loopback;
    memset(&loopback, 0, sizeof(loopback));
    loopback.sin_family = AF_INET;
    loopback.sin_addr.s_addr = inet_addr("8.8.8.8");
    loopback.sin_port = htons(53);

    string ip = "127.0.0.1";
    if (connect(sock, reinterpret_cast<sockaddr*>(&loopback), sizeof(loopback)) == 0) {
        sockaddr_in name;
        socklen_t len = sizeof(name);
        if (getsockname(sock, reinterpret_cast<sockaddr*>(&name), &len) == 0) {
            char buf[16];
            inet_ntop(AF_INET, &(name.sin_addr), buf, sizeof(buf));
            ip = string(buf);
        }
    }
#ifdef _WIN32
    closesocket(sock);
#else
    close(sock);
#endif
    cleanupSockets();
    return ip;
}

// ==========================================
// إدخال البيانات دون إظهار الحروف (Password mask)
// ==========================================

string getHiddenInput() {
    string input;
#ifdef _WIN32
    HANDLE hStdin = GetStdHandle(STD_INPUT_HANDLE);
    DWORD mode = 0;
    GetConsoleMode(hStdin, &mode);
    SetConsoleMode(hStdin, mode & (~ENABLE_ECHO_INPUT));
    getline(cin, input);
    SetConsoleMode(hStdin, mode);
#else
    termios oldt;
    tcgetattr(STDIN_FILENO, &oldt);
    termios newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    getline(cin, input);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
#endif
    return input;
}

// ==========================================
// نظام الواجهة النصية ورسم الإطارات (TUI Rendering)
// ==========================================

void clearScreen() {
    cout << "\033[2J\033[1;1H";
}

void drawHorizontalLine(int width) {
    cout << CLR_GRAY;
    for (int i = 0; i < width; ++i) cout << "═";
    cout << CLR_RESET << endl;
}

void drawHeader() {
    clearScreen();
    cout << CLR_CYAN << CLR_BOLD << "╔══════════════════════════════════════════════════════════╗" << CLR_RESET << endl;
    cout << CLR_CYAN << CLR_BOLD << "║ " << CLR_GREEN << "Ropotnet AI Console " << CLR_CYAN << "◆ " << CLR_PURPLE << "Secure Node" << CLR_CYAN << "                 ║" << CLR_RESET << endl;
    cout << CLR_CYAN << CLR_BOLD << "╚══════════════════════════════════════════════════════════╝" << CLR_RESET << endl;
    
    // شريط معلومات العميل والموقع الجغرافي الصامت
    cout << CLR_GRAY << "  Agent: " << CLR_CYAN << currentSession.agentEmail 
         << CLR_GRAY << " | Language: " << CLR_YELLOW << (currentLang == EN ? "EN" : "AR") 
         << CLR_GRAY << " | Status: " << CLR_GREEN << "Handshake Active" << CLR_RESET << endl;
    drawHorizontalLine(60);
}

// ==========================================
// سيناريوهات الشاشات (Setup & Lock Screens)
// ==========================================

void runFirstTimeSetup(sqlite3* db) {
    clearScreen();
    cout << CLR_CYAN << "╔══════════════════════════════════════════════════════════╗" << endl;
    cout << "║             ROPOTNET SYSTEM Boot Initialization          ║" << endl;
    cout << "╚══════════════════════════════════════════════════════════╝" << CLR_RESET << endl;
    cout << CLR_YELLOW << " [SYSTEM INFO] No master profile detected on this machine." << CLR_RESET << endl << endl;
    
    string name, pwd;
    cout << CLR_BOLD << " > Set Profile Identity Name: " << CLR_RESET;
    getline(cin, name);
    
    cout << CLR_BOLD << " > Create Master Security Passkey: " << CLR_RESET;
    pwd = getHiddenInput();
    cout << CLR_GREEN << " [Encrypted Successfully]" << CLR_RESET << endl;

    if (name.empty() || pwd.empty()) {
        cout << CLR_RED << " [Error] Missing critical initial credentials." << CLR_RESET << endl;
        exit(1);
    }

    string email = name + "@ropotnet.com";
    transform(email.begin(), email.end(), email.begin(), ::tolower);
    email.erase(remove_if(email.begin(), email.end(), ::isspace), email.end());

    saveConfig(db, "agent_name", name);
    saveConfig(db, "agent_email", email);
    saveConfig(db, "master_hash", secureHash(pwd));

    cout << endl << CLR_GREEN << "╔══════════════════════════════════════════════════════════╗" << endl;
    cout << "║      Initialization Complete! Please restart console.    ║" << endl;
    cout << "╚══════════════════════════════════════════════════════════╝" << CLR_RESET << endl;
    exit(0);
}

void runLockScreen(sqlite3* db) {
    clearScreen();
    string storedHash = getConfig(db, "master_hash");
    string storedName = getConfig(db, "agent_name");
    string storedEmail = getConfig(db, "agent_email");

    cout << CLR_CYAN << "╔══════════════════════════════════════════════════════════╗" << endl;
    cout << "║                    ROPOTNET LOCK GATE                    ║" << endl;
    cout << "╚══════════════════════════════════════════════════════════╝" << CLR_RESET << endl;
    cout << CLR_BOLD << " Welcome back, Agent " << CLR_PURPLE << storedName << CLR_RESET << endl;
    cout << CLR_GRAY << " Decrypt terminal session nodes below." << CLR_RESET << endl << endl;

    int attempts = 0;
    while (attempts < 3) {
        cout << " Enter Master Passkey: ";
        string pwd = getHiddenInput();
        string inputHash = secureHash(pwd);

        if (constantTimeCompare(inputHash, storedHash)) {
            currentSession.agentName = storedName;
            currentSession.agentEmail = storedEmail;
            currentSession.masterHash = storedHash;
            currentSession.activeSessionKey = pwd; // مفتاح تشفير وفك الجلسة التلقائي
            return; // تم تخطي البوابة الأمنية بنجاح
        }
        attempts++;
        cout << CLR_RED << " [ACCESS DENIED] Signature mismatch. (" << attempts << "/3)" << CLR_RESET << endl;
    }

    cout << CLR_RED << "\n [LOCKOUT TRIGGERED] Secure shutdown activated." << CLR_RESET << endl;
    this_thread::sleep_for(chrono::seconds(3));
    exit(1);
}

// ==========================================
// قائمة الإعدادات الفرعية الفاخرة ≡
// ==========================================

void executeSettingsMenu(sqlite3* db) {
    while (true) {
        drawHeader();
        if (currentLang == EN) {
            cout << CLR_BOLD << " ≡ SYSTEM CONFIGURATION & DIAGNOSTICS" << CLR_RESET << endl;
            cout << CLR_GRAY << " ──────────────────────────────────────────────────────────" << CLR_RESET << endl;
            cout << "  [1] Toggle Language (العربية)" << endl;
            cout << "  [2] Secret Hardware Telemetry (صامت)" << endl;
            cout << "  [3] Reset & Purge Memory Nodes" << endl;
            cout << "  [4] Return to Chat Console" << endl;
            cout << "  [5] Tutorial Mode (وضع التعليم)" << endl;
            cout << CLR_GRAY << " ──────────────────────────────────────────────────────────" << CLR_RESET << endl;
            cout << " Enter command code: ";
        } else {
            cout << CLR_BOLD << " ≡ لوحة التحكم وفحص النظام الذكي" << CLR_RESET << endl;
            cout << CLR_GRAY << " ──────────────────────────────────────────────────────────" << CLR_RESET << endl;
            cout << "  [1] تغيير لغة النظام للإنجليزية (English)" << endl;
            cout << "  [2] تشخيص بصمة الجهاز الفنية (صامت)" << endl;
            cout << "  [3] مسح وإعادة تهيئة ذاكرة الروبوت بالكامل" << endl;
            cout << "  [4] العودة لشاشة المحادثة الآمنة" << endl;
            cout << "  [5] تشغيل وضع التعليم (Tutorial Mode)" << endl;
            cout << CLR_GRAY << " ──────────────────────────────────────────────────────────" << CLR_RESET << endl;
            cout << " أدخل رمز الأمر المطلوب: ";
        }

        string cmd;
        getline(cin, cmd);

        if (cmd == "1") {
            currentLang = (currentLang == EN) ? AR : EN;
        } 
        else if (cmd == "2") {
            // عرض التشخيص الفني الحقيقي والصامت للجهاز
            drawHeader();
            string my_ip = getSilentIP();
            if (currentLang == EN) {
                cout << CLR_BOLD << " ⚙ TELEMETRY REPORT" << CLR_RESET << endl;
                cout << "  > Platform Core:  " << CLR_GREEN << ROPOTNET_OS << CLR_RESET << endl;
                cout << "  > Device Type:    " << CLR_GREEN << ROPOTNET_DEVICE << CLR_RESET << endl;
                cout << "  > Active Local IP: " << CLR_YELLOW << my_ip << CLR_RESET << endl;
            } else {
                cout << CLR_BOLD << " ⚙ تقرير تشخيص النظام الصامت" << CLR_RESET << endl;
                cout << "  > النواة النشطة:      " << CLR_GREEN << ROPOTNET_OS << CLR_RESET << endl;
                cout << "  > فئة هيكل الجهاز:    " << CLR_GREEN << ROPOTNET_DEVICE << CLR_RESET << endl;
                cout << "  > عنوان الـ IP الفعال:  " << CLR_YELLOW << my_ip << CLR_RESET << endl;
            }
            cout << endl << CLR_GRAY << " Press ENTER to return..." << CLR_RESET;
            string temp;
            getline(cin, temp);
        }
        else if (cmd == "3") {
            if (currentLang == EN) {
                cout << CLR_RED << " WARNING: This will delete everything in ropotnet_secure.db. Continue? (y/n): " << CLR_RESET;
            } else {
                cout << CLR_RED << " تحذير: هذا الإجراء سيمسح قاعدة البيانات بالكامل. هل تريد الاستمرار؟ (y/n): " << CLR_RESET;
            }
            string confirm;
            getline(cin, confirm);
            if (confirm == "y" || confirm == "Y" || confirm == "نعم") {
                sqlite3_exec(db, "DROP TABLE IF EXISTS system_config;", NULL, NULL, NULL);
                sqlite3_exec(db, "DROP TABLE IF EXISTS secure_brain;", NULL, NULL, NULL);
                if (currentLang == EN) {
                    cout << CLR_GREEN << " All nodes purged. Restarting..." << CLR_RESET << endl;
                } else {
                    cout << CLR_GREEN << " تم تفريغ قاعدة البيانات بالكامل. جاري إيقاف التشغيل..." << CLR_RESET << endl;
                }
                this_thread::sleep_for(chrono::seconds(2));
                exit(0);
            }
        }
        else if (cmd == "4") {
            break;
        }
        else if (cmd == "5") {
            drawHeader();
            if (currentLang == EN) {
                cout << CLR_BOLD << " [TUTORIAL MODE]" << CLR_RESET << endl;
                cout << " * This program connects to a local database called 'ropotnet_secure.db'." << endl;
                cout << " * It uses a secure hashing function 'secureHash' to protect your password." << endl;
                cout << " * The 'dbCipher' function encrypts text using a basic XOR operation." << endl;
            } else {
                cout << CLR_BOLD << " [وضع التعليم]" << CLR_RESET << endl;
                cout << " * هذا البرنامج يتصل بقاعدة بيانات محلية تسمى 'ropotnet_secure.db'." << endl;
                cout << " * يستخدم دالة 'secureHash' لحماية وتشفير كلمة المرور الخاصة بك." << endl;
                cout << " * دالة 'dbCipher' تقوم بتشفير النصوص باستخدام عمليات XOR الرياضية المبسطة." << endl;
            }
            cout << endl << CLR_GRAY << " Press ENTER to return..." << CLR_RESET;
            string temp;
            getline(cin, temp);
        }
    }
}

// ==========================================
// الحلقة البرمجية الرئيسية للمحادثة
// ==========================================

int main() {
    setlocale(LC_ALL, "en_US.UTF-8");
    sqlite3* db;
    
    if (sqlite3_open("ropotnet_secure.db", &db) != SQLITE_OK) {
        cout << "[CRITICAL ERROR] Failed to connect to secure memory layer." << endl;
        return 1;
    }

    initDatabase(db);
    string hasProfile = getConfig(db, "master_hash");

    if (hasProfile.empty()) {
        runFirstTimeSetup(db);
    } else {
        runLockScreen(db);
    }

    // الدخول لواجهة الشات النصية الفاخرة
    while (true) {
        drawHeader();
        if (currentLang == EN) {
            cout << CLR_BOLD << " Ropotnet AI Engine is ready. Type <≡> or <settings> to open panel." << endl;
            cout << " Type <exit> to lock console." << CLR_RESET << endl << endl;
            cout << CLR_CYAN << " ┌───[ You ]" << CLR_RESET << endl;
            cout << CLR_CYAN << " └─> " << CLR_RESET;
        } else {
            cout << CLR_BOLD << " الروبوت جاهز للدردشة. اكتب <≡> أو <settings> لفتح لوحة التحكم والترس." << endl;
            cout << " اكتب <exit> لقفل شاشة الكونسول." << CLR_RESET << endl << endl;
            cout << CLR_CYAN << " ┌───[ المطور ]" << CLR_RESET << endl;
            cout << CLR_CYAN << " └─> " << CLR_RESET;
        }

        string input;
        getline(cin, input);

        if (input == "exit" || input == "خروج") {
            break;
        }

        if (input == "≡" || input == "settings" || input == "إعدادات") {
            executeSettingsMenu(db);
            continue;
        }

        if (input.empty()) continue;

        // محاكاة معالجة وتلقي الردود وتشفيرها داخل الـ Brain
        cout << endl << CLR_PURPLE << " AI >> " << CLR_RESET;
        if (currentLang == EN) {
            cout << "Processed your secure payload. Verification signature created successfully." << endl;
            cout << CLR_GRAY << " [XOR-64 Key Match]: " << secureHash(input).substr(0, 16) << "..." << CLR_RESET << endl << endl;
        } else {
            cout << "تمت معالجة بياناتك الآمنة بنجاح وتأكيد بصمة التشفير الخاصة بك." << endl;
            cout << CLR_GRAY