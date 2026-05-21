#include <iostream>
#include <string>
#include <sqlite3.h>
#include <vector>
#include <sstream>
#include <algorithm>
#include <chrono>
#include <thread>
#include <cstring>

#include "bcrypt.h"   // https://github.com/rg3/libbcrypt (you must include C files in your project)
#include "aes.h"      // https://github.com/kokke/tiny-AES-c (you must include C files in your project)
#include <openssl/evp.h>  // for PBKDF2 (key derivation from password)

using namespace std;

// === AES Encryption Utilities using tiny-AES-c ===
#define AES_KEYLEN 32 // 256 bit key
#define AES_IVLEN 16
std::string derive_key(const std::string& pwd, const std::string& salt)
{
    unsigned char key[AES_KEYLEN];
    PKCS5_PBKDF2_HMAC_SHA1(pwd.c_str(), pwd.size(),
                           (const unsigned char*)salt.c_str(), salt.size(),
                           100000, // Iteration count (high for safety, can decrease for perf)
                           AES_KEYLEN, key);
    return std::string((char*)key, AES_KEYLEN);
}

// Encrypt data using AES-CBC
std::string aes_encrypt(const std::string& raw, const std::string& key, std::string& out_iv)
{
    // Generate IV (should be random each time, 16 bytes)
    unsigned char iv[AES_IVLEN];
    FILE* urand = fopen("/dev/urandom", "rb");
    fread(iv, 1, AES_IVLEN, urand); fclose(urand);
    out_iv.assign((char*)iv, AES_IVLEN);

    struct AES_ctx ctx;
    std::string data = raw;
    // Pad data to a multiple of AES block size (16)
    size_t pad = 16 - (data.size() % 16);
    data.append(pad, static_cast<char>(pad));
    unsigned char* buf = (unsigned char*)malloc(data.size());
    memcpy(buf, data.data(), data.size());
    AES_init_ctx_iv(&ctx, (const uint8_t*)key.data(), iv);
    AES_CBC_encrypt_buffer(&ctx, buf, data.size());
    std::string encrypted((char*)buf, data.size());
    free(buf);
    return encrypted;
}
// Decrypt data using AES-CBC
std::string aes_decrypt(const std::string& encrypted, const std::string& key, const std::string& iv)
{
    struct AES_ctx ctx;
    unsigned char* buf = (unsigned char*)malloc(encrypted.size());
    memcpy(buf, encrypted.data(), encrypted.size());
    AES_init_ctx_iv(&ctx, (const uint8_t*)key.data(), (const uint8_t*)iv.data());
    AES_CBC_decrypt_buffer(&ctx, buf, encrypted.size());
    // Remove padding
    size_t pad = buf[encrypted.size()-1];
    size_t sz = encrypted.size()-pad;
    std::string decrypted((char*)buf, sz);
    free(buf);
    return decrypted;
}

// Constant-time string comparison
bool constantTimeCompare(const std::string& a, const std::string& b) {
    if (a.length() != b.length()) return false;
    unsigned char result = 0;
    for (size_t i = 0; i < a.length(); ++i) {
        result |= a[i] ^ b[i];
    }
    return result == 0;
}

// Normalization function as before (remove SQLi vectors, clean input, lowercase, etc.)
std::string normalize(std::string str) {
    std::transform(str.begin(), str.end(), str.begin(), ::tolower);
    // Remove dangerous characters; adjust as needed.
    str.erase(std::remove_if(str.begin(), str.end(), [](char c) {
        return c == '%' || c == '_' || c == '\'' || c == '"' || c == ';';
    }), str.end());
    if (str.length() > 50) str = str.substr(0, 50);
    return str;
}

// Print with wrapping
void printWrapped(std::string text) {
    int maxWidth = 60;
    std::stringstream ss(text);
    std::string word, line;
    while (ss >> word) {
        if (line.length() + word.length() + 1 > maxWidth) {
            std::cout << line << std::endl;
            line = word;
        } else {
            if (!line.empty()) line += " ";
            line += word;
        }
    }
    if (!line.empty()) std::cout << line << std::endl;
}

void clearScreen() {
    std::cout << "\033[2J\033[1;1H";
}

// Get a password securely from the user, no echo (Linux only for this example)
std::string getPassword(const std::string& prompt) {
    std::string password;
    std::cout << "\033[1;37m" << prompt << "\033[0m";
    system("stty -echo");
    getline(cin, password);
    system("stty echo");
    std::cout << std::endl;
    return password;
}

// Save password hash (bcrypt) in the DB
void savePassword(sqlite3* db, const std::string& pwd) {
    char salt[BCRYPT_HASHSIZE];
    char hash[BCRYPT_HASHSIZE];
    bcrypt_gensalt(12, salt); // 12 is secure
    bcrypt_hashpw(pwd.c_str(), salt, hash);
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS config (config_key TEXT PRIMARY KEY, config_val TEXT);", NULL, NULL, NULL);
    sqlite3_stmt* st;
    std::string sql = "INSERT OR REPLACE INTO config (config_key, config_val) VALUES ('master_pwd', ?);";
    sqlite3_prepare_v2(db, sql.c_str(), -1, &st, NULL);
    sqlite3_bind_text(st, 1, hash, -1, SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

// Get saved password hash
std::string getSavedPassword(sqlite3* db) {
    sqlite3_exec(db, "CREATE TABLE IF NOT EXISTS config (config_key TEXT PRIMARY KEY, config_val TEXT);", NULL, NULL, NULL);
    sqlite3_stmt* st;
    std::string sql = "SELECT config_val FROM config WHERE config_key = 'master_pwd';";
    sqlite3_prepare_v2(db, sql.c_str(), -1, &st, NULL);
    std::string pwd = "";
    if (sqlite3_step(st) == SQLITE_ROW) {
        pwd = std::string((const char*)sqlite3_column_text(st, 0));
    }
    sqlite3_finalize(st);
    return pwd;
}

// Save AI reply encrypted with AES
void teachAI(sqlite3* db, const std::string& key, const std::string& response,
             const std::string& aeskey) {
    // Use fixed salt for key derivation (for DB; you can randomize per item)
    std::string salt = "ropotsalt2026";
    std::string kkey = derive_key(aeskey, salt);

    // Save IV for each row (to allow decryption)
    std::string k_iv, r_iv;
    std::string enc_key = aes_encrypt(key, kkey, k_iv);
    std::string enc_resp = aes_encrypt(response, kkey, r_iv);

    sqlite3_stmt* st;
    std::string sql = "INSERT INTO brain (key, response, key_iv, resp_iv) VALUES (?, ?, ?, ?);";
    sqlite3_prepare_v2(db, sql.c_str(), -1, &st, NULL);
    sqlite3_bind_blob(st, 1, enc_key.data(), enc_key.size(), SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 2, enc_resp.data(), enc_resp.size(), SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 3, k_iv.data(), k_iv.size(), SQLITE_TRANSIENT);
    sqlite3_bind_blob(st, 4, r_iv.data(), r_iv.size(), SQLITE_TRANSIENT);
    sqlite3_step(st);
    sqlite3_finalize(st);
}

// Authenticate input password by checking bcrypt hash
bool verifyPassword(const std::string& entered, const std::string& saved_hash) {
    return bcrypt_checkpw(entered.c_str(), saved_hash.c_str()) == 0;
}

// Check if DB was tampered with (has brain data but no master pwd)
bool isDatabaseTampered(sqlite3* db) {
    sqlite3_stmt* st;
    std::string sql = "SELECT COUNT(*) FROM brain;";
    int count = 0;
    if (sqlite3_prepare_v2(db, sql.c_str(), -1, &st, NULL) == SQLITE_OK) {
        if (sqlite3_step(st) == SQLITE_ROW) {
            count = sqlite3_column_int(st, 0);
        }
    }
    sqlite3_finalize(st);
    return count > 0;
}

int main() {
    setlocale(LC_ALL, "en_US.UTF-8");
    sqlite3* db;
    sqlite3_open("ropotnet.db", &db);
    sqlite3_exec(db,
        "CREATE TABLE IF NOT EXISTS brain (id INTEGER PRIMARY KEY AUTOINCREMENT, "
        "key BLOB, response BLOB, key_iv BLOB, resp_iv BLOB);", NULL, NULL, NULL);
    clearScreen();
    std::cout << "\033[1;32m╔══════════════════════════════════════╗\033[0m" << std::endl;
    std::cout << "\033[1;32m║          [ Ropotnet AI Secure ]      ║\033[0m" << std::endl;
    std::cout << "\033[1;32m╚══════════════════════════════════════╝\033[0m" << std::endl;

    std::string saved_hash = getSavedPassword(db);
    std::string current_master_key = "";

    if (saved_hash.empty()) {
        if (isDatabaseTampered(db)) {
            std::cout << "\033[1;31m[خطأ أمني]: تم رصد تلاعب بقاعدة البيانات!\033[0m" << std::endl;
            sqlite3_close(db);
            return 0;
        }
        std::cout << "[Setup]: Please set your master password." << std::endl;
        std::string npwd;
        do {
            npwd = getPassword("Create New Master Password: ");
        } while (npwd.empty());
        savePassword(db, npwd);
        std::cout << "Saved hash, restart to use." << std::endl;
        sqlite3_close(db);
        return 0;
    }

    int attempts = 0;
    bool authenticated = false;
    while (attempts < 3) {
        std::string try_pwd = getPassword("Enter Master Password: ");
        if (verifyPassword(try_pwd, saved_hash)) {
            authenticated = true;
            current_master_key = try_pwd;
            break;
        }
        attempts++;
        std::cout << "[Bad password, try " << (attempts + 1) << "/3]" << std::endl;
    }

    if (!authenticated) {
        std::cout << "[Too many attempts. Delaying...]" << std::endl;
        std::this_thread::sleep_for(std::chrono::seconds(5));
        sqlite3_close(db);
        return 0;
    }

    clearScreen();
    std::cout << "\033[1;36mAI Ready! Type <Learning Mode> to train responses.\033[0m" << std::endl;

    while (true) {
        std::cout << "\033[1;32m┌───[ You ]\033[0m\n\033[1;32m└─> \033[0m";
        std::string input;
        getline(cin, input);

        if (input == "exit" || input == "خروج") break;
        if (input.empty()) continue;

        std::string checkInput = input;
        std::transform(checkInput.begin(), checkInput.end(), checkInput.begin(), ::tolower);

        if (checkInput == "<learning mode>") {
            std::string check_pwd = getPassword("Confirm Master Password: ");
            if (verifyPassword(check_pwd, saved_hash)) {
                std::cout << "Enter trigger key: ";
                std::string t_key; getline(cin, t_key);
                std::cout << "Enter response: ";
                std::string t_res; getline(cin, t_res);
                if (!t_key.empty() && !t_res.empty()) {
                    teachAI(db, normalize(t_key), t_res, current_master_key);
                    std::cout << "[Saved]\n";
                } else {
                    std::cout << "[Canceled]\n";
                }
            } else {
                std::cout << "[Wrong password, learning mode canceled.]\n";
            }
            continue;
        }

        std::string cleanInput = normalize(input);
        if (cleanInput.empty()) continue;

        // Search for triggers
        std::string salt = "ropotsalt2026";
        std::string kkey = derive_key(current_master_key, salt);
        sqlite3_stmt* st;
        std::string sql = "SELECT key, response, key_iv, resp_iv FROM brain;";
        std::vector<std::string> responses;

        if (sqlite3_prepare_v2(db, sql.c_str(), -1, &st, NULL) == SQLITE_OK) {
            while (sqlite3_step(st) == SQLITE_ROW) {
                // Decrypt keys and responses
                const char* enc_k = (const char*)sqlite3_column_blob(st, 0);
                int ek_len = sqlite3_column_bytes(st, 0);
                const char* enc_r = (const char*)sqlite3_column_blob(st, 1);
                int er_len = sqlite3_column_bytes(st, 1);
                const char* k_iv = (const char*)sqlite3_column_blob(st, 2);
                const char* r_iv = (const char*)sqlite3_column_blob(st, 3);
                if (enc_k && enc_r && k_iv && r_iv) {
                    std::string dec_key =
                        aes_decrypt(std::string(enc_k, ek_len), kkey, std::string(k_iv, AES_IVLEN));
                    std::string dec_res =
                        aes_decrypt(std::string(enc_r, er_len), kkey, std::string(r_iv, AES_IVLEN));
                    if (cleanInput.find(dec_key) != std::string::npos ||
                        dec_key.find(cleanInput) != std::string::npos) {
                        if (std::find(responses.begin(), responses.end(), dec_res) == responses.end()) {
                            responses.push_back(dec_res);
                        }
                    }
                }
            }
        }
        sqlite3_finalize(st);

        std::cout << "\033[1;37mAI >>\033[0m" << std::endl;
        if (!responses.empty()) {
            for (size_t i = 0; i < responses.size(); i++) {
                printWrapped(responses[i]);
                if (i < responses.size() - 1) {
                    std::cout << "\033[1;35m   [or]   \033[0m" << std::endl;
                }
            }
            std::cout << std::endl;
        } else {
            std::cout << "No response trained for this input." << std::endl << std::endl;
        }
    }
    sqlite3_close(db);
    return 0;
}