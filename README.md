# ropotnet_ai

---

## 🇦🇪 بالعربي

**روبوترون الذكاء الاصطناعي الآمن**

مشروع برمجيات يستخدم الذكاء الاصطناعي مع التشفير القوي وقاعدة بيانات SQLite. يوفر واجهة تفاعلية مشفرة وآمنة لحفظ وتدريب الردود ويدعم حماية كلمة المرور والتحقق.

### الميزات الرئيسية
- تخزين الردود في قاعدة بيانات SQLite مشفرة
- حماية كلمات المرور باستخدام خوارزمية bcrypt
- تشفير وأمان عبر AES-256 (tiny-AES-c)
- إمكانية "وضع التعلم" لتدريب الروبوت على ردود جديدة
- التحقق من سلامة قاعدة البيانات

### متطلبات التشغيل
- مترجم C++ (مثل: g++)
- مكتبة SQLite3
- مكتبة OpenSSL
- مكتبة libbcrypt (https://github.com/rg3/libbcrypt)
- مكتبة tiny-AES-c (https://github.com/kokke/tiny-AES-c)

> **ملاحظة:** يجب تضمين ملفات C المطلوبة من المكتبات الخارجية في المشروع

### خطوات التثبيت والتشغيل
1. تثبيت المتطلبات أعلاه
2. ترجمة الكود:
   ```bash
   g++ ropotnet_ai.cpp -lsqlite3 -lssl -lcrypto -o ropotnet_ai
   ```
3. تشغيل البرنامج:
   ```bash
   ./ropotnet_ai
   ```
4. أول استخدام يطلب إنشاء كلمة سر رئيسية

### معلومات
جميع الحقوق محفوظة. هذا المشروع تعليمي ويمكن تطويره حسب الحاجة.

---

## 🇬🇧 English

**Secure AI Chatbot Project**

This project is an AI assistant with strong encryption and SQLite database support. It provides an interactive, secure, and encrypted interface for saving and training responses, with master password protection and verification.

### Core Features
- Store encrypted responses in SQLite database
- Password protection using bcrypt
- AES-256 encryption (tiny-AES-c)
- "Learning mode" to train new responses easily
- Database integrity check on start

### Requirements
- C++ compiler (e.g., g++)
- SQLite3 library
- OpenSSL library
- libbcrypt (https://github.com/rg3/libbcrypt)
- tiny-AES-c (https://github.com/kokke/tiny-AES-c)

> **Note:** You must include C source files from external libraries into your project.

### Installation & Usage
1. Install the above dependencies
2. Build the code:
   ```bash
   g++ ropotnet_ai.cpp -lsqlite3 -lssl -lcrypto -o ropotnet_ai
   ```
3. Run the program:
   ```bash
   ./ropotnet_ai
   ```
4. On first use, you will be asked to create a master password

### Info
All rights reserved. This project is for learning purposes and open for further development.
