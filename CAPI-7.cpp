#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <locale.h>

#pragma comment(lib, "advapi32.lib")

#define BLOCK_SIZE 128 // Размер буфера для чтения (кратный 16 для AES)

#pragma comment(lib, "advapi32.lib")

void encrypt_file(const char* szIn, const char* szOut, const char* szPassword) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0, hKeyCheckHash = 0;
    HCRYPTKEY hKey = 0;
    FILE* fIn = NULL, * fOut = NULL;

    // 1. Подключение к провайдеру
    CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);

    // 2. Формируем сеансовый ключ на основе пароля
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    CryptHashData(hHash, (BYTE*)szPassword, (DWORD)strlen(szPassword), 0);
    CryptDeriveKey(hProv, CALG_AES_128, hHash, 0, &hKey);

    // 3. Узнаем параметры (длина блока)
    DWORD dwBlockLenBits = 0, dwParamLen = sizeof(DWORD);
    CryptGetKeyParam(hKey, KP_BLOCKLEN, (BYTE*)&dwBlockLenBits, &dwParamLen, 0);
    DWORD dwBlockLenBytes = dwBlockLenBits / 8;

    DWORD dwSaltLen = 0;
    DWORD dwSaltParamSize = sizeof(DWORD);
    // Сначала узнаем размер соли (передаем NULL в качестве буфера)
    CryptGetKeyParam(hKey, KP_SALT, NULL, &dwSaltLen, 0);

    BYTE* pbSalt = NULL;

    if (dwSaltLen > 0) {
        pbSalt = (BYTE*)malloc(dwSaltLen);
        // Получаем само значение соли
        CryptGetKeyParam(hKey, KP_SALT, pbSalt, &dwSaltLen, 0);
    }

    // 4. Задаем параметры (Режим CBC и IV)

    // 1. Установка Salt-значения (если оно было создано вручную)
// Если pbSalt был выделен и заполнен ранее:
    CryptSetKeyParam(hKey, KP_SALT, pbSalt, 0);

    // 2. Режим дописи (Padding)
    // По умолчанию PKCS5_PADDING (значение 1). Установим явно.
    DWORD dwPadding = PKCS5_PADDING;
    CryptSetKeyParam(hKey, KP_PADDING, (BYTE*)&dwPadding, 0);

    // 3. Режим шифрования (Cipher Mode)
    // Используем CBC
    DWORD dwCipherMode = CRYPT_MODE_CBC;
    CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&dwCipherMode, 0);


    BYTE* pbIV = (BYTE*)malloc(dwBlockLenBytes);
    if (pbIV == NULL) {
        wprintf(L"Ошибка выделения памяти под IV\n");
        return;
    }

    //Заполняем IV случайными байтами (с помощью криптостойкого ГСЧ)
    CryptGenRandom(hProv, dwBlockLenBytes, pbIV);


    // 4. Инициализирующий вектор (IV)
    // IV обязателен для режима CBC. Длина IV всегда равна длине блока (для AES - 16 байт).
    // pbIV должен быть заполнен случайными данными через CryptGenRandom заранее.
    CryptSetKeyParam(hKey, KP_IV, pbIV, 0);
    

    // 5. Число битов для сдвига (только для CFB или OFB)
    // Если бы мы выбрали CRYPT_MODE_CFB, нам нужно было бы указать размер сдвига (например, 8 или 128 бит)
    DWORD dwShiftBits = 128; // Пример для AES
    CryptSetKeyParam(hKey, KP_MODE_BITS, (BYTE*)&dwShiftBits, 0);


    // 5. 
    HCRYPTHASH hFileHash = 0;
    // Создаем хеш-объект для подписи данных файла
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hFileHash);

    // 6. Вычисляем проверочный хеш ключа
    BYTE rgbKeyHash[32];
    DWORD dwKeyHashLen = sizeof(rgbKeyHash);
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hKeyCheckHash);
    CryptHashSessionKey(hKeyCheckHash, hKey, 0);
    CryptGetHashParam(hKeyCheckHash, HP_HASHVAL, rgbKeyHash, &dwKeyHashLen, 0);

    // 7. Открываем файлы
    fIn = fopen(szIn, "rb");
    fOut = fopen(szOut, "wb");

    // 8. Записываем ЗАГОЛОВОК в файл
    // --- А) Запись Salt ---
// Записываем длину (4 байта) и само значение
    fwrite(&dwSaltLen, sizeof(DWORD), 1, fOut);
    if (dwSaltLen > 0 && pbSalt != NULL) {
        fwrite(pbSalt, 1, dwSaltLen, fOut);
    }

    // --- Б) Запись хеша ключа (для проверки пароля) ---
    // Записываем длину хеша и сам хеш
    fwrite(&dwKeyHashLen, sizeof(DWORD), 1, fOut);
    fwrite(rgbKeyHash, 1, dwKeyHashLen, fOut);

    // --- В) Запись IV (Инициализирующего вектора) ---
    // Согласно алгоритму, длина IV равна длине блока (dwBlockLenBytes)
    // Записываем длину и сам вектор
    fwrite(&dwBlockLenBytes, sizeof(DWORD), 1, fOut);
    if (dwBlockLenBytes > 0 && pbIV != NULL) {
        fwrite(pbIV, 1, dwBlockLenBytes, fOut);
    }


    // 9. Шифрование порциями
// Мы берем размер буфера, кратный блоку (например, 100 блоков)
    DWORD dwBufferSize = dwBlockLenBytes * 100;
    // Выделяем память: данные + место под возможный лишний блок (padding)
    BYTE* pbBuffer = (BYTE*)malloc(dwBufferSize + dwBlockLenBytes);
    DWORD dwCount = 0;
    BOOL bFinal = FALSE;



    // Правильный цикл чтения
    while (TRUE) {
        // Читаем данные из файла
        dwCount = (DWORD)fread(pbBuffer, 1, dwBufferSize, fIn);
        
        // Проверяем, не дошли ли мы до конца файла
        if (feof(fIn)) bFinal = TRUE;

        //ОБНОВЛЕНИЕ ХЕША ФАЙЛА // Я не сгенерир
        CryptHashData(hFileHash, pbBuffer, dwCount, 0);

        // Шифруем порцию
        // dwCount — сколько байт прочитали (на входе) и сколько стало (на выходе)
        // dwBufferSize + dwBlockLenBytes — полная вместимость буфера
        // Последний параметр — это ОБЩИЙ размер выделенного куска памяти
        CryptEncrypt(hKey, 0, bFinal, 0, pbBuffer, &dwCount, dwBufferSize + dwBlockLenBytes);


        // Записываем результат (шифртекст)
        fwrite(pbBuffer, 1, dwCount, fOut);

        // Если это была последняя порция, выходим из цикла
        if (bFinal) break;
    }

    wprintf(L"Данные успешно зашифрованы и записаны.\n");

    // 13. Очистка
    if (pbIV) free(pbIV);
    if (pbBuffer) free(pbBuffer);
    if (hKey) CryptDestroyKey(hKey);
    if (hHash) CryptDestroyHash(hHash);
    if (hKeyCheckHash) CryptDestroyHash(hKeyCheckHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    if (fIn) fclose(fIn);
    if (fOut) fclose(fOut);
}


int decrypt_file(const char* szInFile, const char* szOutFile, const char* szPassword) {
    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0, hKeyCheckHash = 0; // Инициализируем нулями
    HCRYPTKEY hKey = 0;
    FILE* fIn = NULL, * fOut = NULL;

    // Инициализируем указатели NULL, чтобы cleanup работал корректно
    BYTE* pbBuffer = NULL, * pbSalt = NULL, * pbStoredKeyHash = NULL, * pbIV = NULL;

    DWORD dwCount;

    // 1. Подключение
    if (!CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT)) {
        wprintf(L"Ошибка CryptAcquireContext: %08x\n", GetLastError());
        return 0;
    }

    // 2. Создание ключа (ИСПОЛЬЗУЕМ AES_128, как при шифровании!)
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    CryptHashData(hHash, (BYTE*)szPassword, (DWORD)strlen(szPassword), 0);
    CryptDeriveKey(hProv, CALG_AES_128, hHash, 0, &hKey);

    // 3. Открытие файлов
    fIn = fopen(szInFile, "rb");
    fOut = fopen(szOutFile, "wb");
    if (!fIn || !fOut) {
        wprintf(L"Ошибка открытия файлов\n");
        goto cleanup;
    }

    // --- ЧТЕНИЕ ЗАГОЛОВКА ---

    // Salt
    DWORD dwSaltLen = 0;
    fread(&dwSaltLen, sizeof(DWORD), 1, fIn);
    if (dwSaltLen > 0) {
        pbSalt = (BYTE*)malloc(dwSaltLen);
        fread(pbSalt, 1, dwSaltLen, fIn);
    }

    // Hash
    DWORD dwStoredKeyHashLen = 0;
    fread(&dwStoredKeyHashLen, sizeof(DWORD), 1, fIn);
    if (dwStoredKeyHashLen > 0) {
        pbStoredKeyHash = (BYTE*)malloc(dwStoredKeyHashLen);
        fread(pbStoredKeyHash, 1, dwStoredKeyHashLen, fIn);
    }

    // IV
    DWORD dwIVLen = 0;
    fread(&dwIVLen, sizeof(DWORD), 1, fIn);
    if (dwIVLen > 0) {
        pbIV = (BYTE*)malloc(dwIVLen);
        fread(pbIV, 1, dwIVLen, fIn);
    }

    wprintf(L"Заголовок файла успешно прочитан.\n");

    // --- ШАГ 4: Установка параметров ---

    // Salt
    if (dwSaltLen > 0 && pbSalt != NULL) {
        CryptSetKeyParam(hKey, KP_SALT, pbSalt, 0);
    }

    // Padding (Важно установить так же, как при шифровании)
    DWORD dwPadding = PKCS5_PADDING;
    CryptSetKeyParam(hKey, KP_PADDING, (BYTE*)&dwPadding, 0);

    // Mode
    DWORD dwCipherMode = CRYPT_MODE_CBC;
    CryptSetKeyParam(hKey, KP_MODE, (BYTE*)&dwCipherMode, 0);

    // IV
    if (pbIV != NULL && dwIVLen > 0) {
        CryptSetKeyParam(hKey, KP_IV, pbIV, 0);
        wprintf(L"IV установлен.\n");
    }

    // --- ШАГ 5: Проверка пароля ---
    BYTE rgbCurrentKeyHash[32];
    DWORD dwCurrentKeyHashLen = sizeof(rgbCurrentKeyHash);

    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hKeyCheckHash);
    CryptHashSessionKey(hKeyCheckHash, hKey, 0);
    CryptGetHashParam(hKeyCheckHash, HP_HASHVAL, rgbCurrentKeyHash, &dwCurrentKeyHashLen, 0);

    if (memcmp(pbStoredKeyHash, rgbCurrentKeyHash, dwStoredKeyHashLen) != 0) {
        wprintf(L"\nОШИБКА: Неверный пароль! Хеши ключей не совпадают.\n");
        // Теперь программа корректно завершится при ошибке
        goto cleanup;
    }
    wprintf(L"Пароль подтвержден.\n");


    // --- ШАГ 8: Дешифрование ---
    DWORD dwBlockLenBits = 0;
    DWORD dwParamSize = sizeof(DWORD);
    CryptGetKeyParam(hKey, KP_BLOCKLEN, (BYTE*)&dwBlockLenBits, &dwParamSize, 0);
    DWORD dwBlockLenBytes = dwBlockLenBits / 8;

    // Если размер блока не определился корректно, ставим 16 (AES default)
    if (dwBlockLenBytes == 0) dwBlockLenBytes = 16;

    DWORD dwBufferSize = dwBlockLenBytes * 100;
    pbBuffer = (BYTE*)malloc(dwBufferSize);

    BOOL bFinal = FALSE;

    wprintf(L"Расшифровка данных...\n");

    while (TRUE) {
        dwCount = (DWORD)fread(pbBuffer, 1, dwBufferSize, fIn);

        if (feof(fIn)) bFinal = TRUE;

        if (!CryptDecrypt(hKey, 0, bFinal, 0, pbBuffer, &dwCount)) {
            wprintf(L"Ошибка CryptDecrypt: %08x\n", GetLastError());
            goto cleanup;
        }

        if (dwCount > 0) {
            fwrite(pbBuffer, 1, dwCount, fOut);
        }

        if (bFinal) break;
    }

    wprintf(L"Дешифрование завершено успешно.\n");

cleanup:
    // Очистка ресурсов
    if (pbBuffer) { SecureZeroMemory(pbBuffer, dwBufferSize); free(pbBuffer); }
    if (pbSalt) free(pbSalt);
    if (pbStoredKeyHash) free(pbStoredKeyHash);
    if (pbIV) free(pbIV);

    if (hKeyCheckHash) CryptDestroyHash(hKeyCheckHash);
    if (hKey) CryptDestroyKey(hKey);
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);

    if (fIn) fclose(fIn);
    if (fOut) fclose(fOut);

    return 1;
}


int compare_files(const char* file1, const char* file2) {
    FILE* f1 = fopen(file1, "rb");
    FILE* f2 = fopen(file2, "rb");
    int result = 1;

    if (!f1 || !f2) return 0;

    // Сравниваем побайтово
    while (1) {
        int b1 = fgetc(f1);
        int b2 = fgetc(f2);
        if (b1 != b2) {
            result = 0;
            break;
        }
        if (b1 == EOF) break;
    }

    fclose(f1);
    fclose(f2);
    return result;
}

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <locale.h>

#pragma comment(lib, "advapi32.lib")



int main() {
    setlocale(LC_ALL, "Russian");

    const char* password = "MySecretPassword";
    const char* inputFile = "лекция.webm";
    const char* outputFile = "лекция.enc";
    const char* decrypted = "лекцияdec.webm";

    encrypt_file(inputFile, outputFile, password);
    decrypt_file(outputFile, decrypted, password);

    system("pause");
    return 0;
}