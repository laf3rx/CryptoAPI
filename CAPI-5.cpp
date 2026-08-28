#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <locale.h>

#pragma comment(lib, "advapi32.lib")

// Вспомогательная функция для чтения файла в буфер
BYTE* LoadFile(const char* fileName, DWORD* pdwLen) {
    FILE* f = fopen(fileName, "rb");
    if (!f) return NULL;
    fseek(f, 0, SEEK_END);
    *pdwLen = ftell(f);
    fseek(f, 0, SEEK_SET);
    BYTE* buf = (BYTE*)malloc(*pdwLen);
    if (buf) fread(buf, 1, *pdwLen, f);
    fclose(f);
    return buf;
}

// Функция для сохранения буфера в файл
void SaveFile(const char* fileName, BYTE* pbData, DWORD dwLen) {
    FILE* f = fopen(fileName, "wb");
    if (f) {
        fwrite(pbData, 1, dwLen, f);
        fclose(f);
    }
}

BOOL PrepareContainer(HCRYPTPROV* phProv, LPCSTR szContainerName) {
    if (!CryptAcquireContextA(phProv, szContainerName, NULL, PROV_RSA_FULL, 0)) {
        DWORD err = GetLastError();
        if (err == (DWORD)NTE_BAD_KEYSET || err == (DWORD)0x80090019) {
            if (!CryptAcquireContextA(phProv, szContainerName, NULL, PROV_RSA_FULL, CRYPT_NEWKEYSET)) {
                return FALSE;
            }
            printf("Контейнер '%s' создан.\n", szContainerName);
        }
        else return FALSE;
    }
    else printf("Контейнер '%s' открыт.\n", szContainerName);
    return TRUE;
}

int main() {
    HCRYPTPROV hProv1 = 0, hProv2 = 0, hProv3 = 0, hProvVerify = 0;
    HCRYPTKEY hKeyX = 0, hKeyDS = 0, hSessionKey = 0, hImportedPubKey = 0;
    HCRYPTKEY hSessionFromEnc = 0, hSessionFromPlain = 0;
    HCRYPTHASH hHash = 0;
    HCRYPTKEY hPasswordKey = 0;
    BYTE* pbKeyBlob = NULL;
    DWORD dwBlobLen = 0;
    const char* password = "SUPERKBSUPERKB12";

    setlocale(LC_ALL, "Russian");
    SetConsoleCP(1251);
    SetConsoleOutputCP(1251);

    // --- ПУНКТЫ 1-2: Инициализация ---
    if (!PrepareContainer(&hProv1, "Container1")) return 1;
    if (!PrepareContainer(&hProv2, "Container2")) return 1;
    if (!PrepareContainer(&hProv3, "Container3")) return 1;

    // --- ПУНКТЫ 3-4: Container1 (Exchange Key) ---
    printf("\n--- Пункты 3-4: Генерация и экспорт Public KeyX ---\n");
    CryptGenKey(hProv1, AT_KEYEXCHANGE, (4096 << 16) | CRYPT_EXPORTABLE, &hKeyX);
    CryptExportKey(hKeyX, 0, PUBLICKEYBLOB, 0, NULL, &dwBlobLen);
    pbKeyBlob = (BYTE*)malloc(dwBlobLen);
    CryptExportKey(hKeyX, 0, PUBLICKEYBLOB, 0, pbKeyBlob, &dwBlobLen);
    SaveFile("KeyX Public.bin", pbKeyBlob, dwBlobLen);
    free(pbKeyBlob);
    printf("Файл 'KeyX Public.bin' сохранен.\n");

    // --- ПУНКТ 5: Container2 (Signature Key) ---
    printf("\n--- Пункт 5: Генерация и экспорт Public DS ---\n");
    CryptGenKey(hProv2, AT_SIGNATURE, CRYPT_EXPORTABLE, &hKeyDS);
    CryptExportKey(hKeyDS, 0, PUBLICKEYBLOB, 0, NULL, &dwBlobLen);
    pbKeyBlob = (BYTE*)malloc(dwBlobLen);
    CryptExportKey(hKeyDS, 0, PUBLICKEYBLOB, 0, pbKeyBlob, &dwBlobLen);
    SaveFile("DS Public.bin", pbKeyBlob, dwBlobLen);
    free(pbKeyBlob);
    printf("Файл 'DS Public.bin' сохранен.\n");

    // --- ПУНКТ 6: Сеансовый ключ без контейнера ---
    printf("\n--- Пункт 6: Экспорт сеансовых ключей (Plaintext и Encrypted) ---\n");
    CryptAcquireContext(&hProvVerify, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
    CryptGenKey(hProvVerify, CALG_RC4, CRYPT_EXPORTABLE, &hSessionKey);

    CryptExportKey(hSessionKey, 0, PLAINTEXTKEYBLOB, 0, NULL, &dwBlobLen);
    pbKeyBlob = (BYTE*)malloc(dwBlobLen);
    CryptExportKey(hSessionKey, 0, PLAINTEXTKEYBLOB, 0, pbKeyBlob, &dwBlobLen);
    SaveFile("Session Key Plaintext.bin", pbKeyBlob, dwBlobLen);
    free(pbKeyBlob);

    DWORD dwPubLen;
    BYTE* pbPubKey = LoadFile("KeyX Public.bin", &dwPubLen);
    if (pbPubKey && CryptImportKey(hProvVerify, pbPubKey, dwPubLen, 0, 0, &hImportedPubKey)) {
        CryptExportKey(hSessionKey, hImportedPubKey, SIMPLEBLOB, 0, NULL, &dwBlobLen);
        pbKeyBlob = (BYTE*)malloc(dwBlobLen);
        CryptExportKey(hSessionKey, hImportedPubKey, SIMPLEBLOB, 0, pbKeyBlob, &dwBlobLen);
        SaveFile("Session Key Encrypted.bin", pbKeyBlob, dwBlobLen);
        free(pbKeyBlob);
        printf("Файлы сеансовых ключей созданы.\n");
    }
    if (pbPubKey) free(pbPubKey);

    // --- ПУНКТ 7: Сравнение ключей ---
    printf("\n--- Пункт 7: Сравнение ключей через Container1 ---\n");
    DWORD dwEncLen, dwPlainLen;
    BYTE* pbEncData = LoadFile("Session Key Encrypted.bin", &dwEncLen);
    BYTE* pbPlainData = LoadFile("Session Key Plaintext.bin", &dwPlainLen);

    if (pbEncData && pbPlainData) {
        if (CryptImportKey(hProv1, pbEncData, dwEncLen, 0, 0, &hSessionFromEnc) &&
            CryptImportKey(hProv1, pbPlainData, dwPlainLen, 0, 0, &hSessionFromPlain)) {

            BYTE b1[256], b2[256]; DWORD l1 = 256, l2 = 256;
            CryptExportKey(hSessionFromEnc, 0, PLAINTEXTKEYBLOB, 0, b1, &l1);
            CryptExportKey(hSessionFromPlain, 0, PLAINTEXTKEYBLOB, 0, b2, &l2);

            if (l1 == l2 && memcmp(b1, b2, l1) == 0) printf("Результат: Ключи идентичны.\n");
            else printf("Результат: Ошибка, ключи различаются.\n");
        }
    }
    if (pbEncData) free(pbEncData);
    if (pbPlainData) free(pbPlainData);

    // --- ПУНКТ 8: Экспорт закрытого Signature (Unencrypted) ---
    printf("\n--- Пункт 8: Экспорт закрытого ключа DS (Unencrypted) ---\n");
    CryptExportKey(hKeyDS, 0, PRIVATEKEYBLOB, 0, NULL, &dwBlobLen);
    pbKeyBlob = (BYTE*)malloc(dwBlobLen);
    CryptExportKey(hKeyDS, 0, PRIVATEKEYBLOB, 0, pbKeyBlob, &dwBlobLen);
    SaveFile("DS Private Unencrypted.bin", pbKeyBlob, dwBlobLen);
    free(pbKeyBlob);
    printf("Файл 'DS Private Unencrypted.bin' создан.\n");

    // --- ПУНКТ 9: Экспорт с паролем и импорт в Container3 ---
    printf("\n--- Пункт 9: Перенос защищенного DS в Container3 ---\n");
    CryptCreateHash(hProv2, CALG_SHA1, 0, 0, &hHash);
    CryptHashData(hHash, (BYTE*)password, (DWORD)strlen(password), 0);
    CryptDeriveKey(hProv2, CALG_RC4, hHash, 0, &hPasswordKey);

    CryptExportKey(hKeyDS, hPasswordKey, PRIVATEKEYBLOB, 0, NULL, &dwBlobLen);
    pbKeyBlob = (BYTE*)malloc(dwBlobLen);
    CryptExportKey(hKeyDS, hPasswordKey, PRIVATEKEYBLOB, 0, pbKeyBlob, &dwBlobLen);
    SaveFile("DS Private Encrypted.bin", pbKeyBlob, dwBlobLen);
    free(pbKeyBlob);

    HCRYPTHASH hHash3 = 0;
    HCRYPTKEY hPasswordKey3 = 0, hImportedDS = 0;
    DWORD dwPrivEncLen;
    BYTE* pbPrivEncData = LoadFile("DS Private Encrypted.bin", &dwPrivEncLen);
    if (pbPrivEncData) {
        CryptCreateHash(hProv3, CALG_SHA1, 0, 0, &hHash3);
        CryptHashData(hHash3, (BYTE*)password, (DWORD)strlen(password), 0);
        CryptDeriveKey(hProv3, CALG_RC4, hHash3, 0, &hPasswordKey3);
        if (CryptImportKey(hProv3, pbPrivEncData, dwPrivEncLen, hPasswordKey3, 0, &hImportedDS)) {
            printf("Успех: Пара DS импортирована в Container3.\n");
        }
        free(pbPrivEncData);
    }
    CryptDestroyKey(hImportedDS); CryptDestroyKey(hPasswordKey3); CryptDestroyHash(hHash3);

    // --- ПУНКТ 10: Экспорт закрытого Key Exchange (Unencrypted) ---
    printf("\n--- Пункт 10: Экспорт закрытого ключа KeyX (Unencrypted) ---\n");
    if (CryptExportKey(hKeyX, 0, PRIVATEKEYBLOB, 0, NULL, &dwBlobLen)) {
        pbKeyBlob = (BYTE*)malloc(dwBlobLen);
        CryptExportKey(hKeyX, 0, PRIVATEKEYBLOB, 0, pbKeyBlob, &dwBlobLen);
        SaveFile("KeyX Private Unencrypted.bin", pbKeyBlob, dwBlobLen);
        free(pbKeyBlob);
        printf("Файл 'KeyX Private Unencrypted.bin' создан.\n");
    }

    // --- ПУНКТ 11: Импорт закрытого Key Exchange в Container3 ---
    printf("\n--- Пункт 11: Импорт закрытого KeyX в Container3 ---\n");
    DWORD dwKeyXPrivLen;
    BYTE* pbKeyXPrivData = LoadFile("KeyX Private Unencrypted.bin", &dwKeyXPrivLen);
    if (pbKeyXPrivData) {
        HCRYPTKEY hImportedKeyX = 0;
        // Импортируем нешифрованный закрытый ключ (hPubKey = 0)
        if (CryptImportKey(hProv3, pbKeyXPrivData, dwKeyXPrivLen, 0, 0, &hImportedKeyX)) {
            printf("Успех: Пара KeyX импортирована в Container3.\n");
            CryptDestroyKey(hImportedKeyX);
        }
        else printf("Ошибка импорта в Container3: %x\n", GetLastError());
        free(pbKeyXPrivData);
    }

    // 
    if (hHash) CryptDestroyHash(hHash);
    if (hPasswordKey) CryptDestroyKey(hPasswordKey);
    if (hSessionFromEnc) CryptDestroyKey(hSessionFromEnc);
    if (hSessionFromPlain) CryptDestroyKey(hSessionFromPlain);
    if (hSessionKey) CryptDestroyKey(hSessionKey);
    if (hImportedPubKey) CryptDestroyKey(hImportedPubKey);
    if (hKeyDS) CryptDestroyKey(hKeyDS);
    if (hKeyX) CryptDestroyKey(hKeyX);
    if (hProv1) CryptReleaseContext(hProv1, 0);
    if (hProv2) CryptReleaseContext(hProv2, 0);
    if (hProv3) CryptReleaseContext(hProv3, 0);
    if (hProvVerify) CryptReleaseContext(hProvVerify, 0);

    printf("\nВсе пункты (1-11) выполнены. Нажмите Enter для выхода.");
    getchar();
    return 0;
}