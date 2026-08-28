#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <wincrypt.h>
#include <locale.h>

#pragma comment(lib, "crypt32.lib")

#define KEY_CONTAINER     "CAPI6_ECP_CONTAINER"
#define PUBLIC_KEY_FILE   "public.key"
#define SIGNATURE_FILE    "signature.sig"

// Обработка ошибок
void HandleError(const char* s) {
    printf("Ошибка: %s\nКод: %x\n", s, GetLastError());
    system("pause");
    exit(1);
}

// --- ЧАСТЬ 1: ГЕНЕРАЦИЯ КЛЮЧЕЙ И ПОДПИСЬ ---
void CreateSignature(const char* targetFile) {
    HCRYPTPROV hProv;
    HCRYPTKEY hKey;
    HCRYPTHASH hHash;
    BYTE pbData[1024];
    BYTE* pbSignature = NULL;
    BYTE* pbKeyBlob = NULL;
    DWORD dwSigLen = 0, dwBlobLen = 0, count = 0;
    FILE* f;

    printf("\n>>> ЭТАП 1: Создание ключей и подписи для файла '%s'\n", targetFile);

    if (!CryptAcquireContext(&hProv, KEY_CONTAINER, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, 0)) {
        if (GetLastError() == NTE_BAD_KEYSET) {
            CryptAcquireContext(&hProv, KEY_CONTAINER, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_NEWKEYSET);
        }
        else HandleError("AcquireContext");
    }

    if (!CryptGenKey(hProv, AT_SIGNATURE, CRYPT_EXPORTABLE, &hKey)) HandleError("GenKey");

    // Экспорт открытого ключа
    CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, NULL, &dwBlobLen);
    pbKeyBlob = (BYTE*)malloc(dwBlobLen);
    CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, pbKeyBlob, &dwBlobLen);

    f = fopen(PUBLIC_KEY_FILE, "wb");
    if (!f) HandleError("Не удалось создать файл ключа.");
    fwrite(pbKeyBlob, 1, dwBlobLen, f);
    fclose(f);
    free(pbKeyBlob);

    // Хеширование
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    f = fopen(targetFile, "rb");
    if (!f) HandleError("Указанный файл не найден!");

    while ((count = (DWORD)fread(pbData, 1, sizeof(pbData), f)) > 0) {
        CryptHashData(hHash, pbData, count, 0);
    }
    fclose(f);

    // Получение размера ЭЦП (dwSigLen) и самой подписи (pbSignature)
    CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, NULL, &dwSigLen);
    pbSignature = (BYTE*)malloc(dwSigLen);
    if (!CryptSignHash(hHash, AT_SIGNATURE, NULL, 0, pbSignature, &dwSigLen)) HandleError("SignHash");

    f = fopen(SIGNATURE_FILE, "wb");
    fwrite(pbSignature, 1, dwSigLen, f);
    fclose(f);

    free(pbSignature);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hKey);
    CryptReleaseContext(hProv, 0);
    printf("[+] Файл успешно подписан.\n");
}

// --- ЧАСТЬ 2: ПРОВЕРКА ПОДПИСИ ---
void VerifySignature(const char* targetFile) {
    HCRYPTPROV hProv;
    HCRYPTKEY hPubKey;
    HCRYPTHASH hHash;
    BYTE pbData[1024];
    BYTE* pbSignature = NULL;
    BYTE* pbKeyBlob = NULL;
    DWORD dwSigLen = 0, dwBlobLen = 0, count = 0;
    FILE* f;

    printf("\n>>> ЭТАП 2: Проверка подписи файла '%s'\n", targetFile);

    CryptAcquireContext(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);

    // Импорт открытого ключа
    f = fopen(PUBLIC_KEY_FILE, "rb");
    if (!f) HandleError("Файл открытого ключа не найден.");
    fseek(f, 0, SEEK_END); dwBlobLen = ftell(f); fseek(f, 0, SEEK_SET);
    pbKeyBlob = (BYTE*)malloc(dwBlobLen);
    fread(pbKeyBlob, 1, dwBlobLen, f); fclose(f);
    CryptImportKey(hProv, pbKeyBlob, dwBlobLen, 0, 0, &hPubKey);
    free(pbKeyBlob);

    // Повторное хеширование текущего состояния файла
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);
    f = fopen(targetFile, "rb");
    if (!f) HandleError("Файл для проверки не найден.");
    while ((count = (DWORD)fread(pbData, 1, sizeof(pbData), f)) > 0) {
        CryptHashData(hHash, pbData, count, 0);
    }
    fclose(f);

    // Чтение подписи
    f = fopen(SIGNATURE_FILE, "rb");
    if (!f) HandleError("Файл подписи не найден.");
    fseek(f, 0, SEEK_END); dwSigLen = ftell(f); fseek(f, 0, SEEK_SET);
    pbSignature = (BYTE*)malloc(dwSigLen);
    fread(pbSignature, 1, dwSigLen, f); fclose(f);

    // Верификация
    if (CryptVerifySignature(hHash, pbSignature, dwSigLen, hPubKey, NULL, 0)) {
        printf("РЕЗУЛЬТАТ: Подпись ВЕРНА.\n");
    }
    else {
        printf("РЕЗУЛЬТАТ: Подпись НЕВЕРНА! Данные изменены.\n");
    }

    free(pbSignature);
    CryptDestroyHash(hHash);
    CryptDestroyKey(hPubKey);
    CryptReleaseContext(hProv, 0);
}

int main() {
    setlocale(LC_ALL, "Russian");
    SetConsoleCP(1251);
    SetConsoleOutputCP(1251);

    char fileName[256];

    printf("Введите имя файла для работы (например, document.txt): ");
    // Считываем имя файла
    scanf("%255s", fileName);

    // Создаем подпись
    CreateSignature(fileName);

    printf("\nВНИМАНИЕ: Измените файл '%s' в текстовом редакторе и сохраните.\n", fileName);
    system("pause");

    // Проверяем
    VerifySignature(fileName);

    system("pause");
    return 0;
}