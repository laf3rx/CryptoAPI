// THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
// ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED TO
// THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
// PARTICULAR PURPOSE.

#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>
#include <ncrypt.h>

#pragma comment(lib, "bcrypt.lib")
#pragma comment(lib, "ncrypt.lib")

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)
#define STATUS_SUCCESS              ((NTSTATUS)0x00000000L)

// Вспомогательная функция для сохранения данных в файл
bool SaveToFile(LPCWSTR filename, PBYTE data, DWORD size)
{
    HANDLE hFile = CreateFileW(filename, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    DWORD bytesWritten = 0;
    bool result = WriteFile(hFile, data, size, &bytesWritten, NULL) && (bytesWritten == size);
    CloseHandle(hFile);
    return result;
}

// Вспомогательная функция для загрузки данных из файла
bool LoadFromFile(LPCWSTR filename, PBYTE* data, DWORD* size)
{
    HANDLE hFile = CreateFileW(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return false;

    *size = GetFileSize(hFile, NULL);
    *data = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, *size);

    if (*data == NULL) {
        CloseHandle(hFile);
        return false;
    }

    DWORD bytesRead = 0;
    bool result = ReadFile(hFile, *data, *size, &bytesRead, NULL) && (bytesRead == *size);
    CloseHandle(hFile);
    return result;
}

void PrintUsage(LPCWSTR progName)
{
    wprintf(L"Usage:\n");
    wprintf(L"  To sign:   %s sign <file_to_sign> <out_signature_file> <out_pubkey_file>\n", progName);
    wprintf(L"  To verify: %s verify <file_to_verify> <in_signature_file> <in_pubkey_file>\n", progName);
}

void __cdecl wmain(int argc, __in_ecount(argc) LPWSTR* wargv)
{
    if (argc != 5)
    {
        PrintUsage(wargv[0]);
        return;
    }

    bool isSigning = false;
    if (_wcsicmp(wargv[1], L"sign") == 0) {
        isSigning = true;
    }
    else if (_wcsicmp(wargv[1], L"verify") == 0) {
        isSigning = false;
    }
    else {
        wprintf(L"**** Error: Unknown command '%s'\n", wargv[1]);
        PrintUsage(wargv[0]);
        return;
    }

    LPCWSTR targetFile = wargv[2];
    LPCWSTR sigFile = wargv[3];
    LPCWSTR pubKeyFile = wargv[4];

    NCRYPT_PROV_HANDLE      hProv = NULL;
    NCRYPT_KEY_HANDLE       hKey = NULL;
    BCRYPT_KEY_HANDLE       hTmpKey = NULL;
    SECURITY_STATUS         secStatus = ERROR_SUCCESS;
    BCRYPT_ALG_HANDLE       hHashAlg = NULL,
        hSignAlg = NULL;
    BCRYPT_HASH_HANDLE      hHash = NULL;
    NTSTATUS                status = STATUS_UNSUCCESSFUL;

    DWORD                   cbData = 0, cbHash = 0, cbHashObject = 0;
    DWORD                   cbBlob = 0, cbSignature = 0;

    PBYTE                   pbHashObject = NULL;
    PBYTE                   pbHash = NULL,
        pbBlob = NULL,
        pbSignature = NULL;

    HANDLE                  hFile = INVALID_HANDLE_VALUE;
    BYTE                    fileBuffer[8192];
    DWORD                   bytesRead = 0;

    // 1. Инициализация криптопровайдеров и хеша (Общее для обоих режимов)
    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hHashAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0))) goto Cleanup;
    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hSignAlg, BCRYPT_ECDSA_P256_ALGORITHM, NULL, 0))) goto Cleanup;

    if (!NT_SUCCESS(status = BCryptGetProperty(hHashAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0))) goto Cleanup;
    pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
    if (!pbHashObject) goto Cleanup;

    if (!NT_SUCCESS(status = BCryptGetProperty(hHashAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0))) goto Cleanup;
    pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
    if (!pbHash) goto Cleanup;

    if (!NT_SUCCESS(status = BCryptCreateHash(hHashAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0))) goto Cleanup;

    // 2. Чтение целевого файла и вычисление хеша (Общее)
    hFile = CreateFileW(targetFile, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"**** Error: Cannot open file %s\n", targetFile);
        goto Cleanup;
    }

    wprintf(L"Hashing file: %s...\n", targetFile);
    while (ReadFile(hFile, fileBuffer, sizeof(fileBuffer), &bytesRead, NULL) && bytesRead > 0) {
        if (!NT_SUCCESS(status = BCryptHashData(hHash, fileBuffer, bytesRead, 0))) goto Cleanup;
    }
    CloseHandle(hFile);
    hFile = INVALID_HANDLE_VALUE;

    if (!NT_SUCCESS(status = BCryptFinishHash(hHash, pbHash, cbHash, 0))) goto Cleanup;

    // РЕЖИМ СОЗДАНИЯ ПОДПИСИ
    if (isSigning)
    {
        wprintf(L"Creating signature...\n");

        if (FAILED(secStatus = NCryptOpenStorageProvider(&hProv, MS_KEY_STORAGE_PROVIDER, 0))) goto Cleanup;

        // Генерируем ключ
        if (FAILED(secStatus = NCryptCreatePersistedKey(hProv, &hKey, NCRYPT_ECDSA_P256_ALGORITHM, L"my ecc file key", 0, NCRYPT_OVERWRITE_KEY_FLAG))) goto Cleanup;
        if (FAILED(secStatus = NCryptFinalizeKey(hKey, 0))) goto Cleanup;

        // Подписываем хеш
        if (FAILED(secStatus = NCryptSignHash(hKey, NULL, pbHash, cbHash, NULL, 0, &cbSignature, 0))) goto Cleanup;
        pbSignature = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbSignature);
        if (!pbSignature) goto Cleanup;
        if (FAILED(secStatus = NCryptSignHash(hKey, NULL, pbHash, cbHash, pbSignature, cbSignature, &cbSignature, 0))) goto Cleanup;

        // Экспортируем открытый ключ
        if (FAILED(secStatus = NCryptExportKey(hKey, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, NULL, 0, &cbBlob, 0))) goto Cleanup;
        pbBlob = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbBlob);
        if (!pbBlob) goto Cleanup;
        if (FAILED(secStatus = NCryptExportKey(hKey, NULL, BCRYPT_ECCPUBLIC_BLOB, NULL, pbBlob, cbBlob, &cbBlob, 0))) goto Cleanup;

        // Сохраняем на диск
        if (!SaveToFile(sigFile, pbSignature, cbSignature)) {
            wprintf(L"**** Error: Failed to save signature to %s\n", sigFile);
            goto Cleanup;
        }
        if (!SaveToFile(pubKeyFile, pbBlob, cbBlob)) {
            wprintf(L"**** Error: Failed to save public key to %s\n", pubKeyFile);
            goto Cleanup;
        }

        wprintf(L"Success! Signature and Public Key have been saved.\n");
    }

    // РЕЖИМ ПРОВЕРКИ ПОДПИСИ
    else
    {
        wprintf(L"Verifying signature...\n");

        // Загружаем файлы с диска
        if (!LoadFromFile(sigFile, &pbSignature, &cbSignature)) {
            wprintf(L"**** Error: Failed to load signature from %s\n", sigFile);
            goto Cleanup;
        }
        if (!LoadFromFile(pubKeyFile, &pbBlob, &cbBlob)) {
            wprintf(L"**** Error: Failed to load public key from %s\n", pubKeyFile);
            goto Cleanup;
        }

        // Импортируем публичный ключ
        if (!NT_SUCCESS(status = BCryptImportKeyPair(hSignAlg, NULL, BCRYPT_ECCPUBLIC_BLOB, &hTmpKey, pbBlob, cbBlob, 0))) {
            wprintf(L"**** Error 0x%x returned by BCryptImportKeyPair\n", status);
            goto Cleanup;
        }

        // Проверяем подпись
        status = BCryptVerifySignature(hTmpKey, NULL, pbHash, cbHash, pbSignature, cbSignature, 0);

        if (status == STATUS_SUCCESS) {
            wprintf(L"--------------------------------------------------\n");
            wprintf(L"[VERIFICATION SUCCESS] The file has NOT been modified.\n");
            wprintf(L"--------------------------------------------------\n");
        }
        else {
            wprintf(L"--------------------------------------------------\n");
            wprintf(L"[VERIFICATION FAILED] Error 0x%x. The file was modified or the signature is invalid!\n", status);
            wprintf(L"--------------------------------------------------\n");
        }
    }

Cleanup:

    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);
    if (hHashAlg) BCryptCloseAlgorithmProvider(hHashAlg, 0);
    if (hSignAlg) BCryptCloseAlgorithmProvider(hSignAlg, 0);
    if (hHash) BCryptDestroyHash(hHash);
    if (pbHashObject) HeapFree(GetProcessHeap(), 0, pbHashObject);
    if (pbHash) HeapFree(GetProcessHeap(), 0, pbHash);
    if (pbSignature) HeapFree(GetProcessHeap(), 0, pbSignature);
    if (pbBlob) HeapFree(GetProcessHeap(), 0, pbBlob);
    if (hTmpKey) BCryptDestroyKey(hTmpKey);
    if (hKey) NCryptDeleteKey(hKey, 0);
    if (hProv) NCryptFreeObject(hProv);
}
