#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <locale.h>

#pragma comment(lib, "advapi32.lib")

#define BUFFER_SIZE 4096

int main() {
    setlocale(LC_ALL, "Russian");

    HCRYPTPROV hProv = 0;
    HCRYPTHASH hHash = 0;
    HANDLE hFile = INVALID_HANDLE_VALUE;
    BYTE rgbFile[BUFFER_SIZE];
    DWORD cbRead = 0;
    BYTE rgbHash[64]; // Буфер для хеша (SHA-256 — 32 байта, берем с запасом)
    DWORD cbHash = 0;

    // 1. Указываем путь к 
    LPCWSTR filename = L"CryptoAPI.pptx";

    wprintf(L"Вычисление SHA-256 для файла: %ls\n", filename);

    // 2. Открываем файл
    hFile = CreateFileW(filename, GENERIC_READ, FILE_SHARE_READ, NULL,
        OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);

    if (hFile == INVALID_HANDLE_VALUE) {
        wprintf(L"Ошибка открытия файла. Убедитесь, что %ls существует.\n", filename);
        return 1;
    }

    // 3. Получаем контекст криптопровайдера 
    CryptAcquireContextW(&hProv, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);

    // 4. Создаем пустой объект хеша для алгоритма SHA-256
    CryptCreateHash(hProv, CALG_SHA_256, 0, 0, &hHash);

    // 5. Читаем файл по блокам и добавляем в хеш
    while (ReadFile(hFile, rgbFile, BUFFER_SIZE, &cbRead, NULL) && cbRead > 0) {
        CryptHashData(hHash, rgbFile, cbRead, 0);
    }

    // 6. Получаем размер хеша и само значение
    cbHash = sizeof(rgbHash);
    if (CryptGetHashParam(hHash, HP_HASHVAL, rgbHash, &cbHash, 0)) {
        wprintf(L"Результат (HEX): ");
        for (DWORD i = 0; i < cbHash; i++) {
            wprintf(L"%02x", rgbHash[i]);
        }
        wprintf(L"\n");
    }
    else {
        wprintf(L"Ошибка CryptGetHashParam: %d\n", GetLastError());
    }

cleanup:
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
    if (hFile != INVALID_HANDLE_VALUE) CloseHandle(hFile);

    system("pause");
    return 0;
}