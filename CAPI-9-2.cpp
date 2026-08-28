#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib") 

#define NT_SUCCESS(Status)          (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL         ((NTSTATUS)0xC0000001L)
#define READ_BUFFER_SIZE            4096 // Читаем файл блоками по 4 КБ

void __cdecl wmain(int argc, __in_ecount(argc) LPWSTR* wargv)
{
    BCRYPT_ALG_HANDLE       hAlg = NULL;
    BCRYPT_HASH_HANDLE      hHash = NULL;
    NTSTATUS                status = STATUS_UNSUCCESSFUL;
    DWORD                   cbData = 0,
        cbHash = 0,
        cbHashObject = 0;
    PBYTE                   pbHashObject = NULL;
    PBYTE                   pbHash = NULL;

    HANDLE                  hFile = INVALID_HANDLE_VALUE;
    BYTE                    pbBuffer[READ_BUFFER_SIZE];
    DWORD                   cbRead = 0;

    PBYTE                   pbKey = NULL;
    int                     cbKey = 0;

    // Проверяем наличие аргументов: путь к файлу и пароль
    if (argc < 3)
    {
        wprintf(L"Usage: %s <path_to_file> <password>\n", wargv[0]);
        return;
    }

    // 1. Конвертируем пароль (широкую строку wargv[2]) в массив байтов (UTF-8)
    cbKey = WideCharToMultiByte(CP_UTF8, 0, wargv[2], -1, NULL, 0, NULL, NULL) - 1; // -1 чтобы не брать нуль-терминатор
    if (cbKey > 0)
    {
        pbKey = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKey);
        WideCharToMultiByte(CP_UTF8, 0, wargv[2], -1, (LPSTR)pbKey, cbKey, NULL, NULL);
    }
    else
    {
        wprintf(L"**** Error: Invalid password provided.\n");
        goto Cleanup;
    }

    // 2. Открываем файл для чтения
    hFile = CreateFileW(wargv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        wprintf(L"**** Error: Cannot open file %s. Error code: %lu\n", wargv[1], GetLastError());
        goto Cleanup;
    }

    // 3. Открываем провайдер алгоритма с флагом HMAC!
    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, BCRYPT_ALG_HANDLE_HMAC_FLAG)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptOpenAlgorithmProvider\n", status);
        goto Cleanup;
    }

    // Вычисляем размер буфера для объекта хэша
    if (!NT_SUCCESS(status = BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbHashObject, sizeof(DWORD), &cbData, 0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    // Выделяем память под объект хэша
    pbHashObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHashObject);
    if (NULL == pbHashObject)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    // Узнаем длину самого хэша
    if (!NT_SUCCESS(status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    // Выделяем память под итоговый хэш
    pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
    if (NULL == pbHash)
    {
        wprintf(L"**** memory allocation failed\n");
        goto Cleanup;
    }

    // 4. Создаем хэш, ПЕРЕДАВАЯ КЛЮЧ (pbKey и cbKey)
    if (!NT_SUCCESS(status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, pbKey, cbKey, 0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptCreateHash\n", status);
        goto Cleanup;
    }

    // 5. Хэшируем данные файла (читаем блоками)
    while (ReadFile(hFile, pbBuffer, READ_BUFFER_SIZE, &cbRead, NULL))
    {
        if (cbRead == 0) // Конец файла
        {
            break;
        }

        if (!NT_SUCCESS(status = BCryptHashData(hHash, pbBuffer, cbRead, 0)))
        {
            wprintf(L"**** Error 0x%x returned by BCryptHashData\n", status);
            goto Cleanup;
        }
    }

    // 6. Завершаем хэширование
    if (!NT_SUCCESS(status = BCryptFinishHash(hHash, pbHash, cbHash, 0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptFinishHash\n", status);
        goto Cleanup;
    }

    // Выводим результат
    wprintf(L"HMAC-SHA256 of %s:\n", wargv[1]);
    for (DWORD i = 0; i < cbHash; i++)
    {
        wprintf(L"%02x", pbHash[i]);
    }
    wprintf(L"\n");

Cleanup:

    // Аккуратно освобождаем все ресурсы, включая память под ключ
    if (hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFile);
    }
    if (pbKey)
    {
        // Для безопасности хорошим тоном считается затирать ключ в памяти перед удалением
        SecureZeroMemory(pbKey, cbKey);
        HeapFree(GetProcessHeap(), 0, pbKey);
    }
    if (hAlg)
    {
        BCryptCloseAlgorithmProvider(hAlg, 0);
    }
    if (hHash)
    {
        BCryptDestroyHash(hHash);
    }
    if (pbHashObject)
    {
        HeapFree(GetProcessHeap(), 0, pbHashObject);
    }
    if (pbHash)
    {
        HeapFree(GetProcessHeap(), 0, pbHash);
    }
}
