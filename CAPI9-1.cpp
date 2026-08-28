#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>

// Директива для линковщика (для Visual Studio), чтобы не прописывать либу вручную
#pragma comment(lib, "Bcrypt.lib")

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

    // Проверяем, передан ли путь к файлу в аргументах командной строки
    if (argc < 2)
    {
        wprintf(L"Usage: %s <path_to_file>\n", wargv[0]);
        return;
    }

    // Открываем файл для чтения
    hFile = CreateFileW(wargv[1], GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_FLAG_SEQUENTIAL_SCAN, NULL);
    if (hFile == INVALID_HANDLE_VALUE)
    {
        wprintf(L"**** Error: Cannot open file %s. Error code: %lu\n", wargv[1], GetLastError());
        goto Cleanup;
    }

    // Открываем провайдер алгоритма (SHA-256)
    if (!NT_SUCCESS(status = BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0)))
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
        wprintf(L"**** Memory allocation failed for Hash Object\n");
        goto Cleanup;
    }

    // Узнаем длину самого хэша (для SHA-256 это 32 байта)
    if (!NT_SUCCESS(status = BCryptGetProperty(hAlg, BCRYPT_HASH_LENGTH, (PBYTE)&cbHash, sizeof(DWORD), &cbData, 0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptGetProperty\n", status);
        goto Cleanup;
    }

    // Выделяем память под результат (хэш)
    pbHash = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbHash);
    if (NULL == pbHash)
    {
        wprintf(L"**** Memory allocation failed for Hash\n");
        goto Cleanup;
    }

    // Создаем хэш
    if (!NT_SUCCESS(status = BCryptCreateHash(hAlg, &hHash, pbHashObject, cbHashObject, NULL, 0, 0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptCreateHash\n", status);
        goto Cleanup;
    }

    // Хэшируем данные файла (читаем блоками и передаем в CNG)
    while (ReadFile(hFile, pbBuffer, READ_BUFFER_SIZE, &cbRead, NULL))
    {
        if (cbRead == 0) // Достигли конца файла
        {
            break;
        }

        if (!NT_SUCCESS(status = BCryptHashData(hHash, pbBuffer, cbRead, 0)))
        {
            wprintf(L"**** Error 0x%x returned by BCryptHashData\n", status);
            goto Cleanup;
        }
    }

    // Завершаем процесс хэширования
    if (!NT_SUCCESS(status = BCryptFinishHash(hHash, pbHash, cbHash, 0)))
    {
        wprintf(L"**** Error 0x%x returned by BCryptFinishHash\n", status);
        goto Cleanup;
    }

    // Выводим полученный хэш на экран
    wprintf(L"SHA-256 Hash of %s:\n", wargv[1]);
    for (DWORD i = 0; i < cbHash; i++)
    {
        wprintf(L"%02x", pbHash[i]);
    }
    wprintf(L"\n");

Cleanup:

    // Очищаем ресурсы
    if (hFile != INVALID_HANDLE_VALUE)
    {
        CloseHandle(hFile);
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
