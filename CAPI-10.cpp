#define UNICODE
#define _UNICODE

#include <tchar.h>
#include <windows.h>
#include <bcrypt.h>
#include <stdio.h> // Добавлено для корректной работы _tprintf

#pragma comment(lib, "bcrypt.lib")

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define STATUS_UNSUCCESSFUL ((NTSTATUS)0xC0000001L)

int _tmain()
{
    ULONG algCount = 0;
    BCRYPT_ALGORITHM_IDENTIFIER* pAlgList = NULL;

    // Объединяем флаги всех криптографических операций с помощью побитового ИЛИ
    ULONG dwAlgOperations = BCRYPT_CIPHER_OPERATION |
        BCRYPT_HASH_OPERATION |
        BCRYPT_SIGNATURE_OPERATION |
        BCRYPT_ASYMMETRIC_ENCRYPTION_OPERATION |
        BCRYPT_SECRET_AGREEMENT_OPERATION |
        BCRYPT_RNG_OPERATION;

    // Передаем объединенные флаги первым параметром
    NTSTATUS result = BCryptEnumAlgorithms(
        dwAlgOperations,
        &algCount,
        &pAlgList,
        0);

    if (!NT_SUCCESS(result))
    {
        _tprintf(TEXT("Ошибка: BCryptEnumAlgorithms завершилась с кодом 0x%08x\n"), result);
        return 1;
    }

    _tprintf(TEXT("Найдено алгоритмов: %lu\n"), algCount);
    _tprintf(TEXT("----------------------------------------\n"));

    for (int i = 0; i < algCount; i++)
    {
        _tprintf(TEXT("Algorithm: %ls\n"), pAlgList[i].pszName);
    }

    // Освобождаем память, выделенную функцией
    BCryptFreeBuffer(pAlgList);

    return 0;
}
