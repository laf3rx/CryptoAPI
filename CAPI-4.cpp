#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <locale.h>

#pragma comment(lib, "advapi32.lib")

// Структура для хранения данных о провайдере
typedef struct {
    WCHAR name[512];
    DWORD type;
} ProviderInfo;

// Функция перевода ANSI -> Unicode
void AnsiToWide(const char* ansiStr, LPWSTR wideStr, int size) {
    MultiByteToWideChar(CP_ACP, 0, ansiStr, -1, wideStr, size);
}

// Проверка ключей в контейнере
void check_container_keys(LPCWSTR providerName, DWORD dwProvType, LPCWSTR containerName) {
    HCRYPTPROV hSpecificProv = 0;
    HCRYPTKEY hSigKey = 0;
    HCRYPTKEY hExchKey = 0;
    BOOL hasSig = FALSE;
    BOOL hasExch = FALSE;

    // Пытаемся открыть контекст
    if (!CryptAcquireContextW(&hSpecificProv, containerName, providerName, dwProvType, 0)) {
        if (!CryptAcquireContextW(&hSpecificProv, containerName, providerName, dwProvType, CRYPT_MACHINE_KEYSET)) {
            wprintf(L"Контейнер: %-30ls | Ошибка доступа: %08x\n", containerName, GetLastError());
            return;
        }
    }

    if (CryptGetUserKey(hSpecificProv, AT_SIGNATURE, &hSigKey)) {
        hasSig = TRUE;
        CryptDestroyKey(hSigKey);
    }
    if (CryptGetUserKey(hSpecificProv, AT_KEYEXCHANGE, &hExchKey)) {
        hasExch = TRUE;
        CryptDestroyKey(hExchKey);
    }

    wprintf(L"Контейнер: %-30ls | ", containerName);
    if (hasSig && hasExch) wprintf(L"Signature + Exchange\n");
    else if (hasSig)      wprintf(L"Только Signature\n");
    else if (hasExch)     wprintf(L"Только Exchange\n");
    else                  wprintf(L"Пустой\n");

    CryptReleaseContext(hSpecificProv, 0);
}

int main() {
    setlocale(LC_ALL, "Russian");
    SetConsoleCP(1251);
    SetConsoleOutputCP(1251);

    ProviderInfo providers[30];
    DWORD dwIndex = 0;
    DWORD dwType;
    DWORD cbName;
    DWORD provCount = 0;

    wprintf(L"Список доступных криптопровайдеров:\n");
    wprintf(L"----------------------------------------------------------------------\n");

    // 1. Перечисление провайдеров
    while (CryptEnumProvidersW(dwIndex, NULL, 0, &dwType, NULL, &cbName)) {
        LPWSTR pszName = (LPWSTR)malloc(cbName);
        if (pszName) {
            if (CryptEnumProvidersW(dwIndex, NULL, 0, &dwType, pszName, &cbName)) {
                wcscpy_s(providers[provCount].name, 512, pszName);
                providers[provCount].type = dwType;
                wprintf(L"[%d] Тип: %-3d | Имя: %ls\n", provCount, dwType, pszName);
                provCount++;
            }
            free(pszName);
        }
        dwIndex++;
        if (provCount >= 30) break;
    }

    if (provCount == 0) {
        wprintf(L"Провайдеры не найдены.\n");
        return 1;
    }

    // 2. Выбор пользователя
    int choice;
    wprintf(L"----------------------------------------------------------------------\n");
    wprintf(L"Выберите номер провайдера (0-%d): ", provCount - 1);
    if (scanf("%d", &choice) != 1 || choice < 0 || choice >= (int)provCount) {
        wprintf(L"Неверный ввод.\n");
        return 1;
    }

    wprintf(L"\nАнализ провайдера: %ls\n", providers[choice].name);



    // 3. Открываем контекст провайдера для перечисления контейнеров
    HCRYPTPROV hProv = 0;
    if (!CryptAcquireContextW(&hProv, NULL, providers[choice].name, providers[choice].type, CRYPT_VERIFYCONTEXT)) {
        wprintf(L"Ошибка входа в провайдер: %08x\n", GetLastError());
        system("pause");
        return 1;
    }

    char szContainerName[512];
    WCHAR wszContainerName[512];
    DWORD cbContainerName;
    DWORD dwFlags = CRYPT_FIRST;
    BOOL found = FALSE;

    wprintf(L"----------------------------------------------------------------------\n");

    // 4. Перечисление контейнеров
    cbContainerName = sizeof(szContainerName);
    while (CryptGetProvParam(hProv, PP_ENUMCONTAINERS, (BYTE*)szContainerName, &cbContainerName, dwFlags)) {
        found = TRUE;
        AnsiToWide(szContainerName, wszContainerName, 512);
        check_container_keys(providers[choice].name, providers[choice].type, wszContainerName);

        dwFlags = CRYPT_NEXT;
        cbContainerName = sizeof(szContainerName);
    }

    if (!found) {
        wprintf(L"Контейнеры не найдены.\n");
    }

    if (hProv) CryptReleaseContext(hProv, 0);
    wprintf(L"----------------------------------------------------------------------\n");
    system("pause");
    return 0;
}