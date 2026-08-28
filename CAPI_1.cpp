#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <locale.h>

#pragma comment(lib, "advapi32.lib")

int main() {
    setlocale(LC_ALL, "Russian");

    DWORD dwIndex = 0; //счётчик 
    DWORD dwType = "";
    DWORD cbName = "";
    LPWSTR pwszName; //long pointer to wide string для строки

    

    //Перечисление криптопровайдеров
    wprintf(L"1. Установленные криптопровайдеры (CSP)\n");
    wprintf(L"%-5s | %-10s | %s\n", L"№", L"Тип", L"Название провайдера");
    wprintf(L"----------------------------------------------------\n");

    // i = 0
    //wide  версия для кодировки широких типов
    while (CryptEnumProvidersW(dwIndex, NULL, 0, &dwType, NULL, &cbName)) {
        pwszName = (LPWSTR)malloc(cbName);
        if (pwszName) {
            if (CryptEnumProvidersW(dwIndex, NULL, 0, &dwType, pwszName, &cbName)) {
                wprintf(L"%-5lu | %-10lu | %ls\n", dwIndex + 1, dwType, pwszName);
            }
            free(pwszName);
        }
        dwIndex++;
    }

    wprintf(L"----------------------------------------------------\n");



    //Типы криптопровайдеров
    wprintf(L"2. Типы провайдеров\n");
    wprintf(L"%-12s | %s\n", L"Номер типа", L"Наименование типа");
    wprintf(L"----------------------------------------------------\n");

    dwIndex = 0;
    while (CryptEnumProviderTypesW(dwIndex, NULL, 0, &dwType, NULL, &cbName)) {
        pwszName = (LPWSTR)malloc(cbName);
        if (pwszName) { // != 0 
            if (CryptEnumProviderTypesW(dwIndex, NULL, 0, &dwType, pwszName, &cbName)) {
                wprintf(L"%-12lu | %ls\n", dwType, pwszName);
            }
            free(pwszName);
        }
        dwIndex++;
    }
    wprintf(L"\n");

    wprintf(L"Нажмите любую клавишу для выхода из программы.");
    getchar();
    return 0;
}