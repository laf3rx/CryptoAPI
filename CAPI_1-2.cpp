#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <locale.h>

#pragma comment(lib, "advapi32.lib")

int main() {
    // Настраиваем вывод русского языка в консоли
    setlocale(LC_ALL, "Russian");

    DWORD dwIndex = 0;
    DWORD dwType;
    DWORD cbName;
    LPWSTR pwszTypeName; // Буфер для названия типа

    wprintf(L"Список зарегистрированных типов криптопровайдеров:\n");
    wprintf(L"--------------------------------------------------------\n");

    // Цикл перечисления типов
    // CryptEnumProviderTypesW работает аналогично: сначала узнаем размер, потом получаем данные
    while (CryptEnumProviderTypesW(dwIndex, NULL, 0, &dwType, NULL, &cbName)) {

        // Выделяем память под название типа
        pwszTypeName = (LPWSTR)malloc(cbName);
        if (NULL == pwszTypeName) {
            wprintf(L"Ошибка выделения памяти.\n");
            break;
        }

        // Получаем идентификатор типа (dwType) и его текстовое описание (pwszTypeName)
        if (CryptEnumProviderTypesW(dwIndex, NULL, 0, &dwType, pwszTypeName, &cbName)) {
            wprintf(L"Номер типа: %-3lu | Название: %ls\n", dwType, pwszTypeName);
        }
        else {
            wprintf(L"Ошибка при получении данных о типе.\n");
        }

        // Очистка
        free(pwszTypeName);
        dwIndex++;
    }

    // Проверка на завершение списка
    if (GetLastError() != ERROR_NO_MORE_ITEMS) {
        wprintf(L"Ошибка: %lu\n", GetLastError());
    }

    wprintf(L"--------------------------------------------------------\n");
    wprintf(L"Перечисление завершено.\n");

    system("pause");
    return 0;
}