#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <locale.h>

#pragma comment(lib, "advapi32.lib")


//структура для хранения данных о провайдере
typedef struct {
    WCHAR name[512];
    DWORD type;
} CSP_INFO;

const wchar_t* GetAlgClass(ALG_ID id);
const wchar_t* GetAlgType(ALG_ID id);
void PrintProtocols(DWORD dwProtocols);


int main() {
    setlocale(LC_ALL, "Russian");

   HCRYPTPROV hProv = 0;
   // LPCWSTR pszProvider = MS_ENH_RSA_AES_PROV; // Выбранный провайдер
   // DWORD dwType = PROV_RSA_AES;
    CSP_INFO providers[50]; // Массив для хранения списка (до 50 штук!!!)
    DWORD dwIndex = 0;
    DWORD dwType, cbName;

    wprintf(L"--- Шаг 1: Получение списка провайдеров ---\n");

    while (CryptEnumProvidersW(dwIndex, NULL, 0, &dwType, NULL, &cbName) && dwIndex < 50) {
        if (CryptEnumProvidersW(dwIndex, NULL, 0, &dwType, providers[dwIndex].name, &cbName)) {
            providers[dwIndex].type = dwType;
            wprintf(L"%d. [%-3lu] %ls\n", dwIndex + 1, dwType, providers[dwIndex].name);
        }
        dwIndex++;
    }

    int choice;
    wprintf(L"\nВведите номер провайдера для анализа (1-%d): ", dwIndex);
    if (wscanf_s(L"%d", &choice) != 1 || choice < 1 || choice >(int)dwIndex) {
        wprintf(L"Неверный выбор.\n");
        return 1;
    }

    // Данные выбранного провайдера
    LPCWSTR selectedName = providers[choice - 1].name;
    DWORD selectedType = providers[choice - 1].type;

    wprintf(L"\n--- Шаг 2: Анализ %ls ---\n", selectedName);

    wprintf(L"Инспекция провайдера: %ls\n", selectedName);
    wprintf(L"--------------------------------------------------\n");

    // 1. Инициализация контекста
    CryptAcquireContextW(&hProv, NULL, selectedName, dwType, CRYPT_VERIFYCONTEXT);

    // 2. Тип реализации (PP_IMPTYPE)
    DWORD dwImplType;
    DWORD cbData = sizeof(DWORD);
    if (CryptGetProvParam(hProv, PP_IMPTYPE, (BYTE*)&dwImplType, &cbData, 0)) {
        wprintf(L"Тип реализации: ");
        if (dwImplType & CRYPT_IMPL_HARDWARE) wprintf(L"Аппаратный\n");
        else if (dwImplType & CRYPT_IMPL_SOFTWARE) wprintf(L"Программный\n");
        else if (dwImplType & CRYPT_IMPL_REMOVABLE) wprintf(L"Съемный (Smart-card)\n");
        else wprintf(L"Смешанный/Неизвестный\n");
    }

    // 3. Версия (PP_VERSION)
    DWORD dwVersion;
    cbData = sizeof(DWORD);
    if (CryptGetProvParam(hProv, PP_VERSION, (BYTE*)&dwVersion, &cbData, 0)) {
        wprintf(L"Версия: %d.%d\n", (dwVersion >> 8) & 0xFF, dwVersion & 0xFF);
    }

    // 4. Шаги изменения длины ключей
    DWORD dwStep;
    cbData = sizeof(DWORD);
    if (CryptGetProvParam(hProv, PP_SIG_KEYSIZE_INC, (BYTE*)&dwStep, &cbData, 0))
        wprintf(L"Шаг изменения ключа подписи: %lu бит\n", dwStep);
    if (CryptGetProvParam(hProv, PP_KEYX_KEYSIZE_INC, (BYTE*)&dwStep, &cbData, 0))
        wprintf(L"Шаг изменения ключа обмена: %lu бит\n", dwStep);

    wprintf(L"\n--- Список алгоритмов ---\n");

    // 5. Перечисление алгоритмов (PP_ENUMALGS_EX)
    PROV_ENUMALGS_EX algInfo;
    cbData = sizeof(algInfo);
    DWORD dwFlags = CRYPT_FIRST;

    while (CryptGetProvParam(hProv, PP_ENUMALGS_EX, (BYTE*)&algInfo, &cbData, dwFlags)) {
        dwFlags = 0; // Для последующих вызовов

        wprintf(L"\n[ID: 0x%08X] - %hs\n", algInfo.aiAlgid, algInfo.szName);
        wprintf(L"  Полное имя: %hs\n", algInfo.szLongName);
        wprintf(L"  Класс:      %ls\n", GetAlgClass(algInfo.aiAlgid));
        wprintf(L"  Тип:       %ls\n", GetAlgType(algInfo.aiAlgid));

        if (GET_ALG_CLASS(algInfo.aiAlgid) != ALG_CLASS_HASH) {
            wprintf(L"  Длина ключа: деф. %lu, мин. %lu, макс. %lu\n",
                algInfo.dwDefaultLen, algInfo.dwMinLen, algInfo.dwMaxLen);
        }

        if (algInfo.dwProtocols != 0) {
            wprintf(L"  Протоколы:  ");
            PrintProtocols(algInfo.dwProtocols);
            wprintf(L"\n");
        }
    }

    if (hProv) CryptReleaseContext(hProv, 0);
    system("pause");
    return 0;
}

// Определение класса алгоритма через макросы WinCrypt.h
const wchar_t* GetAlgClass(ALG_ID id) {
    switch (GET_ALG_CLASS(id)) {
    case ALG_CLASS_DATA_ENCRYPT: return L"Шифрование данных";
    case ALG_CLASS_HASH:         return L"Хеширование";
    case ALG_CLASS_KEY_EXCHANGE: return L"Обмен ключами";
    case ALG_CLASS_SIGNATURE:    return L"Цифровая подпись";
    default:                     return L"Другое";
    }
}

// Определение типа (Блочный/Потоковый или RSA/DSS)
const wchar_t* GetAlgType(ALG_ID id) {
    switch (GET_ALG_TYPE(id)) {
    case ALG_TYPE_BLOCK:  return L"Блочный шифр";
    case ALG_TYPE_STREAM: return L"Потоковый шифр";
    case ALG_TYPE_RSA:    return L"Схема RSA";
    case ALG_TYPE_DSS:    return L"Схема DSS";
    default:              return L"N/A";
    }
}

// Расшифровка битовой маски протоколов
void PrintProtocols(DWORD dwProtocols) {
    if (dwProtocols & CRYPT_FLAG_SSL2)  wprintf(L"SSL v2; ");
    if (dwProtocols & CRYPT_FLAG_SSL3)  wprintf(L"SSL v3; ");
    if (dwProtocols & CRYPT_FLAG_TLS1)  wprintf(L"TLS v1; ");
    if (dwProtocols & CRYPT_FLAG_PCT1)  wprintf(L"PCT v1; ");
    if (dwProtocols & CRYPT_FLAG_IPSEC) wprintf(L"IPSec; ");
}