#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <windows.h>
#include <wincrypt.h>
#include <locale.h>
// Подключаем библиотеку crypt32.lib
#pragma comment(lib, "crypt32.lib")
#define MY_ENCODING_TYPE (PKCS_7_ASN_ENCODING | X509_ASN_ENCODING)
#define DH_KEY_LENGTH 1024 // Длина ключа в битах
// Вспомогательная функция для записи массива байт в файл
void WriteBytesToFile(const char* filename, BYTE* pbData, DWORD cbData) {
    FILE* f = fopen(filename, "wb");
    if (f) {
        fwrite(pbData, 1, cbData, f);
        fclose(f);
        printf("Saved %s (%d bytes)\n", filename, cbData);
    }
    else {
        printf("Error opening %s for writing\n", filename);
    }
}
// Вспомогательная функция для чтения файла в буфер
// Возвращает TRUE при успехе, память под *ppbData выделяется внутри
BOOL ReadBytesFromFile(const char* filename, BYTE** ppbData, DWORD* pcbData) {
    FILE* f = fopen(filename, "rb");
    if (!f) return FALSE;
    fseek(f, 0, SEEK_END);
    *pcbData = ftell(f);
    fseek(f, 0, SEEK_SET);
    *ppbData = (BYTE*)malloc(*pcbData);
    if (!*ppbData) {
        fclose(f);
        return FALSE;
    }
    fread(*ppbData, 1, *pcbData, f);
    fclose(f);
    printf("Read %s (%d bytes)\n", filename, *pcbData);
    return TRUE;
}
void Alice_Generate() {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    BYTE* pbBlob = NULL;
    DWORD cbBlob = 0;
    printf("\n--- ALICE START ---\n");
    // 1. Получаем контекст криптопровайдера (Создаем контейнер ContA)
    if (!CryptAcquireContext(&hProv, "ContA", MS_ENH_DSS_DH_PROV, PROV_DSS_DH, 0)) {
        // Если контейнера нет, создаем его
        
    }
    // 2. Генерируем ключи (P, G генерируются автоматически, X_A внутри, Y_A вычисляется)
    // CALG_DH_SF - алгоритм Диффи-Хеллмана (Store and Forward)
    // (DH_KEY_LENGTH << 16) - задаем длину ключа в верхнем слове флагов
    if (!CryptGenKey(hProv, CALG_DH_SF, (DH_KEY_LENGTH << 16) | CRYPT_EXPORTABLE, &hKey)) {
        printf("Error CryptGenKey: %x\n", GetLastError());
        goto Cleanup;
    }
    // 3. Экспортируем открытый ключ (BLOB), чтобы достать из него P, G и Y
    if (!CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, NULL, &cbBlob)) {
        printf("Error getting blob size: %x\n", GetLastError());
        goto Cleanup;
    }
    pbBlob = (BYTE*)malloc(cbBlob);
    if (!CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, pbBlob, &cbBlob)) {
        printf("Error ExportKey: %x\n", GetLastError());
        goto Cleanup;
    }
    // 4. Парсим BLOB. Структура в памяти:
    // [PUBLICKEYSTRUC] + [DHPUBKEY] + [P bytes] + [G bytes] + [Y bytes]
    PUBLICKEYSTRUC* pPubStruct = (PUBLICKEYSTRUC*)pbBlob;
    DHPUBKEY* pDhPub = (DHPUBKEY*)(pbBlob + sizeof(PUBLICKEYSTRUC));
    // Проверка сигнатуры
    if (pDhPub->magic != 0x31484400) { // "DH1" в ASCII (0x31484400)
        printf("Error: Not a DH public key blob\n");
        goto Cleanup;
    }
    DWORD dwKeyLenBytes = pDhPub->bitlen / 8; // Длина одного параметра (P, G или Y) в байтах
    // Указатели на данные внутри блоба
    BYTE* pP = (BYTE*)pDhPub + sizeof(DHPUBKEY);
    BYTE* pG = pP + dwKeyLenBytes;
    BYTE* pY = pG + dwKeyLenBytes;
    // 5. Сохраняем в отдельные файлы
    WriteBytesToFile("P.bin", pP, dwKeyLenBytes);
    WriteBytesToFile("G.bin", pG, dwKeyLenBytes);
    WriteBytesToFile("Y_A.bin", pY, dwKeyLenBytes);
Cleanup:
    if (pbBlob) free(pbBlob);
    if (hKey) CryptDestroyKey(hKey);
    if (hProv) CryptReleaseContext(hProv, 0);
}
void Bob_Generate() {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKey = 0;
    BYTE* pP = NULL, * pG = NULL;
    DWORD cbP = 0, cbG = 0;
    BYTE* pbOutBlob = NULL;
    DWORD cbOutBlob = 0;
    printf("\n--- BOB START ---\n");
    // 1. Создаем контекст
    if (!CryptAcquireContext(&hProv, NULL, MS_ENH_DSS_DH_PROV, PROV_DSS_DH, CRYPT_VERIFYCONTEXT)) {
        printf("Error AcquireContext Bob: %x\n", GetLastError());
        return;
    }
    // 2. Читаем P и G
    if (!ReadBytesFromFile("P.bin", &pP, &cbP) || !ReadBytesFromFile("G.bin", &pG, &cbG)) {
        printf("Error reading parameters P/G files.\n");
        goto Cleanup;
    }
    // 3. Создаем "пустой" ключ.
    // Важно: здесь мы оставляем указание длины, но используем CRYPT_PREGEN
    // ИЗМЕНЕНИЕ: Используем CALG_DH_EPHEM для Боба
    if (!CryptGenKey(hProv, CALG_DH_EPHEM, (DH_KEY_LENGTH << 16) | CRYPT_PREGEN | CRYPT_EXPORTABLE, &hKey)) {
        printf("Error CryptGenKey Bob: %x\n", GetLastError());
        goto Cleanup;
    }
    // --- ИСПРАВЛЕНИЕ: Используем CRYPT_DATA_BLOB для передачи параметров ---
    // Подготовка P
    CRYPT_DATA_BLOB P_Blob;
    P_Blob.cbData = cbP;
    P_Blob.pbData = pP;
    // Подготовка G
    CRYPT_DATA_BLOB G_Blob;
    G_Blob.cbData = cbG;
    G_Blob.pbData = pG;
    // Устанавливаем P (передаем адрес структуры BLOB, а не сырой массив)
    if (!CryptSetKeyParam(hKey, KP_P, (BYTE*)&P_Blob, 0)) {
        printf("Error setting P: %x\n", GetLastError());
        goto Cleanup;
    }
    // Устанавливаем G
    if (!CryptSetKeyParam(hKey, KP_G, (BYTE*)&G_Blob, 0)) {
        printf("Error setting G: %x\n", GetLastError());
        goto Cleanup;
    }
    // ИЗМЕНЕНИЕ: Генерируем приватный X_B и вычисляем Y_B
    if (!CryptSetKeyParam(hKey, KP_X, NULL, 0)) {
        goto Cleanup;
    }
    // -----------------------------------------------------------------------
    // 4. Экспорт Y_B
    // Сначала узнаем размер
    if (!CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, NULL, &cbOutBlob)) {
        printf("Error ExportKey Size Bob: %x\n", GetLastError());
        goto Cleanup;
    }
    pbOutBlob = (BYTE*)malloc(cbOutBlob);
    // Теперь экспортируем
    if (!CryptExportKey(hKey, 0, PUBLICKEYBLOB, 0, pbOutBlob, &cbOutBlob)) {
        printf("Error ExportKey Bob: %x\n", GetLastError());
        goto Cleanup;
    }
    // 5. Парсим BLOB, чтобы достать Y_B (он в самом конце)
    DHPUBKEY* pDhPub = (DHPUBKEY*)(pbOutBlob + sizeof(PUBLICKEYSTRUC));
    DWORD dwKeyLen = pDhPub->bitlen / 8;
    // Структура: Header + P + G + Y.
    // Нам нужно пропустить Header, P и G, чтобы найти Y.
    BYTE* pY_B = (BYTE*)pDhPub + sizeof(DHPUBKEY) + dwKeyLen + dwKeyLen;
    WriteBytesToFile("Y_B.bin", pY_B, dwKeyLen);
Cleanup:
    if (pP) free(pP);
    if (pG) free(pG);
    if (pbOutBlob) free(pbOutBlob);
    if (hKey) CryptDestroyKey(hKey);
    if (hProv) CryptReleaseContext(hProv, 0);
}
void Alice_Calculate_Session_Key() {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKeyBobPub = 0; // Дескриптор открытого ключа Боба
    HCRYPTKEY hSessionKey = 0; // Дескриптор общего сеансового ключа
    HCRYPTHASH hHash = 0;
    BYTE* pP = NULL, * pG = NULL, * pY_B = NULL;
    DWORD cbP = 0, cbG = 0, cbY_B = 0;
    BYTE* pbBlob = NULL;
    DWORD cbBlob = 0;
    BYTE* pbSessionKeyBlob = NULL;
    DWORD cbSessionKeyBlob = 0;
    BYTE pbHash[16]; // Для MD5 (16 байт)
    DWORD cbHash = 16;
    DWORD i;
    printf("\n--- ALICE CALCULATING SHARED SECRET ---\n");
    // 1. Получаем контекст Алисы (ContA), где уже лежит ее закрытый ключ X_A
    if (!CryptAcquireContext(&hProv, "ContA", MS_ENH_DSS_DH_PROV, PROV_DSS_DH, 0)) {
        printf("Error AcquireContext Alice: %x\n", GetLastError());
        return;
    }
    // 2. Читаем файлы: P, G (параметры группы) и Y_B (открытый ключ Боба)
    if (!ReadBytesFromFile("P.bin", &pP, &cbP) ||
        !ReadBytesFromFile("G.bin", &pG, &cbG) ||
        !ReadBytesFromFile("Y_B.bin", &pY_B, &cbY_B)) {
        printf("Error reading key files.\n");
        goto Cleanup;
    }
    // 3. Формируем PUBLICKEYBLOB для ключа Боба.
    // CryptoAPI не умеет импортировать просто Y. Ему нужен полный комплект: Header + P + G + Y.
    // Структура: [PUBLICKEYSTRUC] [DHPUBKEY] [P bytes] [G bytes] [Y bytes]
    cbBlob = sizeof(PUBLICKEYSTRUC) + sizeof(DHPUBKEY) + cbP + cbG + cbY_B;
    pbBlob = (BYTE*)malloc(cbBlob);
    memset(pbBlob, 0, cbBlob); // Обнуляем для безопасности
    PUBLICKEYSTRUC* pPub = (PUBLICKEYSTRUC*)pbBlob;
    pPub->bType = PUBLICKEYBLOB;
    pPub->bVersion = CUR_BLOB_VERSION;
    pPub->reserved = 0;
    // ИЗМЕНЕНИЕ: Для Боба используем CALG_DH_EPHEM напрямую
    pPub->aiKeyAlg = CALG_DH_EPHEM;
    DHPUBKEY* pDhPub = (DHPUBKEY*)(pbBlob + sizeof(PUBLICKEYSTRUC));
    pDhPub->magic = 0x31484400; // "DH1"
    pDhPub->bitlen = cbP * 8; // 1024
    // Копируем данные в правильном порядке
    BYTE* ptr = (BYTE*)(pDhPub + 1);
    memcpy(ptr, pP, cbP); ptr += cbP;
    memcpy(ptr, pG, cbG); ptr += cbG;
    memcpy(ptr, pY_B, cbY_B);
    // 4. Импортируем ключ Боба
    if (!CryptImportKey(hProv, pbBlob, cbBlob, 0, 0, &hKeyBobPub)) {
        goto Cleanup;
    }
    // 5. Вычисляем общий сеансовый ключ (k = Y_B ^ X_A mod P).
    // Функция CryptDeriveKey делает это "под капотом".
    // В качестве второго аргумента указываем алгоритм сеансового ключа (например, RC4).
    // В качестве hBaseData передаем ДЕСКРИПТОР ОТКРЫТОГО КЛЮЧА БОБА.
    if (!CryptDeriveKey(hProv, CALG_RC4, hKeyBobPub, CRYPT_EXPORTABLE, &hSessionKey)) {
        printf("Error DeriveKey (Shared Secret): %x\n", GetLastError());
        goto Cleanup;
    }
    printf("Session key derived successfully.\n");
    // 6. Вычисляем хэш от сеансового ключа.
    // Чтобы получить байты ключа, экспортируем его в PLAINTEXTKEYBLOB.
    if (!CryptExportKey(hSessionKey, 0, PLAINTEXTKEYBLOB, 0, NULL, &cbSessionKeyBlob)) {
        printf("Error Export Session Key Size: %x\n", GetLastError());
        goto Cleanup;
    }
    pbSessionKeyBlob = (BYTE*)malloc(cbSessionKeyBlob);
    if (!CryptExportKey(hSessionKey, 0, PLAINTEXTKEYBLOB, 0, pbSessionKeyBlob, &cbSessionKeyBlob)) {
        printf("Error Export Session Key: %x\n", GetLastError());
        goto Cleanup;
    }
    // Хэшируем полученные байты (пропускаем заголовок блоба, берем сами данные ключа)
    // Структура PLAINTEXTKEYBLOB: [BLOBHEADER] [DWORD keySize] [Key Data]
    DWORD keyMaterialSize = *((DWORD*)(pbSessionKeyBlob + sizeof(BLOBHEADER)));
    BYTE* pKeyMaterial = pbSessionKeyBlob + sizeof(BLOBHEADER) + sizeof(DWORD);
    // Создаем объект хэша (MD5)
    CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash);
    CryptHashData(hHash, pKeyMaterial, keyMaterialSize, 0);
    CryptGetHashParam(hHash, HP_HASHVAL, pbHash, &cbHash, 0);
    printf("Hash of Session Key: ");
    for (i = 0; i < cbHash; i++) printf("%02X", pbHash[i]);
    printf("\n");
    
Cleanup:
    if (pP) free(pP);
    if (pG) free(pG);
    if (pY_B) free(pY_B);
    if (pbBlob) free(pbBlob);
    if (pbSessionKeyBlob) free(pbSessionKeyBlob);
    if (hKeyBobPub) CryptDestroyKey(hKeyBobPub);
    if (hSessionKey) CryptDestroyKey(hSessionKey);
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
}
// НОВАЯ ФУНКЦИЯ: Для Боба (пункт 4 задачи)
void Bob_Calculate_Session_Key() {
    HCRYPTPROV hProv = 0;
    HCRYPTKEY hKeyAlicePub = 0;
    HCRYPTKEY hSessionKey = 0;
    HCRYPTHASH hHash = 0;
    BYTE* pP = NULL, * pG = NULL, * pY_A = NULL;
    DWORD cbP = 0, cbG = 0, cbY_A = 0;
    BYTE* pbBlob = NULL;
    DWORD cbBlob = 0;
    BYTE* pbSessionKeyBlob = NULL;
    DWORD cbSessionKeyBlob = 0;
    BYTE pbHash[16];
    DWORD cbHash = 16;
    DWORD i;
    printf("\n--- BOB CALCULATING SHARED SECRET ---\n");
    if (!CryptAcquireContext(&hProv, "ContB", MS_ENH_DSS_DH_PROV, PROV_DSS_DH, 0)) {
        printf("Error AcquireContext Bob: %x\n", GetLastError());
        return;
    }
    if (!ReadBytesFromFile("P.bin", &pP, &cbP) ||
        !ReadBytesFromFile("G.bin", &pG, &cbG) ||
        !ReadBytesFromFile("Y_A.bin", &pY_A, &cbY_A)) {
        printf("Error reading key files.\n");
        goto Cleanup;
    }
    cbBlob = sizeof(PUBLICKEYSTRUC) + sizeof(DHPUBKEY) + cbP + cbG + cbY_A;
    pbBlob = (BYTE*)malloc(cbBlob);
    memset(pbBlob, 0, cbBlob);
    PUBLICKEYSTRUC* pPub = (PUBLICKEYSTRUC*)pbBlob;
    pPub->bType = PUBLICKEYBLOB;
    pPub->bVersion = CUR_BLOB_VERSION;
    pPub->reserved = 0;
    // Для Алисы используем CALG_DH_SF
    pPub->aiKeyAlg = CALG_DH_SF;
    DHPUBKEY* pDhPub = (DHPUBKEY*)(pbBlob + sizeof(PUBLICKEYSTRUC));
    pDhPub->magic = 0x31484400;
    pDhPub->bitlen = cbP * 8;
    BYTE* ptr = (BYTE*)(pDhPub + 1);
    memcpy(ptr, pP, cbP); ptr += cbP;
    memcpy(ptr, pG, cbG); ptr += cbG;
    memcpy(ptr, pY_A, cbY_A);
    if (!CryptImportKey(hProv, pbBlob, cbBlob, 0, 0, &hKeyAlicePub)) {
        goto Cleanup;
    }
    if (!CryptDeriveKey(hProv, CALG_RC4, hKeyAlicePub, CRYPT_EXPORTABLE, &hSessionKey)) {
        printf("Error DeriveKey: %x\n", GetLastError());
        goto Cleanup;
    }
    printf("Session key derived successfully.\n");
    if (!CryptExportKey(hSessionKey, 0, PLAINTEXTKEYBLOB, 0, NULL, &cbSessionKeyBlob)) {
        printf("Error Export Session Key Size: %x\n", GetLastError());
        goto Cleanup;
    }
    pbSessionKeyBlob = (BYTE*)malloc(cbSessionKeyBlob);
    if (!CryptExportKey(hSessionKey, 0, PLAINTEXTKEYBLOB, 0, pbSessionKeyBlob, &cbSessionKeyBlob)) {
        printf("Error Export Session Key: %x\n", GetLastError());
        goto Cleanup;
    }
    DWORD keyMaterialSize = *((DWORD*)(pbSessionKeyBlob + sizeof(BLOBHEADER)));
    BYTE* pKeyMaterial = pbSessionKeyBlob + sizeof(BLOBHEADER) + sizeof(DWORD);
    CryptCreateHash(hProv, CALG_MD5, 0, 0, &hHash);
    CryptHashData(hHash, pKeyMaterial, keyMaterialSize, 0);
    CryptGetHashParam(hHash, HP_HASHVAL, pbHash, &cbHash, 0);
    printf("Hash of Session Key: ");
    for (i = 0; i < cbHash; i++) printf("%02X", pbHash[i]);
    printf("\n");
Cleanup:
    if (pP) free(pP);
    if (pG) free(pG);
    if (pY_A) free(pY_A);
    if (pbBlob) free(pbBlob);
    if (pbSessionKeyBlob) free(pbSessionKeyBlob);
    if (hKeyAlicePub) CryptDestroyKey(hKeyAlicePub);
    if (hSessionKey) CryptDestroyKey(hSessionKey);
    if (hHash) CryptDestroyHash(hHash);
    if (hProv) CryptReleaseContext(hProv, 0);
}
int main() {
    setlocale(LC_ALL, "Russian");
    // Шаг 1: Алиса генерирует параметры и свой ключ
    Alice_Generate();
    // "Передача файлов"...
    // Шаг 2: Боб берет параметры, генерирует свой ключ
    Bob_Generate();
    // 3. Алиса вычисляет общий ключ
    Alice_Calculate_Session_Key();
    // 4. Боб вычисляет общий ключ (Новое!)
    Bob_Calculate_Session_Key();
    printf("\nГотово.\n");
    getchar();
    return 0;
}