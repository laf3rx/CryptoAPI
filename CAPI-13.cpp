#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

#define NT_SUCCESS(Status) (((NTSTATUS)(Status)) >= 0)
#define MAX_FILES 100

int main()
{

    BCRYPT_ALG_HANDLE hKdfAlg = NULL;
    BCRYPT_KEY_HANDLE hKdfKey = NULL;
    BCRYPT_ALG_HANDLE hAesAlg = NULL;
    BCRYPT_KEY_HANDLE hAesKey = NULL;

    NTSTATUS status = 0;
    DWORD cbResult = 0;

    PBYTE pbSecret = NULL;
    DWORD cbSecret = 16;
    BYTE rgbSalt[] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08 };
    ULONGLONG cIterations = 10000;

    PBYTE pbKeyObject = NULL;
    DWORD cbKeyObject = 0;
    PBYTE pbIV = NULL;
    DWORD cbBlockLen = 0;
    BYTE rgbIV[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
                     0x08, 0x09, 0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x0F };

    WIN32_FIND_DATAW findData;
    HANDLE hFind = INVALID_HANDLE_VALUE;
    WCHAR fileList[MAX_FILES][MAX_PATH];
    int fileCount = 0;
    int selection = 0;
    int opMode = 0; // 1 - Encrypt, 2 - Decrypt

    FILE* inFile = NULL;
    FILE* outFile = NULL;
    PBYTE pbInputData = NULL;
    DWORD cbInputData = 0;
    PBYTE pbOutputData = NULL;
    DWORD cbOutputData = 0;

    WCHAR pwszPassword[256] = { 0 };
    const WCHAR* wszEncFile = L"encrypted.bin";
    const WCHAR* wszDecFile = L"decrypted.txt";


    wprintf(L"Select operation:\n[1] Encrypt file\n[2] Decrypt file\n> ");
    if (wscanf_s(L"%d", &opMode) <= 0 || (opMode != 1 && opMode != 2)) return 1;

    wprintf(L"\nSearching for files...\n");
    hFind = FindFirstFileW(L"*", &findData);
    if (hFind == INVALID_HANDLE_VALUE) return 1;

    do {
        if (!(findData.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
            wcscpy_s(fileList[fileCount], MAX_PATH, findData.cFileName);
            wprintf(L"[%d] %s\n", fileCount + 1, fileList[fileCount]);
            fileCount++;
        }
    } while (FindNextFileW(hFind, &findData) != 0 && fileCount < MAX_FILES);
    FindClose(hFind);

    if (fileCount == 0) return 0;

    wprintf(L"\nSelect file number: ");
    if (wscanf_s(L"%d", &selection) <= 0 || selection < 1 || selection > fileCount) return 1;

    wprintf(L"Enter password: ");
    wscanf_s(L"%255s", pwszPassword, (unsigned)_countof(pwszPassword));

  
    status = BCryptOpenAlgorithmProvider(&hKdfAlg, BCRYPT_PBKDF2_ALGORITHM, NULL, 0);
  

    pbSecret = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbSecret);


    status = BCryptGenerateSymmetricKey(hKdfAlg, &hKdfKey, NULL, 0, (PBYTE)pwszPassword, (DWORD)wcslen(pwszPassword) * sizeof(WCHAR), 0);
 

    BCryptBuffer bufArray[3];
    bufArray[0] = { (DWORD)((wcslen(BCRYPT_SHA256_ALGORITHM) + 1) * sizeof(WCHAR)), KDF_HASH_ALGORITHM, (PVOID)BCRYPT_SHA256_ALGORITHM };
    bufArray[1] = { sizeof(rgbSalt), KDF_SALT, (PVOID)rgbSalt };
    bufArray[2] = { sizeof(cIterations), KDF_ITERATION_COUNT, (PVOID)&cIterations };
    BCryptBufferDesc params = { BCRYPTBUFFER_VERSION, 3, bufArray };
    status = BCryptKeyDerivation(hKdfKey, &params, pbSecret, cbSecret, &cbResult, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;


    status = BCryptOpenAlgorithmProvider(&hAesAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    status = BCryptSetProperty(hAesAlg, BCRYPT_CHAINING_MODE, (PBYTE)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    status = BCryptGetProperty(hAesAlg, BCRYPT_OBJECT_LENGTH, (PBYTE)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (!pbKeyObject) goto Cleanup;

    status = BCryptGetProperty(hAesAlg, BCRYPT_BLOCK_LENGTH, (PBYTE)&cbBlockLen, sizeof(DWORD), &cbResult, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    pbIV = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbBlockLen);
    if (!pbIV) goto Cleanup;
    memcpy(pbIV, rgbIV, cbBlockLen);
    status = BCryptGenerateSymmetricKey(hAesAlg, &hAesKey, pbKeyObject, cbKeyObject, pbSecret, cbSecret, 0);
    if (!NT_SUCCESS(status)) goto Cleanup;

    if (_wfopen_s(&inFile, fileList[selection - 1], L"rb") != 0) goto Cleanup;
    fseek(inFile, 0, SEEK_END);
    cbInputData = ftell(inFile);
    fseek(inFile, 0, SEEK_SET);

    pbInputData = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbInputData);
    if (pbInputData) fread(pbInputData, 1, cbInputData, inFile);
    fclose(inFile);
    inFile = NULL;

    
    if (opMode == 1) {
        status = BCryptEncrypt(hAesKey, pbInputData, cbInputData, NULL, pbIV, cbBlockLen, NULL, 0, &cbOutputData, BCRYPT_BLOCK_PADDING);
        if (!NT_SUCCESS(status)) goto Cleanup;

        pbOutputData = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbOutputData);
        if (!pbOutputData) goto Cleanup;

        status = BCryptEncrypt(hAesKey, pbInputData, cbInputData, NULL, pbIV, cbBlockLen, pbOutputData, cbOutputData, &cbResult, BCRYPT_BLOCK_PADDING);
        if (!NT_SUCCESS(status)) goto Cleanup;

        if (_wfopen_s(&outFile, wszEncFile, L"wb") == 0) {
            fwrite(pbOutputData, 1, cbResult, outFile);
            fclose(outFile);
            outFile = NULL;
            wprintf(L"[+] Encrypted successfully to %s\n", wszEncFile);
        }
    }
    else {
        status = BCryptDecrypt(hAesKey, pbInputData, cbInputData, NULL, pbIV, cbBlockLen, NULL, 0, &cbOutputData, BCRYPT_BLOCK_PADDING);
        if (!NT_SUCCESS(status)) goto Cleanup;

        pbOutputData = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbOutputData);
        if (!pbOutputData) goto Cleanup;

        status = BCryptDecrypt(hAesKey, pbInputData, cbInputData, NULL, pbIV, cbBlockLen, pbOutputData, cbOutputData, &cbResult, BCRYPT_BLOCK_PADDING);
        if (!NT_SUCCESS(status)) goto Cleanup;

        if (_wfopen_s(&outFile, wszDecFile, L"wb") == 0) {
            fwrite(pbOutputData, 1, cbResult, outFile);
            fclose(outFile);
            outFile = NULL;
            wprintf(L"[+] Decrypted successfully to %s\n", wszDecFile);
        }
    }

Cleanup:
    if (!NT_SUCCESS(status)) wprintf(L"**** Error: 0x%08x\n", status);

    if (hKdfAlg) BCryptCloseAlgorithmProvider(hKdfAlg, 0);
    if (hKdfKey) BCryptDestroyKey(hKdfKey);
    if (hAesAlg) BCryptCloseAlgorithmProvider(hAesAlg, 0);
    if (hAesKey) BCryptDestroyKey(hAesKey);
    if (pbSecret) HeapFree(GetProcessHeap(), 0, pbSecret);
    if (pbKeyObject) HeapFree(GetProcessHeap(), 0, pbKeyObject);
    if (pbIV) HeapFree(GetProcessHeap(), 0, pbIV);
    if (pbInputData) HeapFree(GetProcessHeap(), 0, pbInputData);
    if (pbOutputData) HeapFree(GetProcessHeap(), 0, pbOutputData);
    if (inFile) fclose(inFile);
    if (outFile) fclose(outFile);

    return 0;
}
