#include <windows.h>
#include <stdio.h>
#include <bcrypt.h>

#pragma comment(lib, "bcrypt.lib")

#define KEYSIZE 32
#define IVSIZE 16

typedef struct AES {
    PBYTE pPlaintext;
    DWORD dwPlaintextSize;
    PBYTE pCiphertext;
    DWORD dwCiphertextSize;
    PBYTE pkey;
    PBYTE pIV;
} AES, * PAES;

BOOL AES_Encrypt(PAES pAES);
BOOL AES_Decrypt(PAES pAES);

BOOL SimpleEncryption(PVOID pPlainTextData, DWORD sPlainTextSize, PBYTE pKey, PBYTE pIv, PVOID* pCipherTextData, DWORD* sCipherTextSize) {
    AES aes = { 0 };
    aes.pPlaintext = (PBYTE)pPlainTextData;
    aes.dwPlaintextSize = sPlainTextSize;
    aes.pkey = pKey;
    aes.pIV = pIv;

    if (!AES_Encrypt(&aes)) return FALSE;

    *pCipherTextData = aes.pCiphertext;
    *sCipherTextSize = aes.dwCiphertextSize;
    return TRUE;
}

BOOL SimpleDecryption(PVOID pCipherTextData, DWORD sCipherTextSize, PBYTE pKey, PBYTE pIv, PVOID* pPlainTextData, DWORD* sPlainTextSize) {
    AES aes = { 0 };
    aes.pCiphertext = (PBYTE)pCipherTextData;
    aes.dwCiphertextSize = sCipherTextSize;
    aes.pkey = pKey;
    aes.pIV = pIv;

    if (!AES_Decrypt(&aes)) return FALSE;

    *pPlainTextData = aes.pPlaintext;
    *sPlainTextSize = aes.dwPlaintextSize;
    return TRUE;
}

BOOL AES_Encrypt(PAES pAES) {
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKeyHandle = NULL;
    PBYTE pbKeyObject = NULL;
    DWORD cbKeyObject = 0, cbResult = 0;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return FALSE;

    status = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) return FALSE;

    status = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
    if (!BCRYPT_SUCCESS(status)) return FALSE;

    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (!pbKeyObject) return FALSE;

    status = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, pAES->pkey, KEYSIZE, 0);
    if (!BCRYPT_SUCCESS(status)) return FALSE;

    DWORD cbCipherText = 0;
    status = BCryptEncrypt(hKeyHandle, pAES->pPlaintext, pAES->dwPlaintextSize, NULL, pAES->pIV, IVSIZE, NULL, 0, &cbCipherText, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) return FALSE;

    pAES->pCiphertext = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbCipherText);
    pAES->dwCiphertextSize = cbCipherText;

    status = BCryptEncrypt(hKeyHandle, pAES->pPlaintext, pAES->dwPlaintextSize, NULL, pAES->pIV, IVSIZE, pAES->pCiphertext, cbCipherText, &cbResult, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) return FALSE;

    if (pbKeyObject) HeapFree(GetProcessHeap(), 0, pbKeyObject);
    if (hKeyHandle) BCryptDestroyKey(hKeyHandle);
    if (hAlgorithm) BCryptCloseAlgorithmProvider(hAlgorithm, 0);

    return TRUE;
}

BOOL AES_Decrypt(PAES pAES) {
    BCRYPT_ALG_HANDLE hAlgorithm = NULL;
    BCRYPT_KEY_HANDLE hKeyHandle = NULL;
    PBYTE pbKeyObject = NULL;
    DWORD cbKeyObject = 0, cbResult = 0;
    NTSTATUS status;

    status = BCryptOpenAlgorithmProvider(&hAlgorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status)) return FALSE;

    status = BCryptSetProperty(hAlgorithm, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_CBC, sizeof(BCRYPT_CHAIN_MODE_CBC), 0);
    if (!BCRYPT_SUCCESS(status)) return FALSE;

    status = BCryptGetProperty(hAlgorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&cbKeyObject, sizeof(DWORD), &cbResult, 0);
    if (!BCRYPT_SUCCESS(status)) return FALSE;

    pbKeyObject = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbKeyObject);
    if (!pbKeyObject) return FALSE;

    status = BCryptGenerateSymmetricKey(hAlgorithm, &hKeyHandle, pbKeyObject, cbKeyObject, pAES->pkey, KEYSIZE, 0);
    if (!BCRYPT_SUCCESS(status)) return FALSE;

    DWORD cbPlainText = 0;
    status = BCryptDecrypt(hKeyHandle, pAES->pCiphertext, pAES->dwCiphertextSize, NULL, pAES->pIV, IVSIZE, NULL, 0, &cbPlainText, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) return FALSE;

    PBYTE pbPlainText = (PBYTE)HeapAlloc(GetProcessHeap(), 0, cbPlainText);
    if (!pbPlainText) return FALSE;

    status = BCryptDecrypt(hKeyHandle, pAES->pCiphertext, pAES->dwCiphertextSize, NULL, pAES->pIV, IVSIZE, pbPlainText, cbPlainText, &cbResult, BCRYPT_BLOCK_PADDING);
    if (!BCRYPT_SUCCESS(status)) return FALSE;

    pAES->pPlaintext = pbPlainText;
    pAES->dwPlaintextSize = cbResult;

    if (pbKeyObject) HeapFree(GetProcessHeap(), 0, pbKeyObject);
    if (hKeyHandle) BCryptDestroyKey(hKeyHandle);
    if (hAlgorithm) BCryptCloseAlgorithmProvider(hAlgorithm, 0);

    return TRUE;
}

VOID PrintHexData(LPCSTR Name, PBYTE Data, SIZE_T Size) {

    printf("unsigned char %s[] = {", Name);

    for (int i = 0; i < Size; i++) {
        if (i % 16 == 0)
            printf("\n\t");

        if (i < Size - 1) {
            printf("0x%0.2X, ", Data[i]);
        }
        else {
            printf("0x%0.2X ", Data[i]);
        }
    }

    printf("};\n\n\n");

}

int main() {
    // ---------- GIAI ĐOẠN ENCRYPT ----------
    BYTE key[KEYSIZE], iv[IVSIZE];
    BCRYPT_ALG_HANDLE hRng;
    BCryptOpenAlgorithmProvider(&hRng, BCRYPT_RNG_ALGORITHM, NULL, 0);
    BCryptGenRandom(hRng, key, KEYSIZE, 0);
    BCryptGenRandom(hRng, iv, IVSIZE, 0);
    BCryptCloseAlgorithmProvider(hRng, 0);

    FILE* fkey = nullptr;
    fopen_s(&fkey, "key.bin", "wb");

    fwrite(key, 1, KEYSIZE, fkey);
    fwrite(iv, 1, IVSIZE, fkey);
    fclose(fkey);

    FILE* fin = nullptr;
    fopen_s(&fin, "input.bin", "rb");
    if (!fin) {
        printf("Cannot open input.bin\n");
        return 1;
    }

    fseek(fin, 0, SEEK_END);
    DWORD inputSize = ftell(fin);
    fseek(fin, 0, SEEK_SET);

    BYTE* inputData = (BYTE*)HeapAlloc(GetProcessHeap(), 0, inputSize);
    fread(inputData, 1, inputSize, fin);
    fclose(fin);


    PVOID encryptedData = NULL;
    DWORD encryptedSize = 0;

    PrintHexData("input", inputData, inputSize);

    if (!SimpleEncryption(inputData, inputSize, key, iv, &encryptedData, &encryptedSize)) {
        printf("Encryption failed.\n");
        return 1;
    }

    FILE* fout = nullptr;
    fopen_s(&fout, "encrypted.bin", "wb");

    fwrite(encryptedData, 1, encryptedSize, fout);
    fclose(fout);

    

    printf("[+] Encrypted data written to 'encrypted.bin'\n");
    printf("[+] Key and IV written to 'key.bin'\n");

    HeapFree(GetProcessHeap(), 0, inputData);
    HeapFree(GetProcessHeap(), 0, encryptedData);

    // ---------- GIAI ĐOẠN DECRYPT ----------
    BYTE keyRead[KEYSIZE], ivRead[IVSIZE];
    FILE* fk = nullptr;
    fopen_s(&fk, "key.bin", "rb");

    fread(keyRead, 1, KEYSIZE, fk);
    fread(ivRead, 1, IVSIZE, fk);
    fclose(fk);

    FILE* fencrypted = nullptr;
    fopen_s(&fencrypted, "encrypted.bin", "rb");

    fseek(fencrypted, 0, SEEK_END);
    DWORD encSize = ftell(fencrypted);
    fseek(fencrypted, 0, SEEK_SET);
    BYTE* encData = (BYTE*)HeapAlloc(GetProcessHeap(), 0, encSize);
    fread(encData, 1, encSize, fencrypted);
    fclose(fencrypted);

    PVOID decryptedData = NULL;
    DWORD decryptedSize = 0;
    if (!SimpleDecryption(encData, encSize, keyRead, ivRead, &decryptedData, &decryptedSize)) {
        printf("[-] Decryption failed.\n");
        return 1;
    }

    FILE* fdec = nullptr;
    fopen_s(&fdec, "decrypted.bin", "wb");

    fwrite(decryptedData, 1, decryptedSize, fdec);
    fclose(fdec);

    printf("[+] Decrypted data written to 'decrypted.bin'\n");

    HeapFree(GetProcessHeap(), 0, encData);
    HeapFree(GetProcessHeap(), 0, decryptedData);

    return 0;
}
