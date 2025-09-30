#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdlib.h>
#include <string.h>

// ===== 호출 규약 전환용 매크로 =====
// 빌드 옵션으로 -DSECUREA_CALLCONV=__stdcall 같은 식으로 교체 가능
#ifndef SECUREA_CALLCONV
#define SECUREA_CALLCONV __cdecl
#endif

// ====== DLL 내보낸 함수 시그니처 (네가 준 프로토타입 그대로) ======
typedef int (SECUREA_CALLCONV* PFN_GetState)(void);
typedef int (SECUREA_CALLCONV* PFN_CryptoChangeState)(void);
typedef int (SECUREA_CALLCONV* PFN_CryptoInit)(void** context, unsigned int algo, unsigned int mode, unsigned char* iv);
typedef int (SECUREA_CALLCONV* PFN_CryptoFinalize)(void** context);
typedef int (SECUREA_CALLCONV* PFN_SecureAEncrypt)(void* context, unsigned char* input, unsigned int inputLength,
    unsigned char* output, unsigned int* outputLength);
//int CryptoDecrypt(...); // 주석 처리된 항목은 생략
typedef int (SECUREA_CALLCONV* PFN_SecureACryptoHash)(void* context, unsigned char* input, unsigned int inputLength,
    unsigned char* output);
//int CryptoRandom(...); // 주석 처리된 항목은 생략
typedef int (SECUREA_CALLCONV* PFN_CryptoSetKey)(void* context, unsigned char* key, unsigned int keyLength);
typedef int (SECUREA_CALLCONV* PFN_CryptoCleanKey)(void* context);
typedef int (SECUREA_CALLCONV* PFN_SecureACryptHMac)(void* context, unsigned char* input, unsigned int inputLength,
    unsigned char* output);
typedef int (SECUREA_CALLCONV* PFN_SecureAHMacVerify)(void* context, unsigned char* input, unsigned int inputLength,
    unsigned char* macValue, unsigned int macValueLength);
//int CryptoRSAEncrypt(...);
//int CryptoRSADecrypt(...);
typedef int (SECUREA_CALLCONV* PFN_SecureACoreFunctionTest)(void);
typedef int (SECUREA_CALLCONV* PFN_SecureAIntegrityTest)(void);
typedef int (SECUREA_CALLCONV* PFN_CryptoGetLastErrorCode)(void);
typedef int (SECUREA_CALLCONV* PFN_SecureATestFunc)(void);


// ===== 유틸 =====
static void hexdump(const char* title, const unsigned char* buf, unsigned int len) {
    if (title) printf("%s (len=%u):\n", title, len);
    for (unsigned int i = 0; i < len; ++i) {
        printf("%02X", buf[i]);
        if ((i + 1) % 16 == 0) printf("\n");
        else printf(" ");
    }
    if (len % 16 != 0) printf("\n");
}

static void die_last_error(const char* msg) {
    DWORD e = GetLastError();
    LPVOID p = NULL;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM | FORMAT_MESSAGE_IGNORE_INSERTS,
        NULL, e, MAKELANGID(LANG_NEUTRAL, SUBLANG_DEFAULT), (LPSTR)&p, 0, NULL);
    fprintf(stderr, "[FATAL] %s (GetLastError=%lu: %s)\n", msg, (unsigned long)e, p ? (char*)p : "(no msg)");
    if (p) LocalFree(p);
    ExitProcess(1);
}

static FARPROC must_get(HMODULE h, const char* name) {
    FARPROC p = GetProcAddress(h, name);
    if (!p) {
        char buf[256];
        snprintf(buf, sizeof(buf), "GetProcAddress failed for symbol '%s'", name);
        die_last_error(buf);
    }
    return p;
}

static void log_rc(const char* name, int rc, PFN_CryptoGetLastErrorCode geterr) {
    if (rc == 0) {
        printf("[OK] %s -> rc=%d\n", name, rc);
    }
    else {
        int last = geterr ? geterr() : -1;
        printf("[!!] %s -> rc=%d (CryptoGetLastErrorCode=%d)\n", name, rc, last);
    }
}

int main(int argc, char** argv) {
    // 기본 DLL 경로
    char default_path[MAX_PATH] = "..\\..\\..\\securea_kcmvp\\securea_kcmvp\\x64\\Debug\\securea_kcmvp.dll";
    const char* dll_path = (argc >= 2) ? argv[1] : default_path;

    printf("[*] Loading DLL: %s\n", dll_path);
    HMODULE h = LoadLibraryA(dll_path);
    if (!h) die_last_error("LoadLibraryA failed"); else printf("dll load sucess!");

    // ===== 심볼 바인딩 =====
    PFN_GetState               GetState = (PFN_GetState)must_get(h, "GetState");
    PFN_CryptoChangeState      CryptoChangeState = (PFN_CryptoChangeState)must_get(h, "CryptoChangeState");
    PFN_CryptoInit             CryptoInit = (PFN_CryptoInit)must_get(h, "CryptoInit");
    PFN_CryptoFinalize         CryptoFinalize = (PFN_CryptoFinalize)must_get(h, "CryptoFinalize");
    PFN_SecureAEncrypt         SecureAEncrypt = (PFN_SecureAEncrypt)must_get(h, "SecureAEncrypt");
    PFN_SecureACryptoHash      SecureACryptoHash = (PFN_SecureACryptoHash)must_get(h, "SecureACryptoHash");
    PFN_CryptoSetKey           CryptoSetKey = (PFN_CryptoSetKey)must_get(h, "CryptoSetKey");
    PFN_CryptoCleanKey         CryptoCleanKey = (PFN_CryptoCleanKey)must_get(h, "CryptoCleanKey");
    //PFN_SecureACryptHMac       SecureACryptHMac = (PFN_SecureACryptHMac)must_get(h, "SecureACryptHMac");
    //PFN_SecureAHMacVerify      SecureAHMacVerify = (PFN_SecureAHMacVerify)must_get(h, "SecureAHMacVerify");
    //PFN_SecureACoreFunctionTest SecureACoreFunctionTest = (PFN_SecureACoreFunctionTest)must_get(h, "SecureACoreFunctionTest");
    //PFN_SecureAIntegrityTest   SecureAIntegrityTest = (PFN_SecureAIntegrityTest)must_get(h, "SecureAIntegrityTest");
    //PFN_CryptoGetLastErrorCode CryptoGetLastErrorCode = (PFN_CryptoGetLastErrorCode)must_get(h, "CryptoGetLastErrorCode");
    
    // 3-2) must_get 바인딩 (다른 심볼들과 함께)
    PFN_SecureATestFunc SecureATestFunc = (PFN_SecureATestFunc)must_get(h, "TestFunc");

    // 3-3) 호출 (LoadLibrary 이후, 원하는 위치에서)
    int rc_test = SecureATestFunc();
    printf("[*] SecureATestFunc -> rc=%d\n", rc_test);

    int result = 0;
    // ===== 사전 자기진단(PE 내장 테스트) =====
    //int rc = SecureACoreFunctionTest();
    //log_rc("SecureACoreFunctionTest", rc, CryptoGetLastErrorCode);

    //rc = SecureAIntegrityTest();
    //log_rc("SecureAIntegrityTest", rc, CryptoGetLastErrorCode);

    //// ===== 컨텍스트 초기화 =====
    void* ctx = NULL;
    unsigned int algo = 1; // 라이브러리 enum에 맞춰 조정
    unsigned int mode = 1; // 예: 1=CBC/CTR 등 라이브러리 정의
    unsigned char iv[16] = { 0 };

    result = CryptoInit(&ctx, algo, mode, iv);
    printf("[*] CryptoInit -> rc=%d, ctx=%p\n", result, ctx);
    //log_rc("CryptoInit", rc, CryptoGetLastErrorCode);

    //// 상태 체크
    //int st = GetState();
    //printf("[*] GetState -> %d\n", st);

    //// ===== 키 설정 (예: 128bit) =====
    //unsigned char key[16] = {
    //    0x11,0x22,0x33,0x44, 0x55,0x66,0x77,0x88,
    //    0x99,0xAA,0xBB,0xCC, 0xDD,0xEE,0xFF,0x00
    //};
    //rc = CryptoSetKey(ctx, key, (unsigned int)sizeof(key));
    //log_rc("CryptoSetKey", rc, CryptoGetLastErrorCode);

    //// ===== 테스트 데이터 =====
    unsigned char plaintext[16] = {
        0x11,0x11,0x11,0x11, 0xAA,0xAA,0xAA,0xAA,
        0x11,0x11,0x11,0x11, 0xBB,0xBB,0xBB,0xBB
    };
    //hexdump("[*] plaintext", plaintext, sizeof(plaintext));

    //// ===== 암호화 =====
    //unsigned char ciphertext[64] = { 0 };
    //unsigned int outLen = sizeof(ciphertext);
    //result = SecureAEncrypt(ctx, plaintext, (unsigned int)sizeof(plaintext), ciphertext, &outLen);
    //printf("[*] SecureAEncrypt -> rc=%d, outLen=%u\n", result, outLen);
    //log_rc("SecureAEncrypt", rc, CryptoGetLastErrorCode);
    //hexdump("[*] ciphertext", ciphertext, outLen);

    //// ===== 해시 (출력 길이는 라이브러리 고정값 가정: 예 32바이트) =====
    unsigned char hash_out[32] = { 0 };
    result = SecureACryptoHash(ctx, plaintext, (unsigned int)sizeof(plaintext), hash_out);
    //log_rc("SecureACryptoHash", rc, CryptoGetLastErrorCode);
	printf("result code : %d\n", result);
    hexdump("[*] hash_out", hash_out, (unsigned int)sizeof(hash_out));

    //// ===== HMAC & 검증 =====
    //unsigned char hmac_out[32] = { 0 };
    //rc = SecureACryptHMac(ctx, plaintext, (unsigned int)sizeof(plaintext), hmac_out);
    //log_rc("SecureACryptHMac", rc, CryptoGetLastErrorCode);
    //hexdump("[*] hmac_out", hmac_out, (unsigned int)sizeof(hmac_out));

    //rc = SecureAHMacVerify(ctx, plaintext, (unsigned int)sizeof(plaintext), hmac_out, (unsigned int)sizeof(hmac_out));
    //// 반환 규약(0=성공/1=성공 등)은 라이브러리 정의에 따름. 여기서는 rc 출력만.
    //log_rc("SecureAHMacVerify", rc, CryptoGetLastErrorCode);

    //// ===== 상태 전이 테스트 =====
    //int st2 = CryptoChangeState();
    //printf("[*] CryptoChangeState -> %d\n", st2);

    //// ===== 키/컨텍스트 정리 =====
    //rc = CryptoCleanKey(ctx);
    //log_rc("CryptoCleanKey", rc, CryptoGetLastErrorCode);

    //rc = CryptoFinalize(&ctx);
    //printf("[*] CryptoFinalize -> rc=%d, ctx(after)=%p\n", rc, ctx);
    //log_rc("CryptoFinalize", rc, CryptoGetLastErrorCode);

    FreeLibrary(h);
    printf("[*] Done.\n");
    return 0;
}
