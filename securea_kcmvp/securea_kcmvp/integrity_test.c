#include "integrity_test.h"
#include <string.h>
#include <stdlib.h>
#include <stdio.h>

#include "KISA_SHA256.h"  // SHA256 엔진 사용
#include "KISA_HMAC.h"  // SHA256 엔진 사용

// 예시: 고정 키. 실제 구현에선 보안 영역 혹은 TPM 등에서 가져오는 방식으로 대체
static const BYTE STATIC_MAC_KEY[32] = {
    0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80,
    0x90, 0xa0, 0xb0, 0xc0, 0xd0, 0xe0, 0xf0, 0x00,
    0x01, 0x12, 0x23, 0x34, 0x45, 0x56, 0x67, 0x78,
    0x89, 0x9a, 0xab, 0xbc, 0xcd, 0xde, 0xef, 0xff
};

const BYTE* sudo_getMacKey(size_t* keyLength) {
    if (keyLength) *keyLength = sizeof(STATIC_MAC_KEY);
    return STATIC_MAC_KEY;
}

// 예시: 실행 중인 모듈 파일 전체 내용을 읽어오는 함수
const BYTE* sudo_getModule_macData(size_t* length) {
    FILE* f = fopen("./libsecureacryptomodule.so", "rb");
    if (!f) return NULL;

    fseek(f, 0, SEEK_END);
    long len = ftell(f);
    fseek(f, 0, SEEK_SET);

    BYTE* buffer = (BYTE*)malloc(len);
    if (!buffer) {
        fclose(f);
        return NULL;
    }

    fread(buffer, 1, len, f);
    fclose(f);

    if (length) *length = len;
    return buffer;
}

// 기본 SHA256 기반 MAC or HMAC-SHA256 구현
// 7.28 To-Do
void Mac(
    BYTE* output,
    size_t outputLength,
    const BYTE* data,
    size_t dataLength,
    const BYTE* key,
    size_t keyLength,
    MAC_ALGORITHM alg
) {
    if (!output || !data || !key) return;

    if (alg == MAC_ALG_SHA256) {
        SHA256_Encrpyt(data, (UINT)dataLength, output);
    }
    else if (alg == MAC_ALG_HMAC_SHA256) {
        // HMAC Implementation
        unsigned char hmac[32];
        HMAC_SHA256(data, dataLength, key, keyLength, hmac);
    }

    return 1;
}
