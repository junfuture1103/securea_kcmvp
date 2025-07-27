#ifndef _INTEGRITY_TEST_H_
#define _INTEGRITY_TEST_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

    typedef unsigned char BYTE;

    // 사용할 알고리즘 식별자
    typedef enum {
        MAC_ALG_SHA256 = 0,
        MAC_ALG_HMAC_SHA256 = 1
        // 필요시 확장 가능
    } MAC_ALGORITHM;

    /**
     * @brief Mac을 계산하여 출력한다.
     *
     * @param output           MAC 결과를 저장할 버퍼
     * @param outputLength     출력 MAC 길이 (보통 SHA256이면 32)
     * @param data             입력 데이터 (예: 모듈 바이너리)
     * @param dataLength       입력 데이터 길이
     * @param key              MAC 생성 키 (HMAC일 경우 필수)
     * @param keyLength        키 길이
     * @param alg              사용 알고리즘
     */
    void Mac(
        BYTE* output,
        size_t outputLength,
        const BYTE* data,
        size_t dataLength,
        const BYTE* key,
        size_t keyLength,
        MAC_ALGORITHM alg
    );

    /**
     * @brief 내부 모듈용 key를 반환
     * @return const BYTE* 키 데이터 (정적 or 보안 영역에서 복사)
     */
    const BYTE* sudo_getMacKey(size_t* keyLength);

    /**
     * @brief 현재 모듈 파일을 로드하여 전체 데이터를 반환
     * @param length 반환될 길이 저장 포인터
     * @return const BYTE* 파일 내용 포인터
     */
    const BYTE* sudo_getModule_macData(size_t* length);

#ifdef __cplusplus
}
#endif

#endif /* _INTEGRITY_TEST_H_ */
