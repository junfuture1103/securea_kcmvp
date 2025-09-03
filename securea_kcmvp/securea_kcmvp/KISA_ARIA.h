#ifndef _KISA_ARIA_H_
#define _KISA_ARIA_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

	typedef unsigned char Byte;
	typedef unsigned int  Word;

	/* 암호화 함수
	 * @param i: 입력 평문 (16 bytes)
	 * @param Nr: 라운드 수 (128bit → 12, 192bit → 14, 256bit → 16)
	 * @param rk: 라운드 키 (EncKeySetup으로 생성됨)
	 * @param o: 출력 암호문 (16 bytes)
	 */
	int Crypt(void* context, const Byte* i, int Nr, const Byte* rk, Byte* o);

	/* 암호화 라운드 키 생성 함수
	 * @param mk: 마스터 키
	 * @param rk: 생성된 라운드 키를 저장할 버퍼 (16 * 17 bytes 이상)
	 * @param keyBits: 키 비트 수 (128, 192, or 256)
	 * @return 라운드 수
	 */
	int EncKeySetup(const Byte* mk, Byte* rk, int keyBits);

	/* 복호화 라운드 키 생성 함수
	 * @param mk: 마스터 키
	 * @param rk: 생성된 복호화용 라운드 키를 저장할 버퍼
	 * @param keyBits: 키 비트 수 (128, 192, or 256)
	 * @return 라운드 수
	 */
	int DecKeySetup(const Byte* mk, Byte* rk, int keyBits);

	/* 기본 테스트 함수
	 * endian 검출, 테스트 벡터 검증 및 round-trip 확인
	 */
	int ARIA_encrypt(void* context, unsigned char* input, unsigned int inputLength, unsigned char* output, unsigned int* outputLength);
	int ARIA_decrypt(const Byte* mk, int keyBits, const Byte* in, unsigned int inLen, Byte* out);

	/* 블록 출력 함수 (디버깅용) */
	void printBlock(Byte* b);
	void printBlockOfLength(Byte* b, int len);

#ifdef __cplusplus
}
#endif

#endif /* _KISA_ARIA_H_ */
