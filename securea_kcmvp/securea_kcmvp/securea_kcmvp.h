/// @file sample_kcmvp.h
/// @section intro 소개
/// - 소개 : 
/// @section Program 프로그램명
/// - 프로그램명 : KCMVP API Interface 헤더
/// - 프로그램내용 : 암호모듈의 외부 인터페이스를 정의한다.
/// @section CREATEINFO 작성정보
/// - 작성자  : 
/// - 작성일  : 
/// @date 2023-06-01
/// @section MODIFYINFO 수정정보
/// - 수정일/수정자 : 
/// - 2023-06-01/Author Name : 수정내용
/// 
#pragma once

/// @brief 암호모듈의 버전
#define	VERSION "V0.9.0"

/// @brief 암호모듈의 알고리즘을 정의한다.
#define	CRYPTO_ID_SEED			1		
#define	CRYPTO_ID_ARIA			2		
#define	CRYPTO_HASH_SHA224		3		
#define	CRYPTO_HASH_SHA256		4
#define	CRYPTO_HASH_SHA384		5
#define	CRYPTO_HASH_SHA512		6
#define	CRYPTO_HMAC_SHA256		7
#define	CRYPTO_HMAC_SHA512		8
#define	CRYPTO_RSA_OAEP_2048	9
#define	CRYPTO_RSA_PSS_2048		10
#define	CRYPTO_HMAC_DRBG		11

/// @brief 블록암호의 MODE를 정의한다.
#define CIPHER_MODE_ECB			1	
#define CIPHER_MODE_CBC			2
#define CIPHER_MODE_CFB			3
#define CIPHER_MODE_OFB			4
#define CIPHER_MODE_CTR			5



/// @brief 암호모듈의 오류코드를 정의한다.
#define EC_SUCCESS				0		/// 오류없음
#define EC_STATE				1		/// 암호모듈 상태오류
#define EC_ALGO					2		/// 알고리즘 입력값 오류(정의되지 않은 ALGO)
#define EC_MODE					3		/// MODE 입력값 오류(정의되지 않은 MODE)
#define EC_INITIALIZE_NO		4		/// 초기화 오류(암호모듈이 초기화 되지 않은 상태)
#define EC_KEY_LEN				5		/// KEY 입력값 오류(길이)
#define EC_KEY_VALUE			6		/// KEY 입력값 오류(데이터 NULL)
#define EC_INPUT_LEN			7		/// Input 데이터 입력값 오류(길이)
#define EC_INPUT_VALUE			8		/// Input 데이터 입력값 오류(데이터 NULL)
#define EC_OUTPUT_INIT			9		/// Output 데이터 입력값 오류(포인터 미할당)
#define EC_HMAC_VERIFY			10		/// HMAC 검증 오류
#define EC_PSS_VERIFY_ERROR		11		/// RSA 검증 오류
#define EC_SELFTEST_ERROR		12		/// 자가시험(핵심기능시험) 오류
#define EC_INTEGRITY_VERIFY		13		/// 자가시험(무결성시험) 오류
#define EC_DATA_NULL			14		/// 구조체 입력값 오류(NULL)

/// @brief 암호모듈의 상태를 정의한다.
#define	STATE_POWER_ON					1		/// 전원켜짐
#define	STATE_POWER_OFF					2		/// 전원꺼짐
#define	STATE_SELFTEST					3		/// 자가시험(전원인가 시험)
#define	STATE_CMVP_FINAL				4		/// 종료상태
#define	STATE_INABILITY_ERROR			5		/// 심각한 오류
#define	STATE_CMVP_READY				6		/// 검증대상 동작모드
#define	STATE_CMVP_KEY_SET				7		/// 핵심보안매개변수 주입
#define	STATE_CMVP_ERROR				8		/// 검증대상 암호운영 오류
#define	STATE_CMVP_OPERATION			9		/// 사용자
#define STATE_CMVP_CONDITION			10		/// 자가시험(조건부 시험)
#define STATE_CMVP_INIT					11		/// 시작 상태
#define STATE_CMVP_SUCCESS				12		/// 시험성공 상태

#define EXPORT_API __declspec(dllexport)

/// @struct CRYPTO_CONTEXT
/// @brief 암호모듈내에서 사용할 알고리즘, 모드, 키, 초기화벡터값을 저장하고 있는 구조체
typedef struct _CRYPTO_CONTEXT {
	unsigned int algo;				/// 알고리즘 종류
	unsigned int mode;				/// 블록알고리즘 모드
	unsigned char key[256];			/// 키 저장 변수
	unsigned int keyLen;			/// 키 길이
	unsigned char iv[16];			/// 초기벡터 저장 변수
	unsigned int ivLen;				/// 초기벡터 길이
} CRYPTO_CONTEXT;

/// @brief 인터페이스 함수 정의
EXPORT_API int GetState();
EXPORT_API int CryptoChangeState();
EXPORT_API int CryptoInit(void** context, unsigned int algo, unsigned int mode, unsigned char* iv);
EXPORT_API int CryptoFinalize(void** context);
EXPORT_API int CryptoEncrypt(void* context, unsigned char* input, unsigned int inputLength, unsigned char* output, unsigned int* outputLength);
EXPORT_API int CryptoDecrypt(void* context, unsigned char* input, unsigned int inputLength, unsigned char* output, unsigned int* outputLength);
EXPORT_API int CryptoHash(void* context, unsigned char* input, unsigned inputLength, unsigned char* output);
EXPORT_API int CryptoRandom(void* context, int requestLength, unsigned char* nonce, unsigned int nonceLength, unsigned char* personalString, unsigned int personalStringLength, unsigned char* additionalInput, unsigned int additionalInputLength, unsigned char* output);
EXPORT_API int CryptoSetKey(void* context, unsigned char* key, unsigned int keyLength);
EXPORT_API int CryptoCleanKey(void* context);
EXPORT_API int CryptoHMac(void* context, unsigned char* input, unsigned int inputLength, unsigned char* output);
EXPORT_API int CryptoHMacVerify(void* context, unsigned char* input, unsigned int inputLength, unsigned char* macValue, unsigned int macValueLength);
EXPORT_API int CryptoRSAEncrypt(void* context, unsigned char* publickey, unsigned int publickeyLength, unsigned char* exponent, unsigned int exponentLength, unsigned char* input, unsigned int inputLength, unsigned char* output, unsigned char* seed, unsigned int seedLength);
EXPORT_API int CryptoRSADecrypt(void* context, unsigned char* privatekey, unsigned int privatekeyLength, unsigned char* publickey, unsigned int publickeyLength, unsigned char* input, unsigned int inputLength, unsigned char* output, unsigned int* outputLength);
EXPORT_API int CoreFunctionTest();
EXPORT_API int IntegrityTest();
EXPORT_API int CryptoGetLastErrorCode();

//#ifdef WIN32
#ifdef __cplusplus
extern "C" {
#endif
	typedef int(*DLL_CryptoInit)(void** context, int algo, int mode, unsigned char* iv);
	typedef int(*DLL_CryptoFinalize)(void** context);
#ifdef __cplusplus
}
#endif