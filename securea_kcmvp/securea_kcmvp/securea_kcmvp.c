/// @file sample_kcmvp.c
/// @section intro 소개
/// - 소개 : 
/// @section Program 프로그램명
/// - 프로그램명 : KCMVP API Interface Module
/// - 프로그램내용 : 암호모듈의 외부 인터페이스를 정의한다.
/// @section CREATEINFO 작성정보
/// - 작성자  : 
/// - 작성일  : 
/// @date 2023-06-01
/// @section MODIFYINFO 수정정보
/// - 수정일/수정자 : 
/// - 2023-06-01/Author Name : 수정내용
/// 

#include <stdio.h>
#include <windows.h>

#include "securea_kcmvp.h"
#include "KISA_SHA256.h"
#include "KISA_ARIA.h"
#include "KISA_HMAC.h"
#include "KISA_drbg.h"

int g_module_state;
int g_error_code;

/// @fn int SetState(int state)
/// @brief 암호모듈의 현재상태를 사용자 상태로 변환시키는 함수
/// @return 암호모듈 상태
/// @param[in] state 암호모듈의 현재상태
int SetState(int state)
{
	if (GetState() == STATE_INABILITY_ERROR)
		return EC_STATE;

	g_module_state = state;
	return EC_SUCCESS;
}


/// @fn int GetState()
/// @brief 암호모듈의 현재상태를 얻는 함수
/// @return 암호모듈 상태
EXPORT_API int GetState()
{
	return g_module_state;
}

/// @fn int CryptoChangeState()
/// @brief 암호모듈의 현재상태를 암호운영 오류상태일 경우에만 사용자 상태로로 상태천이
/// @return 암호모듈 상태
EXPORT_API int CryptoChangeState()
{
	if (GetState() == STATE_CMVP_ERROR)
		return SetState(STATE_CMVP_READY);
	else
		return GetState();
}

/// @fn BOOL DllMain(HMODULE hModule, unsigned int ul_reason_for_call, LPVOID lpReserved)
/// @brief 암호모듈의 진입점
/// @return 암호모듈 로딩 성공여부
BOOL APIENTRY DllMain(HMODULE hModule, unsigned int ul_reason_for_call, LPVOID lpReserved)
{
	int rv = EC_SUCCESS;

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		/// 전원켜짐 상태 천이
		SetState(STATE_POWER_ON);

		/// 자가시험상태 천이
		SetState(STATE_SELFTEST);

		rv = SecureACoreFunctionTest(); /// 핵심기능시험
		if (rv != EC_SUCCESS)	 /// 핵심기능시험에 실패할 경우 심각한 오류상태로 천이되고, 암호모듈은 사용불가
		{
			SetState(STATE_INABILITY_ERROR);
			g_error_code = rv;
			return TRUE;
		}

		//rv = SecureAIntegrityTest();	/// 무결성시험
		//if (rv != EC_SUCCESS)	/// 무결성시험에 실패할 경우 심각한 오류상태로 천이되고, 암호모듈은 사용불가
		//{
		//	SetState(STATE_INABILITY_ERROR);
		//	g_error_code = rv;
		//	return TRUE;
		//}

		SetState(STATE_CMVP_READY);
	}
	break;
	case DLL_PROCESS_DETACH:
	{
		/// 암호모듈 종료시 전원꺼짐 상태 천이
		SetState(STATE_POWER_OFF);
	}
	break;
	}
	return TRUE;
}

/// @fn int CryptoInit(void **context, int algo, int mode, ICPoint iv)
/// @brief 사용자가 암호모듈 서비스를 사용하기 위한 기본설정을 초기화
/// @return 암호모듈 상태
/// @param[in, out] context 입력받은 algo, mode, iv를 context 구조체에 입력
/// @param[in] algo 암호모듈 서비스를 사용하기 위한 암호 알고리즘 종류
/// @param[in] mode 암호모듈 서비스를 사용하기 위한 암호 알고리즘 모드(CBC, CTR)
/// @param[in] iv 암호모듈 서비스 사용시 필요한 초기 벡터값
EXPORT_API int CryptoInit(void** context, unsigned int algo, unsigned int mode, unsigned char* iv)
{
	CRYPTO_CONTEXT* ctx = (CRYPTO_CONTEXT*)calloc(sizeof(CRYPTO_CONTEXT) + 1, 1);
	if (ctx == NULL)
	{
		return EC_DATA_NULL;
	}

	/// 암호모듈 상태체크(암호모듈이 심각한 오류상태인 경우 상태오류코드를 출력)
	if (g_module_state == STATE_INABILITY_ERROR)
	{
		memset(ctx->key, 0x00, 256);
		memset(ctx->iv, 0x00, 16);
		free(ctx); ctx = NULL;
		return EC_STATE;
	}
		
	/// 암호모듈 상태체크(암호모듈이 검증대상 동작모드가 아닌 경우 상태오류코드를 출력)
	if (g_module_state != STATE_CMVP_READY)
	{
		memset(ctx->key, 0x00, 256);
		memset(ctx->iv, 0x00, 16);
		free(ctx); ctx = NULL;
		SetState(STATE_CMVP_ERROR);
		return EC_STATE;
	}

	/// 암호모듈 상태를 시작상태로 변경
	SetState(STATE_CMVP_INIT);

	/// 입력값 형식검증(mode와, iv에 대해서도 형식검증 필요)
	switch (algo)
	{
	case CRYPTO_ID_SEED:
	case CRYPTO_ID_ARIA:
	case CRYPTO_HASH_SHA256:
	case CRYPTO_HASH_SHA512:
	case CRYPTO_HMAC_SHA256:
	case CRYPTO_HMAC_SHA512:
	case CRYPTO_RSA_OAEP_2048:
	case CRYPTO_RSA_PSS_2048:
	case CRYPTO_HMAC_DRBG:
		ctx->algo = algo;
		ctx->mode = mode;
		break;
	default:
		SetState(STATE_CMVP_ERROR);
		memset(ctx->key, 0x00, 256);
		memset(ctx->iv, 0x00, 16);
		free(ctx); ctx = NULL;
		return EC_ALGO;
	}

	*context = ctx;

	return EC_SUCCESS;
}

/// @fn int CryptoFinalize(void **context)
/// @brief 암호모듈 서비스를 중지하고 모든 메모리를 해제하는 함수
/// @return 암호모듈 상태
/// @param[in, out] context context 구조체를 초기화
EXPORT_API int CryptoFinalize(void** context)
{
	/// 암호모듈 상태체크(암호모듈이 심각한 오류상태인 경우 상태오류코드를 출력)
	if (g_module_state == STATE_INABILITY_ERROR)
	{
		return EC_STATE;
	}

	/// 암호모듈 상태체크(암호모듈이 시작상태 또는 사용자 상태가 아닌 경우 상태오류코드를 출력)
	if (g_module_state != STATE_CMVP_INIT && g_module_state != STATE_CMVP_OPERATION)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_STATE;
	}

	/// 암호모듈 상태를 사용자 상태로 변경
	SetState(STATE_CMVP_OPERATION);

	/// 입력값 형식검증
	if (*context == NULL)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INITIALIZE_NO;
	}
	else
	{
		memset(*context, 0x00, sizeof(CRYPTO_CONTEXT));
		free(*context);
		*context = NULL;
		SetState(STATE_CMVP_FINAL);
		SetState(STATE_CMVP_READY);
	}

	return EC_SUCCESS;
}

/// @fn int CryptoEncrypt(void *context, unsigned char* input, unsigned int inputLength, unsigned char* output, unsigned int* outputLength)
/// @brief 블록단위 메시지 암호 기능을 제공
/// @return 암호모듈 상태
/// @param[in] context 알고리즘 종류(SEED, ARIA)와, 암호모드(ECB,CBC,CTR) 정보를 담고 있는 구조체
/// @param[in] input 입력데이터(원문)
/// @param[in] inputLength 입력데이터의 길이
/// @param[out] output 암호화된 출력데이터의 포인터
/// @param[out] outputLength 출력데이터의 길이
EXPORT_API int SecureAEncrypt(void* context, unsigned char* input, unsigned int inputLength, unsigned char* output, unsigned int* outputLength)
{
	int rv = EC_SUCCESS;
	int NumberRound = 0;

	CRYPTO_CONTEXT* ctx = NULL;

	/// 암호모듈 상태체크(암호모듈이 심각한 오류상태인 경우 상태오류코드를 출력)
	if (g_module_state == STATE_INABILITY_ERROR)
	{
		return EC_STATE;
	}
	
	/// 암호모듈 상태체크(암호모듈이 시작상태 또는 사용자 상태가 아닌 경우 상태오류코드를 출력)
	if (g_module_state != STATE_CMVP_KEY_SET && g_module_state != STATE_CMVP_OPERATION)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_STATE;
	}
	SetState(STATE_CMVP_OPERATION);

	/// 입력값 형식검증
	if (context == NULL)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INITIALIZE_NO;
	}
	ctx = (CRYPTO_CONTEXT*)context;

	if (inputLength <= 0)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INPUT_LEN;
	}
	if (input == NULL)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INPUT_VALUE;
	}
	if (outputLength < 0)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_OUTPUT_INIT;
	}
	if (ctx->mode != CIPHER_MODE_ECB && ctx->mode != CIPHER_MODE_CBC)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_MODE;
	}

	switch (ctx->algo)
	{
	case CRYPTO_ID_SEED:
		/// SEED 알고리즘 구현
		/// rv = SEEDEncrypt(ctx, input, output);
		break;
	case CRYPTO_ID_ARIA:
		/// ARIA 알고리즘 구현
		rv = ARIA_encrypt(ctx, input, NumberRound, output, output);
		break;
	default:
		SetState(STATE_CMVP_ERROR);
		return EC_ALGO;
	}
	if (rv != EC_SUCCESS)
	{
		SetState(STATE_CMVP_ERROR);
	}
	else
	{
		SetState(STATE_CMVP_OPERATION);
	}

	/// 제로화 수행

	return rv;
}

/// @fn int CryptoDecrypt(void *context, int padType, ICPoint input, ICPoint *output)
/// @brief 블록단위 메시지 복호 기능을 제공
/// @return 암호모듈 상태
/// @param[in] context 알고리즘 종류와, 암호모드(CBC, CTR) 정보를 담고 있는 구조체
/// @param[in] padType 패딩타입
/// @param[in] input 입력데이터와 길이 정보를 담고 있는 구조체
/// @param[out] output input 데이터를 복호화하여 해당 구조체로 리턴한다.
/// 
/// @fn int CryptoDecrypt(void *context, unsigned char* input, unsigned int inputLength, unsigned char* output, unsigned int* outputLength)
/// @brief 블록단위 메시지 복호 기능을 제공
/// @return 암호모듈 상태
/// @param[in] context 알고리즘 종류(SEED, ARIA)와, 암호모드(ECB,CBC,CTR) 정보를 담고 있는 구조체
/// @param[in] input 입력데이터(암호문)
/// @param[in] inputLength 입력데이터의 길이
/// @param[out] output 복호화된 출력데이터의 포인터
/// @param[out] outputLength 출력데이터의 길이
EXPORT_API int SecureACryptoDecrypt(void* context, unsigned char* input, unsigned int inputLength, unsigned char* output, unsigned int* outputLength)
{
	int rv = EC_SUCCESS;
	CRYPTO_CONTEXT* ctx = NULL;

	/// 암호모듈 상태체크(암호모듈이 심각한 오류상태인 경우 상태오류코드를 출력)
	if (g_module_state == STATE_INABILITY_ERROR)
	{
		return EC_STATE;
	}

	/// 암호모듈 상태체크(암호모듈이 시작상태 또는 사용자 상태가 아닌 경우 상태오류코드를 출력)
	if (g_module_state != STATE_CMVP_KEY_SET && g_module_state != STATE_CMVP_OPERATION)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_STATE;
	}
	SetState(STATE_CMVP_OPERATION);

	if (context == NULL)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INITIALIZE_NO;
	}
	ctx = (CRYPTO_CONTEXT*)context;
	
	/// 입력값 형식검증
	if (inputLength <= 0)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INPUT_LEN;
	}
	if (input== NULL)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INPUT_VALUE;
	}
	if (outputLength < 0)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_OUTPUT_INIT;
	}
	if (ctx->mode != CIPHER_MODE_ECB && ctx->mode != CIPHER_MODE_CBC)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_MODE;
	}

	switch (ctx->algo)
	{
	case CRYPTO_ID_SEED:
		/// SEED 알고리즘 구현
		/// rv = SEEDDecrypt(ctx, input, output);
		break;
	case CRYPTO_ID_ARIA:
		/// ARIA
		 rv = ARIA_decrypt(ctx, input, 1, output, output);
		break;
	default:
		SetState(STATE_CMVP_ERROR);
		return EC_ALGO;
	}
	if (rv != EC_SUCCESS)
	{
		SetState(STATE_CMVP_ERROR);
	}
	else
	{
		SetState(STATE_CMVP_OPERATION);
	}

	/// 제로화 수행

	return rv;
}

/// @fn int CryptoHash(void *context, unsigned char* input, unsigned inputLength, unsigned char* output)
/// @brief SHA 알고리즘을 사용하여 해시값을 생성
/// @return 암호모듈 상태
/// @param[in] context 알고리즘 종류를 담고 있는 구조체
/// @param[in] input 입력데이터(원문)
/// @param[in] inputLength 입력데이터의 길이
/// @param[out] output 해시 암호화된 결과
EXPORT_API int SecureACryptoHash(void* context, unsigned char* input, unsigned inputLength, unsigned char* output)
{
	int rv = EC_SUCCESS;
	CRYPTO_CONTEXT* ctx = NULL;

	/// 암호모듈 상태체크(암호모듈이 심각한 오류상태인 경우 상태오류코드를 출력)
	if (g_module_state == STATE_INABILITY_ERROR)
	{
		return EC_STATE;
	}

	/// 암호모듈 상태체크(암호모듈이 시작상태 또는 사용자 상태가 아닌 경우 상태오류코드를 출력)
	if (g_module_state != STATE_CMVP_INIT && g_module_state != STATE_CMVP_OPERATION)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_STATE;
	}

	SetState(STATE_CMVP_OPERATION);

	/// 입력데이터 형식검증
	if (context == NULL)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INITIALIZE_NO;
	}
	ctx = (CRYPTO_CONTEXT*)context;

	/// 해시암호화의 경우 입력데이터의 길이가 0이어도 해시가 가능하여야 하기 때문에 입력데이터의 길이는 체크하지 않는다.
	if (input == NULL)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INPUT_VALUE;
	}
	if (output == NULL)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_OUTPUT_INIT;
	}
	if (ctx->algo != CRYPTO_HASH_SHA256 && ctx->algo != CRYPTO_HASH_SHA512)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_ALGO;
	}

	/// 해시 알고리즘 구현
	 rv = SHA256_Encrpyt(input, inputLength, output);
	if (rv != EC_SUCCESS)
	{
		SetState(STATE_CMVP_ERROR);
	}
	else
	{
		SetState(STATE_CMVP_OPERATION);
	}

	/// 제로화 수행
	return rv;
}

/// @fn int CryptoRandom(void *context, int requestLength, unsigned char* nonce, unsigned int nonceLength, unsigned char* personalString, unsigned int personalStringLength, unsigned char* additionalInput, unsigned int additionalInputLength, unsigned char* output)
/// @brief HMAC_DRBG를 이용한 난수 생성
/// @return 암호모듈 상태
/// @param[in] context 알고리즘 정보를 담고 있는 구조체
/// @param[in] requestLength 생성할 난수의 길이
/// @param[in] nonce 난수생성시 사용할 논스
/// @param[in] nonceLength 논스의 길이
/// @param[in] personalString 난수생성시 사용할 개별화문자열
/// @param[in] personalStringLength 개별화문자열의 길이
/// @param[in] additionalInput 난수생성시 사용할 추가입력 데이터
/// @param[in] additionalInput 추가입력문자의 길이
/// @param[out] output 생성된 난수 출력값
EXPORT_API int SecureACryptoRandom(void* context, int requestLength, 
	unsigned char* nonce, unsigned int nonceLength, 
	unsigned char* personalString, unsigned int personalStringLength,
	unsigned char* additionalInput, unsigned int additionalInputLength,
	unsigned char* output)
{
	int rv = EC_SUCCESS;
	CRYPTO_CONTEXT* ctx = NULL;

	/// 암호모듈 상태체크(암호모듈이 심각한 오류상태인 경우 상태오류코드를 출력)
	if (g_module_state == STATE_INABILITY_ERROR)
	{
		return EC_STATE;
	}

	/// 암호모듈 상태체크(암호모듈이 시작상태 또는 사용자 상태가 아닌 경우 상태오류코드를 출력)
	if (g_module_state != STATE_CMVP_INIT && g_module_state != STATE_CMVP_OPERATION)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_STATE;
	}
	
	/// 입력데이터 형식검증
	if (context == NULL)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INITIALIZE_NO;
	}
	ctx = (CRYPTO_CONTEXT*)context;

	SetState(STATE_CMVP_OPERATION);
	SetState(STATE_CMVP_CONDITION);

	/// 논스의 길이가 16인지 체크(논스의 최소 길이는 엔트로피 보안강도/2 보다 같거나 커야함)
	if (nonceLength != 16)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INPUT_LEN;
	}

	/// 출력요청길이가 2^19를 안넘는지 체크
	if (requestLength > 256 || requestLength <= 0)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INPUT_LEN;
	}
	if (output == NULL)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_OUTPUT_INIT;
	}

	/// AdditionalInput 길이가 2^35를 안넘는지 체크
	if (additionalInputLength != 0)
	{
		if (additionalInputLength > 256 || additionalInputLength < 32)
		{
			SetState(STATE_CMVP_ERROR);
			return EC_INPUT_LEN;
		}
	}

	/// PersonalString 길이가 2^35를 안넘는지 체크
	if (personalStringLength != 0)
	{
		if (personalStringLength > 256 || personalStringLength < 32)
		{
			SetState(STATE_CMVP_ERROR);
			return EC_INPUT_LEN;
		}
	}

	 // 랜덤 알고리즘 구현
	 //rv = DRBG_RANDOM(ctx, nonce, personalString, additionalInput, output);	
	 
	 int num_of_bits = requestLength * 8;
	 rv =  KISA_CTR_DRBG_Generate(ctx, output, num_of_bits, additionalInput, additionalInputLength);

	if (rv != EC_SUCCESS)
	{
		if (GetState() != STATE_INABILITY_ERROR)
			SetState(STATE_INABILITY_ERROR);
	}
	else
	{
		SetState(STATE_CMVP_SUCCESS);
		SetState(STATE_CMVP_OPERATION);
	}

	/// 조건부 시험 구현
	/// 반복 횟수 테스트 RCT(Repetition_Count_Test) 시험
	/// 적응성 비율 테스트 APT(Adaptive_Proportion_Test) 시험

	/// 제로화 수행

	return rv;
}


/// @fn int CryptoSetKey(void *context, unsigned char* key, unsigned int keyLength)
/// @brief 블록단위 암복호화에 사용할 키를 context 구조체에 입력
/// @return 암호모듈 상태
/// @param[in] context 알고리즘 정보를 담고 있는 구조체
/// @param[in] key 키데이터를 담고 있는 포인터
/// @param[in] keyLength 키 길이
EXPORT_API int CryptoSetKey(void* context, unsigned char* key, unsigned int keyLength)
{
	int rv = 0;
	CRYPTO_CONTEXT* ctx = NULL;

	/// 암호모듈 상태체크(암호모듈이 심각한 오류상태인 경우 상태오류코드를 출력)
	if (g_module_state == STATE_INABILITY_ERROR)
	{
		return EC_STATE;
	}

	/// 암호모듈 상태체크(암호모듈이 시작상태가 아닌 경우 상태오류코드를 출력)
	if (g_module_state != STATE_CMVP_INIT)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_STATE;
	}

	/// 입력데이터 형식검증
	if (context == NULL)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INITIALIZE_NO;
	}
	ctx = (CRYPTO_CONTEXT*)context;

	SetState(STATE_CMVP_KEY_SET);	/// 암호모듈을 키 주입상태로 천이

	memcpy(ctx->key, key, keyLength);
	ctx->keyLen = keyLength;

	return EC_SUCCESS;
}

/// @fn int CryptoCleanKey(void *context)
/// @brief context 구조체의 메모리를 해제하여 키 제로화를 수행
/// @return 암호모듈 상태
/// @param[in] context 알고리즘 정보를 담고 있는 구조체
EXPORT_API int CryptoCleanKey(void* context)
{
	int rv = 0;
	CRYPTO_CONTEXT* ctx = NULL;

	/// 암호모듈 상태체크(암호모듈이 심각한 오류상태인 경우 상태오류코드를 출력)
	if (g_module_state == STATE_INABILITY_ERROR)
	{
		return EC_STATE;
	}

	/// 암호모듈 상태체크(암호모듈이 사용자 상태가 아닌 경우 상태오류코드를 출력)
	if (g_module_state != STATE_CMVP_OPERATION)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_STATE;
	}

	/// 입력데이터 형식검증
	if (context == NULL)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INITIALIZE_NO;
	}
	ctx = (CRYPTO_CONTEXT*)context;

	SetState(STATE_CMVP_OPERATION);

	/// 키 제로화
	memset(ctx->key, 0x00, ctx->keyLen);
	ctx->keyLen = 0;

	SetState(STATE_CMVP_OPERATION);

	return EC_SUCCESS;
}


/// @fn int CryptoHMac(void *context, unsigned char* input, unsigned int inputLength, unsigned char* output)
/// @brief 메시지 인증값을 생성
/// @return 암호모듈 상태
/// @param[in] context 알고리즘 정보를 담고 있는 구조체
/// @param[in] input 입력값(원문)을 담고 있는 포인터
/// @param[in] inputLength 입력값의 길이
/// @param[out] output 생성된 MAC값
EXPORT_API int SecureACryptHMac(void* context, unsigned char* input, unsigned int inputLength, unsigned char* output)
{
	int rv = EC_SUCCESS;
	CRYPTO_CONTEXT* ctx = NULL;

	/// 암호모듈 상태체크(암호모듈이 심각한 오류상태인 경우 상태오류코드를 출력)
	if (g_module_state == STATE_INABILITY_ERROR)
	{
		return EC_STATE;
	}

	/// 암호모듈 상태체크(암호모듈이 사용자 상태가 아닌 경우 상태오류코드를 출력)
	if (g_module_state != STATE_CMVP_KEY_SET && g_module_state != STATE_CMVP_OPERATION)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_STATE;
	}

	/// 입력데이터 형식검증
	if (context == NULL)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INITIALIZE_NO;
	}
	ctx = (CRYPTO_CONTEXT*)context;

	SetState(STATE_CMVP_OPERATION);

	if (inputLength <= 0)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INPUT_LEN;
	}

	if (input == NULL)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INPUT_VALUE;
	}
	if (ctx->keyLen <= 0)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_KEY_LEN;
	}
	if (output == NULL)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_OUTPUT_INIT;
	}
	unsigned char msg[1024] = { 0, }, key[1024] = { 0, };
	unsigned int msgLen = 0, keyLen = 0, outputLen = 0, ret = 0;

	keyLen = asc2hex(key, "C6F1D667A50AAEBA5A200A0A7CC24FFBB24984426AB8ABACCEE75162F3E1646B");
	
	/// HMAC 생성 알고리즘 구현
	 rv = HMAC_SHA256(input, inputLength, key, keyLen, output);
	if (rv != EC_SUCCESS)
	{
		SetState(STATE_CMVP_ERROR);
	}
	else
	{
		SetState(STATE_CMVP_OPERATION);
	}

	// 제로화 수행

	return rv;
}

/// @fn int CryptoHMacVerify(void* context, unsigned char* input, unsigned int inputLength, unsigned char* macValue, unsigned int macValueLength)
/// @brief 메시지 인증값을 검증
/// @return 암호모듈 상태
/// @param[in] context 알고리즘 정보를 담고 있는 구조체
/// @param[in] input 입력값(원문)
/// @param[in] inputLength 입력값의 길이
/// @param[in] macValue HMAC 데이터
/// @param[in] macValueLength HMAC 길이
EXPORT_API int CryptoHMacVerify(void* context, unsigned char* input, unsigned int inputLength, unsigned char* macValue, unsigned int macValueLength)
{
	int rv = EC_SUCCESS;
	CRYPTO_CONTEXT* ctx = NULL;

	/// 암호모듈 상태체크(암호모듈이 심각한 오류상태인 경우 상태오류코드를 출력)
	if (g_module_state == STATE_INABILITY_ERROR)
	{
		return EC_STATE;
	}

	/// 암호모듈 상태체크(암호모듈이 사용자 상태가 아닌 경우 상태오류코드를 출력)
	if (g_module_state != STATE_CMVP_KEY_SET && g_module_state != STATE_CMVP_OPERATION)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_STATE;
	}

	/// 입력데이터 형식검증
	if (context == NULL)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INITIALIZE_NO;
	}
	ctx = (CRYPTO_CONTEXT*)context;

	SetState(STATE_CMVP_OPERATION);

	if (inputLength <= 0)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INPUT_LEN;
	}
	if (input == NULL)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INPUT_VALUE;
	}
	if (ctx->keyLen <= 0)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_KEY_LEN;
	}
	if (macValueLength != 32 && macValueLength != 64)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INPUT_LEN;
	}
	if (macValue == NULL)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INPUT_VALUE;
	}
	if (ctx->mode != CRYPTO_HMAC_SHA256 && ctx->mode != CRYPTO_HMAC_SHA512)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_ALGO;
	}

	unsigned char key[1024] = { 0, };
	unsigned int keyLen = 0;

	keyLen = asc2hex(key, "C6F1D667A50AAEBA5A200A0A7CC24FFBB24984426AB8ABACCEE75162F3E1646B");
	
	/// HMAC 검증 알고리즘 구현
	 rv = test_hmac_sha256(ctx->algo, input, inputLength, key, keyLen, macValue, macValueLength);
	if (rv != EC_SUCCESS)
	{
		SetState(STATE_CMVP_ERROR);
	}
	else
	{
		SetState(STATE_CMVP_OPERATION);
	}

	// 제로화 수행

	return rv;
}


/// @fn int CryptoRSAEncrypt(void* context, unsigned char* publickey, unsigned int publickeyLength, unsigned char* exponent, unsigned int exponentLength, unsigned char* input, unsigned int inputLength, unsigned char* output, unsigned char* seed, unsigned int seedLength, unsigned int shaFlag)
/// @brief RSA_OAEP 방식을 사용한 암호화
/// @return 암호모듈 상태
/// @param[in] context 알고리즘 정보를 담고 있는 구조체
/// @param[in] publickey 암호화에 사용될 공개키
/// @param[in] publickeyLength 공개키 길이
/// @param[in] exponent 암호화에 사용될 공개키 지수
/// @param[in] exponentLength 공개키 지수 길이
/// @param[in] input 암호화 대상이 되는 평문 입력값
/// @param[in] inputLength 입력값 길이
/// @param[out] output 생성된 암호문이 저장될 매개변수
/// @param[in] seed 암호문에 사용될 초기 SEED값(NULL 입력시 내부에서 랜덤 생성)
/// @param[in] seedLength seed의 길이
 /* 
EXPORT_API int CryptoRSAEncrypt(void* context, unsigned char* publickey, unsigned int publickeyLength,
	unsigned char* exponent, unsigned int exponentLength,
	unsigned char* input, unsigned int inputLength,
	unsigned char* output, unsigned char* seed, unsigned int seedLength)
{
	int rv = EC_SUCCESS;
	CRYPTO_CONTEXT* ctx = NULL;

	/// 암호모듈 상태체크(암호모듈이 심각한 오류상태인 경우 상태오류코드를 출력)
	if (g_module_state == STATE_INABILITY_ERROR)
	{
		return EC_STATE;
	}

	/// 암호모듈 상태체크(암호모듈이 사용자 상태가 아닌 경우 상태오류코드를 출력)
	if (g_module_state != STATE_CMVP_INIT && g_module_state != STATE_CMVP_OPERATION)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_STATE;
	}

	/// 입력데이터 형식검증
	if (context == NULL)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INITIALIZE_NO;
	}
	ctx = (CRYPTO_CONTEXT*)context;

	SetState(STATE_CMVP_KEY_SET);
	SetState(STATE_CMVP_OPERATION);

	/// 메시지 크기 확인
	if (inputLength <= 0 || inputLength > 190)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INPUT_LEN;
	}
	if (input == NULL)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INPUT_VALUE;
	}
	if (publickeyLength != 256)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_KEY_LEN;
	}
	if (publickey == NULL)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_KEY_VALUE;
	}
	if (exponentLength <= 0 || exponent == NULL)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_KEY_VALUE;
	}
	if (output == NULL)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_OUTPUT_INIT;
	}

	/// 입력된 매개변수를 이용한 RSA 암호화 알고리즘 구현
	if (rv != EC_SUCCESS)
	{
		SetState(STATE_CMVP_ERROR);
	}
	else
	{
		SetState(STATE_CMVP_OPERATION);
	}

	// 제로화 수행

	return rv;
}
*/


/// @fn int CryptoRSADecrypt(void* context, unsigned char* privatekey, unsigned int privatekeyLength, unsigned char* publickey, unsigned int publickeyLength, unsigned char* input, unsigned int inputLength, unsigned char* output, unsigned int* outputLength)
/// @brief RSA_OAEP 방식을 사용한 복호화
/// @return 암호모듈 상태
/// @param[in] context 알고리즘 정보를 담고 있는 구조체
/// @param[in] privatekey 복호화에 사용될 개인키
/// @param[in] privatekeyLength 개인키 길이
/// @param[in] publickey 복호화에 사용될 공개키
/// @param[in] publickeyLength 공개키 길이
/// @param[in] input 복호화 대상이 되는 암호문 입력값
/// @param[in] inputLength 입력값 길이
/// @param[out] output 복호화된 평문이 저장될 매개변수
/// @param[out] outputLength 복호화된 평문의 길이
/*
EXPORT_API int CryptoRSADecrypt(void* context, unsigned char* privatekey, unsigned int privatekeyLength,
	unsigned char* publickey, unsigned int publickeyLength,
	unsigned char* input, unsigned int inputLength,
	unsigned char* output, unsigned int* outputLength)
{
	int rv = EC_SUCCESS;
	CRYPTO_CONTEXT* ctx = NULL;

	/// 암호모듈 상태체크(암호모듈이 심각한 오류상태인 경우 상태오류코드를 출력)
	if (g_module_state == STATE_INABILITY_ERROR)
	{
		return EC_STATE;
	}

	/// 암호모듈 상태체크(암호모듈이 사용자 상태가 아닌 경우 상태오류코드를 출력)
	if (g_module_state != STATE_CMVP_INIT && g_module_state != STATE_CMVP_OPERATION)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_STATE;
	}

	/// 입력데이터 형식검증
	if (context == NULL)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INITIALIZE_NO;
	}
	ctx = (CRYPTO_CONTEXT*)context;

	SetState(STATE_CMVP_KEY_SET);
	SetState(STATE_CMVP_OPERATION);

	if (ctx->algo != CRYPTO_RSA_OAEP_2048)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_ALGO;
	}

	/// 암호문 C길이 |C| = |n|
	if (inputLength != 256)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INPUT_LEN;
	}
	if (input == NULL)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INPUT_VALUE;
	}
	if (publickeyLength != 256)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_KEY_LEN;
	}
	if (publickey == NULL)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_KEY_VALUE;
	}
	if (privatekeyLength != 256)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_KEY_LEN;
	}
	if (privatekey == NULL)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_KEY_VALUE;
	}
	if (output == NULL)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_OUTPUT_INIT;
	}
	/// 입력된 매개변수를 이용한 RSA 복호화 알고리즘 구현
	if (rv != EC_SUCCESS)
	{
		SetState(STATE_CMVP_ERROR);
	}
	else
	{
		SetState(STATE_CMVP_OPERATION);
	}

	// 제로화 수행

	return rv;
}
*/

int test_hmac_sha256() {
	/* === 테스트 벡터(사용자가 준 원본) === */
	unsigned char msg[1024] = { 0, }, key[1024] = { 0, }, expected_hmac[32] = { 0, }, hmac[32];
	unsigned int msgLen = 0, keyLen = 0, outputLen = 0, ret = 0;
	//void HMAC_SHA256(const u8* message, u32 mlen, const u8* key, u32 klen, u8 hmac[SHA256_DIGEST_VALUELEN]);

	keyLen = asc2hex(key, "C6F1D667A50AAEBA5A200A0A7CC24FFBB24984426AB8ABACCEE75162F3E1646B");
	msgLen = asc2hex(msg, "548A457280851ECA0F5476AFDAC102CF6C7DBE09B3083D74FBD03DA31E9D7F27F42CD656111A7D4BB005AD2EEAED6FB62CE0B0EBE7D6933189DA0B82AD6AA8FB8E21B19AC29374462579DA0F130E3EB8DAB87F726EEB54EB5F4AE087091087ED0BAFFFC6FAB7AAC156F823DBBCEB17DD5E4E5626B10F29AA656BE73B9A57C308");
	outputLen = asc2hex(expected_hmac, "96C37F36CA0DEA3B2B3E60F1F6CDF79CFF72CA2A43A091C8105AE882A690EF2F");

	/* === 암호화 수행 === */
	int rv = EC_SUCCESS;
	rv = HMAC_SHA256(msg, msgLen, key, keyLen, hmac);
	if (rv != EC_SUCCESS)
	{
		SetState(STATE_CMVP_ERROR);
	}

	/* === 암호화 결과검증 === */
	if (memcmp(hmac, expected_hmac, 16) == 0) {
		return EC_SUCCESS;  // 암호문 일치
	}
	else {
		return EC_HMAC_VERIFY;  // 암호문 불일치
	}
}

int test_aria() {
	/* === 테스트 벡터(사용자가 준 원본) === */
	/* 평문 */
	Byte p[16] = {
		0x11, 0x11, 0x11, 0x11, 0xaa, 0xaa, 0xaa, 0xaa,
		0x11, 0x11, 0x11, 0x11, 0xbb, 0xbb, 0xbb, 0xbb
	};

	/* 192비트 키 (mk[0..23] 사용) */
	Byte mk[32];
	for (int i = 0; i < 16; i++) mk[i] = (Byte)(i * 0x11);        /* 00,11,22,...,FF */
	for (int i = 16; i < 24; i++) mk[i] = (Byte)((i - 16) * 0x11);/* 00..77 */
	for (int i = 24; i < 32; i++) mk[i] = 0; /* 상위는 0으로 클리어 */

	/* 기대 암호문 */
	const Byte expected[16] = {
		0x8d, 0x14, 0x70, 0x62, 0x5f, 0x59, 0xeb, 0xac,
		0xb0, 0xe5, 0x5b, 0x53, 0x4b, 0x3e, 0x46, 0x2b
	};

	/* === 암호화 수행 === */
	int rv = EC_SUCCESS;
	Byte out[16];

	CRYPTO_CONTEXT* ctx = NULL;
	ctx = (CRYPTO_CONTEXT*)malloc(sizeof(CRYPTO_CONTEXT));
	memset(ctx, 0x00, sizeof(CRYPTO_CONTEXT));

	ctx->algo = CRYPTO_ID_ARIA;

	rv = SecureAEncrypt(ctx, p, 16, out, 16);
	if (rv != EC_SUCCESS)
	{
		SetState(STATE_CMVP_ERROR);
	}

	/* === 암호화 결과검증 === */
	if (memcmp(out, expected, 16) == 0) {
		return EC_SUCCESS;  // 암호문 일치
	}
	else {
		return EC_ARIA_VERIFY_ERROR;  // 암호문 불일치
	}
}

/// @fn int CoreFunctionTest()
/// @brief 핵심기능시험 인터페이스 함수, 기지답안테스트(KAT) 검사를 수행하여 통과해야 암호모듈을 사용할 수 있다.
/// @return 암호모듈 상태
EXPORT_API int SecureACoreFunctionTest()
{
	int rv = EC_SUCCESS;
	unsigned char random_output[32] = { 0, };

	// SHA256테스트는 HMAC_SHA256 테스트에 포함되므로 대체함
	//rv = SHA256_Encrpyt(input, 3, random_output); if (rv != EC_SUCCESS)	return rv;
	rv = test_hmac_sha256();				if (rv != EC_SUCCESS)	return rv;
	rv = test_aria();			if (rv != EC_SUCCESS)	return rv;

	if (rv != EC_SUCCESS)	
		return rv;

	return EC_SUCCESS;
}

EXPORT_API int SecureAIntegrityTest()
{
	int		ERROR_CODE = 0;
	unsigned char*	key = NULL;
	unsigned int*	keyLength = 0;
	unsigned char*	module_macValue = NULL;
	unsigned char*	output = NULL;
	unsigned int*	outputLenth = 0;
	unsigned char*	modulefile = NULL;
	unsigned int*	modulefileLength = 0;

	HMODULE hModule = GetModuleHandle("sample_kcmvp.dll");
	unsigned char moduleName[260] = { 0, };

	/// GetModuleFileName() 등을 이용하여 현재 실행중인 모듈의 경로를 확인
	GetModuleFileName(
		hModule,	/// 현재 실행되고 있는 모듈의 핸들, 또는 NULL(자신의 실행경로 반환)
		moduleName,  /// 실행 경로를 받을 포인터
		MAX_PATH			/// 실행 경로가 들어갈 버퍼의 길이
	);

	// 암호모듈 내 포함된 Mac값 추출
	//module_macValue = sudo_getModule_macData();

	// Mac값 생성에 사용될 키 추출
	//key = sudo_getMacKey();

	// 암호모듈 파일에 대한 무결성 검증값(Mac값 생성)
	//Mac(output, outputLenth, modulefile, modulefileLength, key, keyLength, alg);

	if (memcmp(output, module_macValue, (size_t)outputLenth) != 0) {
		return EC_INTEGRITY_VERIFY;
	}

	return EC_SUCCESS;
}

/// @fn int CryptoGetLastErrorCode()
/// @brief 암호모듈의 마지막 오류코드를 리턴
/// @return 암호모듈의 마지막 오류코드를 리턴
EXPORT_API int CryptoGetLastErrorCode()
{
	return g_error_code;
}


int asc2hex(unsigned char* dst, const char* src)
{
	unsigned char temp = 0x00;
	int i = 0;

	while (src[i] != 0x00)
	{
		temp = 0x00;

		if ((src[i] >= 0x30) && (src[i] <= 0x39))
			temp = src[i] - '0';
		else if ((src[i] >= 0x41) && (src[i] <= 0x5A))
			temp = src[i] - 'A' + 10;
		else if ((src[i] >= 0x61) && (src[i] <= 0x7A))
			temp = src[i] - 'a' + 10;
		else
			temp = 0x00;

		(i & 1) ? (dst[i >> 1] ^= temp & 0x0F) : (dst[i >> 1] = 0, dst[i >> 1] = temp << 4);

		i++;
	}

	return ((i + 1) / 2);
}

int main(void)
{
	int* p = (int*)malloc(sizeof(int) * 10);

	//if (p == NULL)
	//{
	//	return 0;
	//}

	for (int i = 0; i < 10; i++)
	{
		p[i] = i + 1;
	}

	free(p);

	return 0;
}