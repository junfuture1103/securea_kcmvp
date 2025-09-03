/// @file sample_kcmvp.c
/// @section intro �Ұ�
/// - �Ұ� : 
/// @section Program ���α׷���
/// - ���α׷��� : KCMVP API Interface Module
/// - ���α׷����� : ��ȣ����� �ܺ� �������̽��� �����Ѵ�.
/// @section CREATEINFO �ۼ�����
/// - �ۼ���  : 
/// - �ۼ���  : 
/// @date 2023-06-01
/// @section MODIFYINFO ��������
/// - ������/������ : 
/// - 2023-06-01/Author Name : ��������
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
/// @brief ��ȣ����� ������¸� ����� ���·� ��ȯ��Ű�� �Լ�
/// @return ��ȣ��� ����
/// @param[in] state ��ȣ����� �������
int SetState(int state)
{
	if (GetState() == STATE_INABILITY_ERROR)
		return EC_STATE;

	g_module_state = state;
	return EC_SUCCESS;
}


/// @fn int GetState()
/// @brief ��ȣ����� ������¸� ��� �Լ�
/// @return ��ȣ��� ����
EXPORT_API int GetState()
{
	return g_module_state;
}

/// @fn int CryptoChangeState()
/// @brief ��ȣ����� ������¸� ��ȣ� ���������� ��쿡�� ����� ���·η� ����õ��
/// @return ��ȣ��� ����
EXPORT_API int CryptoChangeState()
{
	if (GetState() == STATE_CMVP_ERROR)
		return SetState(STATE_CMVP_READY);
	else
		return GetState();
}

/// @fn BOOL DllMain(HMODULE hModule, unsigned int ul_reason_for_call, LPVOID lpReserved)
/// @brief ��ȣ����� ������
/// @return ��ȣ��� �ε� ��������
BOOL APIENTRY DllMain(HMODULE hModule, unsigned int ul_reason_for_call, LPVOID lpReserved)
{
	int rv = EC_SUCCESS;

	switch (ul_reason_for_call)
	{
	case DLL_PROCESS_ATTACH:
	{
		/// �������� ���� õ��
		SetState(STATE_POWER_ON);

		/// �ڰ�������� õ��
		SetState(STATE_SELFTEST);

		rv = SecureACoreFunctionTest(); /// �ٽɱ�ɽ���
		if (rv != EC_SUCCESS)	 /// �ٽɱ�ɽ��迡 ������ ��� �ɰ��� �������·� õ�̵ǰ�, ��ȣ����� ���Ұ�
		{
			SetState(STATE_INABILITY_ERROR);
			g_error_code = rv;
			return TRUE;
		}

		//rv = SecureAIntegrityTest();	/// ���Ἲ����
		//if (rv != EC_SUCCESS)	/// ���Ἲ���迡 ������ ��� �ɰ��� �������·� õ�̵ǰ�, ��ȣ����� ���Ұ�
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
		/// ��ȣ��� ����� �������� ���� õ��
		SetState(STATE_POWER_OFF);
	}
	break;
	}
	return TRUE;
}

/// @fn int CryptoInit(void **context, int algo, int mode, ICPoint iv)
/// @brief ����ڰ� ��ȣ��� ���񽺸� ����ϱ� ���� �⺻������ �ʱ�ȭ
/// @return ��ȣ��� ����
/// @param[in, out] context �Է¹��� algo, mode, iv�� context ����ü�� �Է�
/// @param[in] algo ��ȣ��� ���񽺸� ����ϱ� ���� ��ȣ �˰��� ����
/// @param[in] mode ��ȣ��� ���񽺸� ����ϱ� ���� ��ȣ �˰��� ���(CBC, CTR)
/// @param[in] iv ��ȣ��� ���� ���� �ʿ��� �ʱ� ���Ͱ�
EXPORT_API int CryptoInit(void** context, unsigned int algo, unsigned int mode, unsigned char* iv)
{
	CRYPTO_CONTEXT* ctx = (CRYPTO_CONTEXT*)calloc(sizeof(CRYPTO_CONTEXT) + 1, 1);
	if (ctx == NULL)
	{
		return EC_DATA_NULL;
	}

	/// ��ȣ��� ����üũ(��ȣ����� �ɰ��� ���������� ��� ���¿����ڵ带 ���)
	if (g_module_state == STATE_INABILITY_ERROR)
	{
		memset(ctx->key, 0x00, 256);
		memset(ctx->iv, 0x00, 16);
		free(ctx); ctx = NULL;
		return EC_STATE;
	}
		
	/// ��ȣ��� ����üũ(��ȣ����� ������� ���۸�尡 �ƴ� ��� ���¿����ڵ带 ���)
	if (g_module_state != STATE_CMVP_READY)
	{
		memset(ctx->key, 0x00, 256);
		memset(ctx->iv, 0x00, 16);
		free(ctx); ctx = NULL;
		SetState(STATE_CMVP_ERROR);
		return EC_STATE;
	}

	/// ��ȣ��� ���¸� ���ۻ��·� ����
	SetState(STATE_CMVP_INIT);

	/// �Է°� ���İ���(mode��, iv�� ���ؼ��� ���İ��� �ʿ�)
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
/// @brief ��ȣ��� ���񽺸� �����ϰ� ��� �޸𸮸� �����ϴ� �Լ�
/// @return ��ȣ��� ����
/// @param[in, out] context context ����ü�� �ʱ�ȭ
EXPORT_API int CryptoFinalize(void** context)
{
	/// ��ȣ��� ����üũ(��ȣ����� �ɰ��� ���������� ��� ���¿����ڵ带 ���)
	if (g_module_state == STATE_INABILITY_ERROR)
	{
		return EC_STATE;
	}

	/// ��ȣ��� ����üũ(��ȣ����� ���ۻ��� �Ǵ� ����� ���°� �ƴ� ��� ���¿����ڵ带 ���)
	if (g_module_state != STATE_CMVP_INIT && g_module_state != STATE_CMVP_OPERATION)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_STATE;
	}

	/// ��ȣ��� ���¸� ����� ���·� ����
	SetState(STATE_CMVP_OPERATION);

	/// �Է°� ���İ���
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
/// @brief ��ϴ��� �޽��� ��ȣ ����� ����
/// @return ��ȣ��� ����
/// @param[in] context �˰��� ����(SEED, ARIA)��, ��ȣ���(ECB,CBC,CTR) ������ ��� �ִ� ����ü
/// @param[in] input �Էµ�����(����)
/// @param[in] inputLength �Էµ������� ����
/// @param[out] output ��ȣȭ�� ��µ������� ������
/// @param[out] outputLength ��µ������� ����
EXPORT_API int SecureAEncrypt(void* context, unsigned char* input, unsigned int inputLength, unsigned char* output, unsigned int* outputLength)
{
	int rv = EC_SUCCESS;
	int NumberRound = 0;

	CRYPTO_CONTEXT* ctx = NULL;

	/// ��ȣ��� ����üũ(��ȣ����� �ɰ��� ���������� ��� ���¿����ڵ带 ���)
	if (g_module_state == STATE_INABILITY_ERROR)
	{
		return EC_STATE;
	}
	
	/// ��ȣ��� ����üũ(��ȣ����� ���ۻ��� �Ǵ� ����� ���°� �ƴ� ��� ���¿����ڵ带 ���)
	if (g_module_state != STATE_CMVP_KEY_SET && g_module_state != STATE_CMVP_OPERATION)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_STATE;
	}
	SetState(STATE_CMVP_OPERATION);

	/// �Է°� ���İ���
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
		/// SEED �˰��� ����
		/// rv = SEEDEncrypt(ctx, input, output);
		break;
	case CRYPTO_ID_ARIA:
		/// ARIA �˰��� ����
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

	/// ����ȭ ����

	return rv;
}

/// @fn int CryptoDecrypt(void *context, int padType, ICPoint input, ICPoint *output)
/// @brief ��ϴ��� �޽��� ��ȣ ����� ����
/// @return ��ȣ��� ����
/// @param[in] context �˰��� ������, ��ȣ���(CBC, CTR) ������ ��� �ִ� ����ü
/// @param[in] padType �е�Ÿ��
/// @param[in] input �Էµ����Ϳ� ���� ������ ��� �ִ� ����ü
/// @param[out] output input �����͸� ��ȣȭ�Ͽ� �ش� ����ü�� �����Ѵ�.
/// 
/// @fn int CryptoDecrypt(void *context, unsigned char* input, unsigned int inputLength, unsigned char* output, unsigned int* outputLength)
/// @brief ��ϴ��� �޽��� ��ȣ ����� ����
/// @return ��ȣ��� ����
/// @param[in] context �˰��� ����(SEED, ARIA)��, ��ȣ���(ECB,CBC,CTR) ������ ��� �ִ� ����ü
/// @param[in] input �Էµ�����(��ȣ��)
/// @param[in] inputLength �Էµ������� ����
/// @param[out] output ��ȣȭ�� ��µ������� ������
/// @param[out] outputLength ��µ������� ����
EXPORT_API int SecureACryptoDecrypt(void* context, unsigned char* input, unsigned int inputLength, unsigned char* output, unsigned int* outputLength)
{
	int rv = EC_SUCCESS;
	CRYPTO_CONTEXT* ctx = NULL;

	/// ��ȣ��� ����üũ(��ȣ����� �ɰ��� ���������� ��� ���¿����ڵ带 ���)
	if (g_module_state == STATE_INABILITY_ERROR)
	{
		return EC_STATE;
	}

	/// ��ȣ��� ����üũ(��ȣ����� ���ۻ��� �Ǵ� ����� ���°� �ƴ� ��� ���¿����ڵ带 ���)
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
	
	/// �Է°� ���İ���
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
		/// SEED �˰��� ����
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

	/// ����ȭ ����

	return rv;
}

/// @fn int CryptoHash(void *context, unsigned char* input, unsigned inputLength, unsigned char* output)
/// @brief SHA �˰����� ����Ͽ� �ؽð��� ����
/// @return ��ȣ��� ����
/// @param[in] context �˰��� ������ ��� �ִ� ����ü
/// @param[in] input �Էµ�����(����)
/// @param[in] inputLength �Էµ������� ����
/// @param[out] output �ؽ� ��ȣȭ�� ���
EXPORT_API int SecureACryptoHash(void* context, unsigned char* input, unsigned inputLength, unsigned char* output)
{
	int rv = EC_SUCCESS;
	CRYPTO_CONTEXT* ctx = NULL;

	/// ��ȣ��� ����üũ(��ȣ����� �ɰ��� ���������� ��� ���¿����ڵ带 ���)
	if (g_module_state == STATE_INABILITY_ERROR)
	{
		return EC_STATE;
	}

	/// ��ȣ��� ����üũ(��ȣ����� ���ۻ��� �Ǵ� ����� ���°� �ƴ� ��� ���¿����ڵ带 ���)
	if (g_module_state != STATE_CMVP_INIT && g_module_state != STATE_CMVP_OPERATION)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_STATE;
	}

	SetState(STATE_CMVP_OPERATION);

	/// �Էµ����� ���İ���
	if (context == NULL)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INITIALIZE_NO;
	}
	ctx = (CRYPTO_CONTEXT*)context;

	/// �ؽþ�ȣȭ�� ��� �Էµ������� ���̰� 0�̾ �ؽð� �����Ͽ��� �ϱ� ������ �Էµ������� ���̴� üũ���� �ʴ´�.
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

	/// �ؽ� �˰��� ����
	 rv = SHA256_Encrpyt(input, inputLength, output);
	if (rv != EC_SUCCESS)
	{
		SetState(STATE_CMVP_ERROR);
	}
	else
	{
		SetState(STATE_CMVP_OPERATION);
	}

	/// ����ȭ ����
	return rv;
}

/// @fn int CryptoRandom(void *context, int requestLength, unsigned char* nonce, unsigned int nonceLength, unsigned char* personalString, unsigned int personalStringLength, unsigned char* additionalInput, unsigned int additionalInputLength, unsigned char* output)
/// @brief HMAC_DRBG�� �̿��� ���� ����
/// @return ��ȣ��� ����
/// @param[in] context �˰��� ������ ��� �ִ� ����ü
/// @param[in] requestLength ������ ������ ����
/// @param[in] nonce ���������� ����� ��
/// @param[in] nonceLength ���� ����
/// @param[in] personalString ���������� ����� ����ȭ���ڿ�
/// @param[in] personalStringLength ����ȭ���ڿ��� ����
/// @param[in] additionalInput ���������� ����� �߰��Է� ������
/// @param[in] additionalInput �߰��Է¹����� ����
/// @param[out] output ������ ���� ��°�
EXPORT_API int SecureACryptoRandom(void* context, int requestLength, 
	unsigned char* nonce, unsigned int nonceLength, 
	unsigned char* personalString, unsigned int personalStringLength,
	unsigned char* additionalInput, unsigned int additionalInputLength,
	unsigned char* output)
{
	int rv = EC_SUCCESS;
	CRYPTO_CONTEXT* ctx = NULL;

	/// ��ȣ��� ����üũ(��ȣ����� �ɰ��� ���������� ��� ���¿����ڵ带 ���)
	if (g_module_state == STATE_INABILITY_ERROR)
	{
		return EC_STATE;
	}

	/// ��ȣ��� ����üũ(��ȣ����� ���ۻ��� �Ǵ� ����� ���°� �ƴ� ��� ���¿����ڵ带 ���)
	if (g_module_state != STATE_CMVP_INIT && g_module_state != STATE_CMVP_OPERATION)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_STATE;
	}
	
	/// �Էµ����� ���İ���
	if (context == NULL)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INITIALIZE_NO;
	}
	ctx = (CRYPTO_CONTEXT*)context;

	SetState(STATE_CMVP_OPERATION);
	SetState(STATE_CMVP_CONDITION);

	/// ���� ���̰� 16���� üũ(���� �ּ� ���̴� ��Ʈ���� ���Ȱ���/2 ���� ���ų� Ŀ����)
	if (nonceLength != 16)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INPUT_LEN;
	}

	/// ��¿�û���̰� 2^19�� �ȳѴ��� üũ
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

	/// AdditionalInput ���̰� 2^35�� �ȳѴ��� üũ
	if (additionalInputLength != 0)
	{
		if (additionalInputLength > 256 || additionalInputLength < 32)
		{
			SetState(STATE_CMVP_ERROR);
			return EC_INPUT_LEN;
		}
	}

	/// PersonalString ���̰� 2^35�� �ȳѴ��� üũ
	if (personalStringLength != 0)
	{
		if (personalStringLength > 256 || personalStringLength < 32)
		{
			SetState(STATE_CMVP_ERROR);
			return EC_INPUT_LEN;
		}
	}

	 // ���� �˰��� ����
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

	/// ���Ǻ� ���� ����
	/// �ݺ� Ƚ�� �׽�Ʈ RCT(Repetition_Count_Test) ����
	/// ������ ���� �׽�Ʈ APT(Adaptive_Proportion_Test) ����

	/// ����ȭ ����

	return rv;
}


/// @fn int CryptoSetKey(void *context, unsigned char* key, unsigned int keyLength)
/// @brief ��ϴ��� �Ϻ�ȣȭ�� ����� Ű�� context ����ü�� �Է�
/// @return ��ȣ��� ����
/// @param[in] context �˰��� ������ ��� �ִ� ����ü
/// @param[in] key Ű�����͸� ��� �ִ� ������
/// @param[in] keyLength Ű ����
EXPORT_API int CryptoSetKey(void* context, unsigned char* key, unsigned int keyLength)
{
	int rv = 0;
	CRYPTO_CONTEXT* ctx = NULL;

	/// ��ȣ��� ����üũ(��ȣ����� �ɰ��� ���������� ��� ���¿����ڵ带 ���)
	if (g_module_state == STATE_INABILITY_ERROR)
	{
		return EC_STATE;
	}

	/// ��ȣ��� ����üũ(��ȣ����� ���ۻ��°� �ƴ� ��� ���¿����ڵ带 ���)
	if (g_module_state != STATE_CMVP_INIT)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_STATE;
	}

	/// �Էµ����� ���İ���
	if (context == NULL)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INITIALIZE_NO;
	}
	ctx = (CRYPTO_CONTEXT*)context;

	SetState(STATE_CMVP_KEY_SET);	/// ��ȣ����� Ű ���Ի��·� õ��

	memcpy(ctx->key, key, keyLength);
	ctx->keyLen = keyLength;

	return EC_SUCCESS;
}

/// @fn int CryptoCleanKey(void *context)
/// @brief context ����ü�� �޸𸮸� �����Ͽ� Ű ����ȭ�� ����
/// @return ��ȣ��� ����
/// @param[in] context �˰��� ������ ��� �ִ� ����ü
EXPORT_API int CryptoCleanKey(void* context)
{
	int rv = 0;
	CRYPTO_CONTEXT* ctx = NULL;

	/// ��ȣ��� ����üũ(��ȣ����� �ɰ��� ���������� ��� ���¿����ڵ带 ���)
	if (g_module_state == STATE_INABILITY_ERROR)
	{
		return EC_STATE;
	}

	/// ��ȣ��� ����üũ(��ȣ����� ����� ���°� �ƴ� ��� ���¿����ڵ带 ���)
	if (g_module_state != STATE_CMVP_OPERATION)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_STATE;
	}

	/// �Էµ����� ���İ���
	if (context == NULL)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INITIALIZE_NO;
	}
	ctx = (CRYPTO_CONTEXT*)context;

	SetState(STATE_CMVP_OPERATION);

	/// Ű ����ȭ
	memset(ctx->key, 0x00, ctx->keyLen);
	ctx->keyLen = 0;

	SetState(STATE_CMVP_OPERATION);

	return EC_SUCCESS;
}


/// @fn int CryptoHMac(void *context, unsigned char* input, unsigned int inputLength, unsigned char* output)
/// @brief �޽��� �������� ����
/// @return ��ȣ��� ����
/// @param[in] context �˰��� ������ ��� �ִ� ����ü
/// @param[in] input �Է°�(����)�� ��� �ִ� ������
/// @param[in] inputLength �Է°��� ����
/// @param[out] output ������ MAC��
EXPORT_API int SecureACryptHMac(void* context, unsigned char* input, unsigned int inputLength, unsigned char* output)
{
	int rv = EC_SUCCESS;
	CRYPTO_CONTEXT* ctx = NULL;

	/// ��ȣ��� ����üũ(��ȣ����� �ɰ��� ���������� ��� ���¿����ڵ带 ���)
	if (g_module_state == STATE_INABILITY_ERROR)
	{
		return EC_STATE;
	}

	/// ��ȣ��� ����üũ(��ȣ����� ����� ���°� �ƴ� ��� ���¿����ڵ带 ���)
	if (g_module_state != STATE_CMVP_KEY_SET && g_module_state != STATE_CMVP_OPERATION)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_STATE;
	}

	/// �Էµ����� ���İ���
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
	
	/// HMAC ���� �˰��� ����
	 rv = HMAC_SHA256(input, inputLength, key, keyLen, output);
	if (rv != EC_SUCCESS)
	{
		SetState(STATE_CMVP_ERROR);
	}
	else
	{
		SetState(STATE_CMVP_OPERATION);
	}

	// ����ȭ ����

	return rv;
}

/// @fn int CryptoHMacVerify(void* context, unsigned char* input, unsigned int inputLength, unsigned char* macValue, unsigned int macValueLength)
/// @brief �޽��� �������� ����
/// @return ��ȣ��� ����
/// @param[in] context �˰��� ������ ��� �ִ� ����ü
/// @param[in] input �Է°�(����)
/// @param[in] inputLength �Է°��� ����
/// @param[in] macValue HMAC ������
/// @param[in] macValueLength HMAC ����
EXPORT_API int CryptoHMacVerify(void* context, unsigned char* input, unsigned int inputLength, unsigned char* macValue, unsigned int macValueLength)
{
	int rv = EC_SUCCESS;
	CRYPTO_CONTEXT* ctx = NULL;

	/// ��ȣ��� ����üũ(��ȣ����� �ɰ��� ���������� ��� ���¿����ڵ带 ���)
	if (g_module_state == STATE_INABILITY_ERROR)
	{
		return EC_STATE;
	}

	/// ��ȣ��� ����üũ(��ȣ����� ����� ���°� �ƴ� ��� ���¿����ڵ带 ���)
	if (g_module_state != STATE_CMVP_KEY_SET && g_module_state != STATE_CMVP_OPERATION)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_STATE;
	}

	/// �Էµ����� ���İ���
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
	
	/// HMAC ���� �˰��� ����
	 rv = test_hmac_sha256(ctx->algo, input, inputLength, key, keyLen, macValue, macValueLength);
	if (rv != EC_SUCCESS)
	{
		SetState(STATE_CMVP_ERROR);
	}
	else
	{
		SetState(STATE_CMVP_OPERATION);
	}

	// ����ȭ ����

	return rv;
}


/// @fn int CryptoRSAEncrypt(void* context, unsigned char* publickey, unsigned int publickeyLength, unsigned char* exponent, unsigned int exponentLength, unsigned char* input, unsigned int inputLength, unsigned char* output, unsigned char* seed, unsigned int seedLength, unsigned int shaFlag)
/// @brief RSA_OAEP ����� ����� ��ȣȭ
/// @return ��ȣ��� ����
/// @param[in] context �˰��� ������ ��� �ִ� ����ü
/// @param[in] publickey ��ȣȭ�� ���� ����Ű
/// @param[in] publickeyLength ����Ű ����
/// @param[in] exponent ��ȣȭ�� ���� ����Ű ����
/// @param[in] exponentLength ����Ű ���� ����
/// @param[in] input ��ȣȭ ����� �Ǵ� �� �Է°�
/// @param[in] inputLength �Է°� ����
/// @param[out] output ������ ��ȣ���� ����� �Ű�����
/// @param[in] seed ��ȣ���� ���� �ʱ� SEED��(NULL �Է½� ���ο��� ���� ����)
/// @param[in] seedLength seed�� ����
 /* 
EXPORT_API int CryptoRSAEncrypt(void* context, unsigned char* publickey, unsigned int publickeyLength,
	unsigned char* exponent, unsigned int exponentLength,
	unsigned char* input, unsigned int inputLength,
	unsigned char* output, unsigned char* seed, unsigned int seedLength)
{
	int rv = EC_SUCCESS;
	CRYPTO_CONTEXT* ctx = NULL;

	/// ��ȣ��� ����üũ(��ȣ����� �ɰ��� ���������� ��� ���¿����ڵ带 ���)
	if (g_module_state == STATE_INABILITY_ERROR)
	{
		return EC_STATE;
	}

	/// ��ȣ��� ����üũ(��ȣ����� ����� ���°� �ƴ� ��� ���¿����ڵ带 ���)
	if (g_module_state != STATE_CMVP_INIT && g_module_state != STATE_CMVP_OPERATION)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_STATE;
	}

	/// �Էµ����� ���İ���
	if (context == NULL)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_INITIALIZE_NO;
	}
	ctx = (CRYPTO_CONTEXT*)context;

	SetState(STATE_CMVP_KEY_SET);
	SetState(STATE_CMVP_OPERATION);

	/// �޽��� ũ�� Ȯ��
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

	/// �Էµ� �Ű������� �̿��� RSA ��ȣȭ �˰��� ����
	if (rv != EC_SUCCESS)
	{
		SetState(STATE_CMVP_ERROR);
	}
	else
	{
		SetState(STATE_CMVP_OPERATION);
	}

	// ����ȭ ����

	return rv;
}
*/


/// @fn int CryptoRSADecrypt(void* context, unsigned char* privatekey, unsigned int privatekeyLength, unsigned char* publickey, unsigned int publickeyLength, unsigned char* input, unsigned int inputLength, unsigned char* output, unsigned int* outputLength)
/// @brief RSA_OAEP ����� ����� ��ȣȭ
/// @return ��ȣ��� ����
/// @param[in] context �˰��� ������ ��� �ִ� ����ü
/// @param[in] privatekey ��ȣȭ�� ���� ����Ű
/// @param[in] privatekeyLength ����Ű ����
/// @param[in] publickey ��ȣȭ�� ���� ����Ű
/// @param[in] publickeyLength ����Ű ����
/// @param[in] input ��ȣȭ ����� �Ǵ� ��ȣ�� �Է°�
/// @param[in] inputLength �Է°� ����
/// @param[out] output ��ȣȭ�� ���� ����� �Ű�����
/// @param[out] outputLength ��ȣȭ�� ���� ����
/*
EXPORT_API int CryptoRSADecrypt(void* context, unsigned char* privatekey, unsigned int privatekeyLength,
	unsigned char* publickey, unsigned int publickeyLength,
	unsigned char* input, unsigned int inputLength,
	unsigned char* output, unsigned int* outputLength)
{
	int rv = EC_SUCCESS;
	CRYPTO_CONTEXT* ctx = NULL;

	/// ��ȣ��� ����üũ(��ȣ����� �ɰ��� ���������� ��� ���¿����ڵ带 ���)
	if (g_module_state == STATE_INABILITY_ERROR)
	{
		return EC_STATE;
	}

	/// ��ȣ��� ����üũ(��ȣ����� ����� ���°� �ƴ� ��� ���¿����ڵ带 ���)
	if (g_module_state != STATE_CMVP_INIT && g_module_state != STATE_CMVP_OPERATION)
	{
		SetState(STATE_CMVP_ERROR);
		return EC_STATE;
	}

	/// �Էµ����� ���İ���
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

	/// ��ȣ�� C���� |C| = |n|
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
	/// �Էµ� �Ű������� �̿��� RSA ��ȣȭ �˰��� ����
	if (rv != EC_SUCCESS)
	{
		SetState(STATE_CMVP_ERROR);
	}
	else
	{
		SetState(STATE_CMVP_OPERATION);
	}

	// ����ȭ ����

	return rv;
}
*/

int test_hmac_sha256() {
	/* === �׽�Ʈ ����(����ڰ� �� ����) === */
	unsigned char msg[1024] = { 0, }, key[1024] = { 0, }, expected_hmac[32] = { 0, }, hmac[32];
	unsigned int msgLen = 0, keyLen = 0, outputLen = 0, ret = 0;
	//void HMAC_SHA256(const u8* message, u32 mlen, const u8* key, u32 klen, u8 hmac[SHA256_DIGEST_VALUELEN]);

	keyLen = asc2hex(key, "C6F1D667A50AAEBA5A200A0A7CC24FFBB24984426AB8ABACCEE75162F3E1646B");
	msgLen = asc2hex(msg, "548A457280851ECA0F5476AFDAC102CF6C7DBE09B3083D74FBD03DA31E9D7F27F42CD656111A7D4BB005AD2EEAED6FB62CE0B0EBE7D6933189DA0B82AD6AA8FB8E21B19AC29374462579DA0F130E3EB8DAB87F726EEB54EB5F4AE087091087ED0BAFFFC6FAB7AAC156F823DBBCEB17DD5E4E5626B10F29AA656BE73B9A57C308");
	outputLen = asc2hex(expected_hmac, "96C37F36CA0DEA3B2B3E60F1F6CDF79CFF72CA2A43A091C8105AE882A690EF2F");

	/* === ��ȣȭ ���� === */
	int rv = EC_SUCCESS;
	rv = HMAC_SHA256(msg, msgLen, key, keyLen, hmac);
	if (rv != EC_SUCCESS)
	{
		SetState(STATE_CMVP_ERROR);
	}

	/* === ��ȣȭ ������� === */
	if (memcmp(hmac, expected_hmac, 16) == 0) {
		return EC_SUCCESS;  // ��ȣ�� ��ġ
	}
	else {
		return EC_HMAC_VERIFY;  // ��ȣ�� ����ġ
	}
}

int test_aria() {
	/* === �׽�Ʈ ����(����ڰ� �� ����) === */
	/* �� */
	Byte p[16] = {
		0x11, 0x11, 0x11, 0x11, 0xaa, 0xaa, 0xaa, 0xaa,
		0x11, 0x11, 0x11, 0x11, 0xbb, 0xbb, 0xbb, 0xbb
	};

	/* 192��Ʈ Ű (mk[0..23] ���) */
	Byte mk[32];
	for (int i = 0; i < 16; i++) mk[i] = (Byte)(i * 0x11);        /* 00,11,22,...,FF */
	for (int i = 16; i < 24; i++) mk[i] = (Byte)((i - 16) * 0x11);/* 00..77 */
	for (int i = 24; i < 32; i++) mk[i] = 0; /* ������ 0���� Ŭ���� */

	/* ��� ��ȣ�� */
	const Byte expected[16] = {
		0x8d, 0x14, 0x70, 0x62, 0x5f, 0x59, 0xeb, 0xac,
		0xb0, 0xe5, 0x5b, 0x53, 0x4b, 0x3e, 0x46, 0x2b
	};

	/* === ��ȣȭ ���� === */
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

	/* === ��ȣȭ ������� === */
	if (memcmp(out, expected, 16) == 0) {
		return EC_SUCCESS;  // ��ȣ�� ��ġ
	}
	else {
		return EC_ARIA_VERIFY_ERROR;  // ��ȣ�� ����ġ
	}
}

/// @fn int CoreFunctionTest()
/// @brief �ٽɱ�ɽ��� �������̽� �Լ�, ��������׽�Ʈ(KAT) �˻縦 �����Ͽ� ����ؾ� ��ȣ����� ����� �� �ִ�.
/// @return ��ȣ��� ����
EXPORT_API int SecureACoreFunctionTest()
{
	int rv = EC_SUCCESS;
	unsigned char random_output[32] = { 0, };

	// SHA256�׽�Ʈ�� HMAC_SHA256 �׽�Ʈ�� ���ԵǹǷ� ��ü��
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

	/// GetModuleFileName() ���� �̿��Ͽ� ���� �������� ����� ��θ� Ȯ��
	GetModuleFileName(
		hModule,	/// ���� ����ǰ� �ִ� ����� �ڵ�, �Ǵ� NULL(�ڽ��� ������ ��ȯ)
		moduleName,  /// ���� ��θ� ���� ������
		MAX_PATH			/// ���� ��ΰ� �� ������ ����
	);

	// ��ȣ��� �� ���Ե� Mac�� ����
	//module_macValue = sudo_getModule_macData();

	// Mac�� ������ ���� Ű ����
	//key = sudo_getMacKey();

	// ��ȣ��� ���Ͽ� ���� ���Ἲ ������(Mac�� ����)
	//Mac(output, outputLenth, modulefile, modulefileLength, key, keyLength, alg);

	if (memcmp(output, module_macValue, (size_t)outputLenth) != 0) {
		return EC_INTEGRITY_VERIFY;
	}

	return EC_SUCCESS;
}

/// @fn int CryptoGetLastErrorCode()
/// @brief ��ȣ����� ������ �����ڵ带 ����
/// @return ��ȣ����� ������ �����ڵ带 ����
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