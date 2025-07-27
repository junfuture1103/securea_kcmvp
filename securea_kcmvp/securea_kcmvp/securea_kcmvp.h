/// @file sample_kcmvp.h
/// @section intro �Ұ�
/// - �Ұ� : 
/// @section Program ���α׷���
/// - ���α׷��� : KCMVP API Interface ���
/// - ���α׷����� : ��ȣ����� �ܺ� �������̽��� �����Ѵ�.
/// @section CREATEINFO �ۼ�����
/// - �ۼ���  : 
/// - �ۼ���  : 
/// @date 2023-06-01
/// @section MODIFYINFO ��������
/// - ������/������ : 
/// - 2023-06-01/Author Name : ��������
/// 
#pragma once

/// @brief ��ȣ����� ����
#define	VERSION "V0.9.0"

/// @brief ��ȣ����� �˰����� �����Ѵ�.
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

/// @brief ��Ͼ�ȣ�� MODE�� �����Ѵ�.
#define CIPHER_MODE_ECB			1	
#define CIPHER_MODE_CBC			2
#define CIPHER_MODE_CFB			3
#define CIPHER_MODE_OFB			4
#define CIPHER_MODE_CTR			5



/// @brief ��ȣ����� �����ڵ带 �����Ѵ�.
#define EC_SUCCESS				0		/// ��������
#define EC_STATE				1		/// ��ȣ��� ���¿���
#define EC_ALGO					2		/// �˰��� �Է°� ����(���ǵ��� ���� ALGO)
#define EC_MODE					3		/// MODE �Է°� ����(���ǵ��� ���� MODE)
#define EC_INITIALIZE_NO		4		/// �ʱ�ȭ ����(��ȣ����� �ʱ�ȭ ���� ���� ����)
#define EC_KEY_LEN				5		/// KEY �Է°� ����(����)
#define EC_KEY_VALUE			6		/// KEY �Է°� ����(������ NULL)
#define EC_INPUT_LEN			7		/// Input ������ �Է°� ����(����)
#define EC_INPUT_VALUE			8		/// Input ������ �Է°� ����(������ NULL)
#define EC_OUTPUT_INIT			9		/// Output ������ �Է°� ����(������ ���Ҵ�)
#define EC_HMAC_VERIFY			10		/// HMAC ���� ����
#define EC_PSS_VERIFY_ERROR		11		/// RSA ���� ����
#define EC_SELFTEST_ERROR		12		/// �ڰ�����(�ٽɱ�ɽ���) ����
#define EC_INTEGRITY_VERIFY		13		/// �ڰ�����(���Ἲ����) ����
#define EC_DATA_NULL			14		/// ����ü �Է°� ����(NULL)

/// @brief ��ȣ����� ���¸� �����Ѵ�.
#define	STATE_POWER_ON					1		/// ��������
#define	STATE_POWER_OFF					2		/// ��������
#define	STATE_SELFTEST					3		/// �ڰ�����(�����ΰ� ����)
#define	STATE_CMVP_FINAL				4		/// �������
#define	STATE_INABILITY_ERROR			5		/// �ɰ��� ����
#define	STATE_CMVP_READY				6		/// ������� ���۸��
#define	STATE_CMVP_KEY_SET				7		/// �ٽɺ��ȸŰ����� ����
#define	STATE_CMVP_ERROR				8		/// ������� ��ȣ� ����
#define	STATE_CMVP_OPERATION			9		/// �����
#define STATE_CMVP_CONDITION			10		/// �ڰ�����(���Ǻ� ����)
#define STATE_CMVP_INIT					11		/// ���� ����
#define STATE_CMVP_SUCCESS				12		/// ���輺�� ����

#define EXPORT_API __declspec(dllexport)

/// @struct CRYPTO_CONTEXT
/// @brief ��ȣ��⳻���� ����� �˰���, ���, Ű, �ʱ�ȭ���Ͱ��� �����ϰ� �ִ� ����ü
typedef struct _CRYPTO_CONTEXT {
	unsigned int algo;				/// �˰��� ����
	unsigned int mode;				/// ��Ͼ˰��� ���
	unsigned char key[256];			/// Ű ���� ����
	unsigned int keyLen;			/// Ű ����
	unsigned char iv[16];			/// �ʱ⺤�� ���� ����
	unsigned int ivLen;				/// �ʱ⺤�� ����
} CRYPTO_CONTEXT;

/// @brief �������̽� �Լ� ����
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