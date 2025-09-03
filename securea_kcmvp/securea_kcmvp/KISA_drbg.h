/*!
 * \file ctr_drbg.h
 * \brief CTR-DRBG �˰��� ���� (NIST 800-90)
 * \author
 * Copyright (c) 2011 by \<KISA\>
 */

#ifndef CTR_DRBG_H
#define CTR_DRBG_H

#ifdef  __cplusplus
extern "C" {
#endif

	//------------------------------------------------
#define ALGO_SEED								1
#define ALGO_ARIA128							2
#define ALGO_ARIA192							3
#define ALGO_ARIA256							4

//------------------------------------------------
#define ALGO_SEED_OUTLEN_IN_BYTES				16
#define ALGO_ARIA128_OUTLEN_IN_BYTES			16
#define ALGO_ARIA192_OUTLEN_IN_BYTES			16
#define ALGO_ARIA256_OUTLEN_IN_BYTES			16

//------------------------------------------------
#define ALGO_SEED_KEYLEN_IN_BYTES				16
#define ALGO_ARIA128_KEYLEN_IN_BYTES			16
#define ALGO_ARIA192_KEYLEN_IN_BYTES			24
#define ALGO_ARIA256_KEYLEN_IN_BYTES			32

//------------------------------------------------
#define ALGO_SEED_SECURITY_STRENGTH_IN_BYTES	16
#define ALGO_ARIA128_SECURITY_STRENGTH_IN_BYTES	16
#define ALGO_ARIA192_SECURITY_STRENGTH_IN_BYTES	24
#define ALGO_ARIA256_SECURITY_STRENGTH_IN_BYTES	32

//------------------------------------------------
#define ALGO_SEED_SEEDLEN_IN_BYTES				ALGO_SEED_OUTLEN_IN_BYTES + ALGO_SEED_KEYLEN_IN_BYTES
#define ALGO_ARIA128_SEEDLEN_IN_BYTES			ALGO_ARIA128_OUTLEN_IN_BYTES + ALGO_ARIA128_KEYLEN_IN_BYTES
#define ALGO_ARIA192_SEEDLEN_IN_BYTES			ALGO_ARIA192_OUTLEN_IN_BYTES + ALGO_ARIA192_KEYLEN_IN_BYTES
#define ALGO_ARIA256_SEEDLEN_IN_BYTES			ALGO_ARIA256_OUTLEN_IN_BYTES + ALGO_ARIA256_KEYLEN_IN_BYTES

//------------------------------------------------
#define MAX_V_LEN_IN_BYTES						16
#define MAX_Key_LEN_IN_BYTES					32
#define MAX_SEEDLEN_IN_BYTES					ALGO_ARIA256_SEEDLEN_IN_BYTES

//------------------------------------------------
#define MIN_ENTROPY_INPUT_LEN_IN_BYTES			// Depends on SECURITY_STRENGTH of each algorithm

//------------------------------------------------
#define MAX_NUM_INPUT_OF_BYTES_PER_REQUEST		0x10000			// 2^19 bits

//------------------------------------------------
// The following values are too huge to apply on the current architectures,
// thus we do not consider the maximum length of either input or entropy.
#define MAX_ENTROPY_INPUT_LEN_IN_BYTES			0x100000000		// 2^35 bits
#define MAX_PERSONALIZED_STRING_LEN_IN_BYTES	0x100000000		// 2^35 bits
#define MAX_ADDITIONAL_INPUT_LEN_IN_BYTES		0x100000000		// 2^35 bits
#define NUM_OF_REQUESTS_BETWEEN_RESEEDS			0x1000000000000UL// 2^48 bits

#define STATE_INITIALIZED_FLAG					0xFE12DC34

//------------------------------------------------
// The following values define either using derivation-function or not
// when KISA_CTR_DRBG_Instantiate(..., unsigned char derivation_function_flag) is called.
#define NON_DERIVATION_FUNCTION					0x00
#define USE_DERIVATION_FUNCTION					0xFF


#ifdef WIN32
	typedef unsigned __int64	uint64;
#else
	typedef unsigned long long	uint64;
#endif

	/*!
	 * \brief
	 * CTR DRBG ������ ���� ���� ���� ����ü (STATE)
	 */
	typedef struct ctr_drbg_state {
		unsigned char	algo; /*!< ALGO_SEED / ALGO_ARIA128 / ALGO_ARIA192 / ALGO_ARIA256 */
		unsigned char	V[MAX_V_LEN_IN_BYTES];
		int				Vlen;
		unsigned char	Key[MAX_Key_LEN_IN_BYTES];
		int				Keylen;
		int				seedlen;
		uint64			reseed_counter;
		int				security_strength;
		int				initialized_flag;		  // If initialized_flag = STATE_INITIALIZED_FLAG, state is already initialized.
		unsigned char	derivation_function_flag; // 0x00 : non-df ,  0xFF : use df
	}KISA_CTR_DRBG_STATE;



	/*!
	 * \brief
	 * CTR DRBG �ʱ�ȭ �Լ�. ���� ������ ���ؼ��� �ݵ�� �ʱ�ȭ�� �ʿ�
	 *
	 * \param state
	 * ������ ��� �ִ� KISA_CTR_DRBG_STATE ����ü
	 *
	 * \param algo
	 * ���ο��� ���� ��ĪŰ ��ȣ�� ���� (ALGO_SEED / ALGO_ARIA128 / ALGO_ARIA192 / ALGO_ARIA256 �� ����)
	 *
	 * \param entropy_input
	 * ���� ���� �ʱ�ȭ�� ���� ��Ʈ���� ���� �Է�
	 * (���̴� ����ϴ� ��ĪŰ ��ȣ�� ALGO_XXX_SECURITY_STRENGTH_IN_BYTES �̻��� �Է��ؾ���)
	 * (i.e. SEED : 16 bytes / ARIA128 : 16 bytes / ARIA192 : 24 bytes / ARIA256 : 32 bytes �̻�)
	 * (Derivation Function�� ������� ���� ��쿡�� ALGO_xxx_SEEDLEN_IN_BYTES �̻��� �Է��ؾ� ��)
	 *
	 * \param entropylen
	 * �Է��ϴ� ��Ʈ������ ���� (bytes ����)
	 *
	 * \param nonce
	 * ���� ���� �ʱ�ȭ�� ���� Nonce �Է�
	 * (�Է� ����ȣ�� security strength ���� �̻��� �Է��ؾ� ��)
	 *
	 * \param noncelen
	 * �Է��ϴ� ��Ʈ������ ���� (bytes ����)
	 *
	 * \param personalization_string
	 * ����� ���� ��Ʈ�� �Է�(�ɼ�). �Է����� ���� ��� NULL
	 *
	 * \param stringlen
	 * ����� ���� ��Ʈ���� ����. NULL�� ��� ���̸� 0���� �Է�
	 *
	 * \param derivation_function_flag
	 * �Է��ϴ� ��Ʈ���� ������ Full Entropy�� ��� : NON_DERIVATION_FUNCTION /
	 * �Է��ϴ� ��Ʈ���� ������ Full Entropy�� �ƴ� ��� : USE_DERIVATION_FUNCTION
	 *
	 * \returns
	 * �ʱ�ȭ ���� (1) / ���� (0)
	 */
	int KISA_CTR_DRBG_Instantiate(KISA_CTR_DRBG_STATE* state,
		unsigned char algo,
		unsigned char* entropy_input, int entropylen,
		unsigned char* nonce, int noncelen,
		unsigned char* personalization_string, int stringlen,
		unsigned char derivation_function_flag
	);



	/*!
	 * \brief
	 * CTR DRBG ���� ���� �Լ�. �ݵ�� KISA_CTR_DRBG_Instantiate ���� ���Ŀ� ���� ����
	 *
	 * \param state
	 * ������ ��� �ִ� KISA_CTR_DRBG_STATE ����ü
	 *
	 * \param output
	 * ������ ������ �ԷµǴ� ����
	 *
	 * \param request_num_of_bits
	 * ������ ������ ���� (bits) ����
	 *
	 * \param additional_input
	 * �ΰ����� �����õ� �Է�(�ɼ�). �Է����� ���� ��� NULL
	 *
	 * \param addlen
	 * ����� ���� ��Ʈ���� ����. NULL�� ��� ���̸� 0���� �Է�
	 *
	 *
	 * \returns
	 * ���� (1) / ���� (0)
	 */
	int KISA_CTR_DRBG_Generate(KISA_CTR_DRBG_STATE* state,
		unsigned char* output, int request_num_of_bits,
		unsigned char* addtional_input, int addlen
	);


	/*!
	 * \brief
	 * CTR DRBG �� �ʱ�ȭ �Լ�(�ʿ��). KISA_CTR_DRBG_Instantiate�� ������ ������Ų ���Ŀ� ��� ����
	 *
	 * \param state
	 * ������ ��� �ִ� KISA_CTR_DRBG_STATE ����ü
	 *
	 * \param entropy_input
	 * ���� ���� �ʱ�ȭ�� ���� ��Ʈ���� ���� �Է�
	 * (���̴� ����ϴ� ��ĪŰ ��ȣ�� ALGO_XXX_SECURITY_STRENGTH_IN_BYTES �̻��� �Է��ؾ���)
	 * (i.e. SEED : 16 bytes / ARIA128 : 16 bytes / ARIA192 : 24 bytes / ARIA256 : 32 bytes �̻�)
	 * (Derivation Function�� ������� ���� ��쿡�� ALGO_xxx_SEEDLEN_IN_BYTES �̻��� �Է��ؾ� ��)
	 *
	 * \param entropylen
	 * �Է��ϴ� ��Ʈ������ ���� (bytes ����)
	 *
	 * \param additional_input
	 * �ΰ����� �����õ� �Է�(�ɼ�). �Է����� ���� ��� NULL
	 *
	 * \param addlen
	 * ����� ���� ��Ʈ���� ����. NULL�� ��� ���̸� 0���� �Է�
	 *
	 *
	 * \returns
	 * ���� (1) / ���� (0)
	 */
	int KISA_CTR_DRBG_Reseed(KISA_CTR_DRBG_STATE* state,
		unsigned char* entropy_input, int entropylen,
		unsigned char* additional_input, int addlen
	);

#ifdef  __cplusplus
}
#endif

#endif