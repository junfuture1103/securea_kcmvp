/**
@file KISA_SHA_256.h
@brief SHA256 ��ȣ �˰���
@author Copyright (c) 2013 by KISA
@remarks http://seed.kisa.or.kr/
*/

#ifndef SHA256_H
#define SHA256_H

#ifdef  __cplusplus
extern "C" {
#endif

#ifndef OUT
#define OUT
#endif

#ifndef IN
#define IN
#endif

#ifndef INOUT
#define INOUT
#endif

#undef BIG_ENDIAN
#undef LITTLE_ENDIAN

#if defined(USER_BIG_ENDIAN)
#define BIG_ENDIAN
#elif defined(USER_LITTLE_ENDIAN)
#define LITTLE_ENDIAN
#else
#if 0
#define BIG_ENDIAN
#elif defined(_MSC_VER)
#define LITTLE_ENDIAN
#else
#error
#endif
#endif

	typedef unsigned long KISA_ULONG;
	typedef KISA_ULONG* KISA_ULONG_PTR;

	typedef unsigned int KISA_UINT;
	typedef KISA_UINT* KISA_UINT_PTR;

	typedef signed int KISA_SINT;
	typedef KISA_SINT* KISA_SINT_PTR;

	typedef unsigned char KISA_UCHAR;
	typedef KISA_UCHAR* KISA_UCHAR_PTR;

	typedef unsigned char KISA_BYTE;

#define SHA256_DIGEST_BLOCKLEN	64
#define SHA256_DIGEST_VALUELEN	32

	typedef struct {
		KISA_UINT uChainVar[SHA256_DIGEST_VALUELEN / 4];
		KISA_UINT uHighLength;
		KISA_UINT uLowLength;
		KISA_UINT remain_num;
		KISA_BYTE szBuffer[SHA256_DIGEST_BLOCKLEN];
	} SHA256_INFO;

	/**
	@brief ���⺯���� ���̺����� �ʱ�ȭ�ϴ� �Լ�
	@param Info : SHA256_Process ȣ�� �� ���Ǵ� ����ü
	*/
	void SHA256_Init(OUT SHA256_INFO* Info);

	/**
	@brief ���⺯���� ���̺����� �ʱ�ȭ�ϴ� �Լ�
	@param Info : SHA256_Init ȣ���Ͽ� �ʱ�ȭ�� ����ü(���������� ���ȴ�.)
	@param pszMessage : ����� �Է� ��
	@param inLen : ����� �Է� �� ����
	*/
	void SHA256_Process(OUT SHA256_INFO* Info, IN const KISA_BYTE* pszMessage, IN KISA_UINT uDataLen);

	/**
	@brief �޽��� �����̱�� ���� �����̱⸦ ������ �� ������ �޽��� ����� ������ �����Լ��� ȣ���ϴ� �Լ�
	@param Info : SHA256_Init ȣ���Ͽ� �ʱ�ȭ�� ����ü(���������� ���ȴ�.)
	@param pszDigest : ��ȣ��
	*/
	void SHA256_Close(OUT SHA256_INFO* Info, OUT KISA_BYTE* pszDigest);

	/**
	@brief ����� �Է� ���� �ѹ��� ó��
	@param pszMessage : ����� �Է� ��
	@param pszDigest : ��ȣ��
	@remarks ���������� SHA256_Init, SHA256_Process, SHA256_Close�� ȣ���Ѵ�.
	*/
	int SHA256_Encrpyt(IN const KISA_BYTE* pszMessage, IN KISA_UINT uPlainTextLen, OUT KISA_BYTE* pszDigest);

#ifdef  __cplusplus
}
#endif

#endif