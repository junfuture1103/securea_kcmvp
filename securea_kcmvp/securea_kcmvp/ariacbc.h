/*!
 * \file aria.h
 * \brief ARIA ��ȣ �˰��� ( ����ǥ�� :  KS X 1213:2004 )
 * \author
 * Copyright (c) 2011 by \<KISA\>
 */

#ifndef HEADER_ARIA_H
#define HEADER_ARIA_H

#define ARIA_ENCRYPT	1			/*!< ARIA�� ��ȣȭ*/
#define ARIA_DECRYPT	0			/*!< ARIA�� ��ȣȭ*/

#define ARIA_BLOCK_SIZE	16			/*!< ARIA�� BLOCK_SIZE*/

#define ARIA128 128
#define ARIA192 192
#define ARIA256 256

#define ARIA128_KEY_SIZE		16					
#define ARIA192_KEY_SIZE		24					
#define ARIA256_KEY_SIZE		32

#define ARIA128_IV_SIZE			ARIA_BLOCK_SIZE		

#define ARIA_MAXKB	32
#define ARIA_MAXNR	16
#define ARIA_WORD_SIZE  4


#ifdef  __cplusplus
extern "C" {
#endif


	/*!
	 * \brief
	 * ARIA Key ����ü
	 */
	typedef struct kisa_aria_key_st {
		unsigned char rk[ARIA_MAXNR * (ARIA_MAXNR + 1)];
		int nr;
	} KISA_ARIA_KEY;


	/*!
	 * \brief
	 * ARIA ��ȣȭ �˰��� CBC ���� ������ ���� ���� ����ü
	 */
	typedef struct kisa_aria_cbc_info_st {
		int				encrypt;							/*!< ��ȣȭ/��ȣȭ ��� ������*/
		unsigned char	ivec[ARIA_BLOCK_SIZE];				/*!< �ʱ� ����*/
		KISA_ARIA_KEY	ariakey;
		unsigned char	cbc_buffer[ARIA_BLOCK_SIZE];		/*!< ���� ����*/
		int				buffer_length;						/*!< ���� ������ ����*/
		unsigned char	cbc_last_block[ARIA_BLOCK_SIZE];	/*!< CBC ���� ����*/
		int				last_block_flag;					/*!< CBC ���� ���� ��� ����*/
	} KISA_ARIA_CBC_INFO;


	void KISA_ARIA_encrypt_init(const unsigned char* userkey, int keyBits, KISA_ARIA_KEY* ariakey);
	void KISA_ARIA_decrypt_init(const unsigned char* userkey, int keyBits, KISA_ARIA_KEY* ariakey);
	void KISA_ARIA_process_block(const unsigned char* in, unsigned char* out, KISA_ARIA_KEY* ariakey);

	int KISA_ARIA_CBC_init(KISA_ARIA_CBC_INFO* info, int encrypt, int bits, unsigned char* user_key, unsigned char* iv);
	int KISA_ARIA_CBC_process(KISA_ARIA_CBC_INFO* info, unsigned char* in, int inLen, unsigned char* out, int* outLen);
	int KISA_ARIA_CBC_close(KISA_ARIA_CBC_INFO* info, unsigned char* out, int* outLen);


	/*!
 * \brief
 * ARIA 128bit CBC ��ȣȭ �Լ�. �־��� �Է¿� ���� ��ȣȭ�� ó��(CBC���, PKCS�е�)
 *
 * \param userkey
 * ����� �Է� Ű(16 bytes)
 *
 * \param iv
 * ����� �Է� �ʱ� ���� (16 bytes)
 *
 * \param in
 * ��ȣȭ �Ϸ��� �Է�
 *
 * \param len
 * �Է� �������� ����
 *
 * \param out
 * ��ȣ���� ��ϵ� ��� ����
 *
 * \returns
 * ���� ������ : ��ȣ�� ����� ���� / �޸𸮰� ������ �Ҵ���� �ʾ��� ��� (0)
 *
 * \remarks
 * ��¹��� out�� �Է¹����� ���̴� (len+16) bytes �̻� �̸� �Ҵ�Ǿ� �־�� ������
 *
 */
	int KISA_ARIA128_CBC_ENCRYPT(unsigned char* userkey,
		unsigned char* iv,
		unsigned char* in,
		unsigned int   len,
		unsigned char* out);

	/*!
	 * \brief
	 * ARIA 128bit CBC ��ȣȭ �Լ�. �־��� �Է¿� ���� ��ȣȭ�� ó��(CBC���, PKCS�е�)
	 *
	 * \param userkey
	 * ����� �Է� Ű(16 bytes)
	 *
	 * \param iv
	 * ����� �Է� �ʱ� ���� (16 bytes)
	 *
	 * \param in
	 * ��ȣȭ �Ϸ��� �Է�
	 *
	 * \param len
	 * �Է� �������� ����
	 *
	 * \param out
	 * ��ȣȭ�� ���� ��ϵ� ��� ����
	 *
	 * \returns
	 * ���� ������ : �� ����� ���� / �޸𸮰� ������ �Ҵ���� �ʾ��� ��� �Ǵ� �߸��� ��ȣ�� (0)
	 *
	 * \remarks
	 * ��¹��� out�� �Է¹����� ���� len�� ���� �̸� �Ҵ�Ǿ� �־�� ������
	 *
	 */
	int KISA_ARIA128_CBC_DECRYPT(unsigned char* userkey,
		unsigned char* iv,
		unsigned char* in,
		unsigned int   len,
		unsigned char* out);

	/*!
 * \brief
 * ARIA 192bit CBC ��ȣȭ �Լ�. �־��� �Է¿� ���� ��ȣȭ�� ó��(CBC���, PKCS�е�)
 *
 * \param userkey
 * ����� �Է� Ű(24 bytes)
 *
 * \param iv
 * ����� �Է� �ʱ� ���� (16 bytes)
 *
 * \param in
 * ��ȣȭ �Ϸ��� �Է�
 *
 * \param len
 * �Է� �������� ����
 *
 * \param out
 * ��ȣ���� ��ϵ� ��� ����
 *
 * \returns
 * ���� ������ : ��ȣ�� ����� ���� / �޸𸮰� ������ �Ҵ���� �ʾ��� ��� (0)
 *
 * \remarks
 * ��¹��� out�� �Է¹����� ���̴� (len+16) bytes �̻� �̸� �Ҵ�Ǿ� �־�� ������
 *
 */
	int KISA_ARIA192_CBC_ENCRYPT(unsigned char* userkey,
		unsigned char* iv,
		unsigned char* in,
		unsigned int   len,
		unsigned char* out);

	/*!
	 * \brief
	 * ARIA 192bit CBC ��ȣȭ �Լ�. �־��� �Է¿� ���� ��ȣȭ�� ó��(CBC���, PKCS�е�)
	 *
	 * \param userkey
	 * ����� �Է� Ű(24 bytes)
	 *
	 * \param iv
	 * ����� �Է� �ʱ� ���� (16 bytes)
	 *
	 * \param in
	 * ��ȣȭ �Ϸ��� �Է�
	 *
	 * \param len
	 * �Է� �������� ����
	 *
	 * \param out
	 * ��ȣȭ�� ���� ��ϵ� ��� ����
	 *
	 * \returns
	 * ���� ������ : �� ����� ���� / �޸𸮰� ������ �Ҵ���� �ʾ��� ��� �Ǵ� �߸��� ��ȣ�� (0)
	 *
	 * \remarks
	 * ��¹��� out�� �Է¹����� ���� len�� ���� �̸� �Ҵ�Ǿ� �־�� ������
	 *
	 */
	int KISA_ARIA192_CBC_DECRYPT(unsigned char* userkey,
		unsigned char* iv,
		unsigned char* in,
		unsigned int   len,
		unsigned char* out);

	/*!
 * \brief
 * ARIA 256bit CBC ��ȣȭ �Լ�. �־��� �Է¿� ���� ��ȣȭ�� ó��(CBC���, PKCS�е�)
 *
 * \param userkey
 * ����� �Է� Ű(32 bytes)
 *
 * \param iv
 * ����� �Է� �ʱ� ���� (16 bytes)
 *
 * \param in
 * ��ȣȭ �Ϸ��� �Է�
 *
 * \param len
 * �Է� �������� ����
 *
 * \param out
 * ��ȣ���� ��ϵ� ��� ����
 *
 * \returns
 * ���� ������ : ��ȣ�� ����� ���� / �޸𸮰� ������ �Ҵ���� �ʾ��� ��� (0)
 *
 * \remarks
 * ��¹��� out�� �Է¹����� ���̴� (len+16) bytes �̻� �̸� �Ҵ�Ǿ� �־�� ������
 *
 */
	int KISA_ARIA256_CBC_ENCRYPT(unsigned char* userkey,
		unsigned char* iv,
		unsigned char* in,
		unsigned int   len,
		unsigned char* out);

	/*!
	 * \brief
	 * ARIA 256bit CBC ��ȣȭ �Լ�. �־��� �Է¿� ���� ��ȣȭ�� ó��(CBC���, PKCS�е�)
	 *
	 * \param userkey
	 * ����� �Է� Ű(32 bytes)
	 *
	 * \param iv
	 * ����� �Է� �ʱ� ���� (16 bytes)
	 *
	 * \param in
	 * ��ȣȭ �Ϸ��� �Է�
	 *
	 * \param len
	 * �Է� �������� ����
	 *
	 * \param out
	 * ��ȣȭ�� ���� ��ϵ� ��� ����
	 *
	 * \returns
	 * ���� ������ : �� ����� ���� / �޸𸮰� ������ �Ҵ���� �ʾ��� ��� �Ǵ� �߸��� ��ȣ�� (0)
	 *
	 * \remarks
	 * ��¹��� out�� �Է¹����� ���� len�� ���� �̸� �Ҵ�Ǿ� �־�� ������
	 *
	 */
	int KISA_ARIA256_CBC_DECRYPT(unsigned char* userkey,
		unsigned char* iv,
		unsigned char* in,
		unsigned int   len,
		unsigned char* out);




#ifdef  __cplusplus
}
#endif
#endif /* HEADER_ARIA_H */

