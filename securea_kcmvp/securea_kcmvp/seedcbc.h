/*!
 * \file seed.h
 * \brief SEED ��ȣ �˰��� (����ǥ�� : TTAS.KO-12.0004 : 128��Ʈ ��Ͼ�ȣ�˰���(SEED))
 * \author
 * Copyright (c) 2010 by \<KISA\>
 */
#ifndef KISA_SEED_H
#define KISA_SEED_H

#ifdef  __cplusplus
extern "C" {
#endif

#define SEED_BLOCK_SIZE 16			/*!< SEED �� ũ��*/
#define SEED_ENCRYPT	1			/*!< SEED ��ȣȭ ���*/
#define SEED_DECRYPT	0			/*!< SEED ��ȣȭ ���*/

	/*!
	 * \brief
	 * SEED ���� ���� ��ȣȭ�� ���� SEED Key ����ü
	 * \remarks
	 * unsigned int key_data[32] �ڷ���
	 */
	typedef struct kisa_seed_key_st {
		unsigned int key_data[32];
	} KISA_SEED_KEY;

	/*!
	* \brief
	* SEED �ʱ�ȭ�� ���� ��ȣȭŰ ���� �Լ�
	* \param user_key
	* ����ڰ� �����ϴ� �Է� Ű (16 bytes)
	* \param ks
	* ����ڰ� �����ϴ� Ű�� ����Ǵ� Ű ����ü
	* \remarks
	* const unsigned char *user_key�� ũ��� �ݵ�� 16 bytes �� �ԷµǾ�� �ϰ� Ű����ü(KISA_SEED_KEY *ks)�� �޸� �Ҵ��� �Ǿ��־�� ��
	*/
	void KISA_SEED_init(const unsigned char* user_key, KISA_SEED_KEY* ks);

	/*!
	* \brief
	* SEED �˰��� ���� �� ��ȣȭ �Լ�
	* \param in
	* ����� �Է� ��(16 bytes)
	* \param out
	* ����� �Է¿� ���� ��� ��ȣ��(16 bytes)
	* \param ks
	* KISA_SEED_init�� ����� Ű�� ������ KISA_SEED_KEY ����ü
	* \remarks
	* -# ����� �Է� ��(const unsigned char *in)�� ũ��� �ݵ�� 16 bytes �� �Է�
	* -# ��� ��ȣ��(unsigned char *out)�� 16 bytes �̻� �޸� �Ҵ��� �Ǿ� �־�� �ϸ�, 16 bytes ��ȣ���� �����
	*/
	void KISA_SEED_encrypt_block(const unsigned char* in, unsigned char* out, const KISA_SEED_KEY* ks);

	/*!
	* \brief
	* SEED �˰��� ���� �� ��ȣȭ �Լ�
	* \param in
	* ����� �Է� ��ȣ��(16 bytes)
	* \param out
	* ����� �Է¿� ���� ��� ��(16 bytes)
	* \param ks
	* KISA_SEED_init�� ����� Ű�� ������ KISA_SEED_KEY ����ü
	* \remarks
	* -# ����� �Է� ��ȣ��(const unsigned char *in)�� ũ��� �ݵ�� 16 bytes �� �Է�
	* -# ��� ��(unsigned char *out)�� 16 bytes �̻� �޸� �Ҵ��� �Ǿ� �־�� �ϸ�, 16 bytes �򹮿� �����
	*/
	void KISA_SEED_decrypt_block(const unsigned char* in, unsigned char* out, const KISA_SEED_KEY* ks);


	/*!
	 * \brief
	 * SEED ��ȣȭ �˰��� CBC ���� ������ ���� ���� ����ü
	 */
	typedef struct kisa_seed_cbc_info_st {
		int				encrypt;							/*!< ��ȣȭ/��ȣȭ ��� ������*/
		unsigned char	ivec[SEED_BLOCK_SIZE];				/*!< �ʱ� ����*/
		KISA_SEED_KEY	seed_key;							/*!< SEED ��ȣȭ Ű*/
		unsigned char	cbc_buffer[SEED_BLOCK_SIZE];		/*!< ���� ����*/
		int				buffer_length;						/*!< ���� ������ ����*/
		unsigned char	cbc_last_block[SEED_BLOCK_SIZE];	/*!< CBC ���� ����*/
		int				last_block_flag;					/*!< CBC ���� ���� ��� ����*/
	} KISA_SEED_CBC_INFO;

	/*!
	* \brief
	* SEED CBC �˰��� �ʱ�ȭ �Լ�
	* \param info
	* SEED CBC �˰��� ��� ���� ����ü ���� (�̸� �޸𸮰� �Ҵ�Ǿ� �־�� ��)
	* \param enc
	* �˰��� ��ȣȭ �� ��ȣȭ ��� ���� (��ȣȭ : SEED_ENCRYPT / ��ȣȭ : SEED_DECRYPT)
	* \param user_key
	* ����ڰ� �����ϴ� �Է� Ű (16 bytes)
	* \param iv
	* ����ڰ� �����ϴ� �ʱ�ȭ ���� (16 bytes)
	* \returns
	* �ʱ�ȭ ���� (1) / �޸𸮰� ������ �Ҵ���� �ʾ��� ��� (0)
	* \remarks
	* user_key�� iv�� �ݵ�� 16 bytes�� �� ũ��� ����
	*/
	int KISA_SEED_CBC_init(KISA_SEED_CBC_INFO* info, int enc, unsigned char* user_key, unsigned char* iv);

	/*!
	 * \brief
	 * SEED CBC �˰��� ���� �� ��ȣȭ �Լ�
	 *
	 * \param info
	 * SEED CBC �˰��� ��� ���� ����ü ���� (KISA_SEED_CBC_init �� �ʱ�ȭ �ʿ�)
	 *
	 * \param in
	 * ����� �Է� ��/��ȣ��
	 *
	 * \param inLen
	 * ����� �Է��� ���� ����
	 *
	 * \param out
	 * ����� �Է¿� ���� ��ȣ��/�� ��� ����
	 *
	 * \param outLen
	 * ��� ���ۿ� ����� �������� ����
	 *
	 * \returns
	 * ���� ���� (1) / �޸𸮰� ������ �Ҵ���� �ʾ��� ��� (0)
	 *
	 * \remarks
	 * -# ����� �Ǵ� ������ ũ��� ����� �Է��� ���� ���� ũ�ų� ���� �̸� �޸� �Ҵ��� �ؾ���
	 * -# outLen�� ������ ��¹��� out�� ����� ������� ���̸� �Լ� ���ο��� ������
	 */
	int KISA_SEED_CBC_process(KISA_SEED_CBC_INFO* info, unsigned char* in, int inLen, unsigned char* out, int* outLen);

	/*!
	 * \brief
	 * SEED CBC �˰��� ���� ���� �� �е�(PKCS7) ó�� �Լ�
	 *
	 * \param info
	 * SEED CBC �˰��� ��� ���� ����ü ���� (KISA_SEED_CBC_init �� �ʱ�ȭ �ʿ�)
	 *
	 * \param out
	 * ����� �Է¿� ���� ���� ��� ���� ����Ǵ� ����
	 *
	 * \param outLen
	 * ��� ���ۿ� ����� �������� ����
	 *
	 * \returns
	 * ���� ���� (1) / �޸𸮰� ������ �Ҵ���� �ʾ��� ��� (0)
	 *
	 * \remarks
	 * ��¹��� out�� SEED �˰����� �Ѻ�(16 bytes) �̻����� �޸� �Ҵ��� �Ǿ� �־�� ��
	 *
	 */
	int KISA_SEED_CBC_close(KISA_SEED_CBC_INFO* info, unsigned char* out, int* outLen);

	/*!
	 * \brief
	 * SEED CBC ��ȣȭ �Լ�. �־��� �Է¿� ���� ��ȣȭ�� ó��(CBC���, PKCS�е�)
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
	int KISA_SEED_CBC_ENCRYPT(unsigned char* userkey,
		unsigned char* iv,
		unsigned char* in,
		unsigned int   len,
		unsigned char* out);

	/*!
	 * \brief
	 * SEED CBC ��ȣȭ �Լ�. �־��� �Է¿� ���� ��ȣȭ�� ó��(CBC���, PKCS�е�)
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
	int KISA_SEED_CBC_DECRYPT(unsigned char* userkey,
		unsigned char* iv,
		unsigned char* in,
		unsigned int   len,
		unsigned char* out);

#ifdef  __cplusplus
}
#endif


#endif /* HEADER_SEED_H */