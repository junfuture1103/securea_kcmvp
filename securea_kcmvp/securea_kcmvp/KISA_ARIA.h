#ifndef _KISA_ARIA_H_
#define _KISA_ARIA_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stdio.h>

	typedef unsigned char Byte;
	typedef unsigned int  Word;

	/* ��ȣȭ �Լ�
	 * @param i: �Է� �� (16 bytes)
	 * @param Nr: ���� �� (128bit �� 12, 192bit �� 14, 256bit �� 16)
	 * @param rk: ���� Ű (EncKeySetup���� ������)
	 * @param o: ��� ��ȣ�� (16 bytes)
	 */
	int Crypt(void* context, const Byte* i, int Nr, const Byte* rk, Byte* o);

	/* ��ȣȭ ���� Ű ���� �Լ�
	 * @param mk: ������ Ű
	 * @param rk: ������ ���� Ű�� ������ ���� (16 * 17 bytes �̻�)
	 * @param keyBits: Ű ��Ʈ �� (128, 192, or 256)
	 * @return ���� ��
	 */
	int EncKeySetup(const Byte* mk, Byte* rk, int keyBits);

	/* ��ȣȭ ���� Ű ���� �Լ�
	 * @param mk: ������ Ű
	 * @param rk: ������ ��ȣȭ�� ���� Ű�� ������ ����
	 * @param keyBits: Ű ��Ʈ �� (128, 192, or 256)
	 * @return ���� ��
	 */
	int DecKeySetup(const Byte* mk, Byte* rk, int keyBits);

	/* �⺻ �׽�Ʈ �Լ�
	 * endian ����, �׽�Ʈ ���� ���� �� round-trip Ȯ��
	 */
	int ARIA_encrypt(void* context, unsigned char* input, unsigned int inputLength, unsigned char* output, unsigned int* outputLength);
	int ARIA_decrypt(const Byte* mk, int keyBits, const Byte* in, unsigned int inLen, Byte* out);

	/* ��� ��� �Լ� (������) */
	void printBlock(Byte* b);
	void printBlockOfLength(Byte* b, int len);

#ifdef __cplusplus
}
#endif

#endif /* _KISA_ARIA_H_ */
