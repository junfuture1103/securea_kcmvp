#ifndef _INTEGRITY_TEST_H_
#define _INTEGRITY_TEST_H_

#ifdef __cplusplus
extern "C" {
#endif

#include <stddef.h>

    typedef unsigned char BYTE;

    // ����� �˰��� �ĺ���
    typedef enum {
        MAC_ALG_SHA256 = 0,
        MAC_ALG_HMAC_SHA256 = 1
        // �ʿ�� Ȯ�� ����
    } MAC_ALGORITHM;

    /**
     * @brief Mac�� ����Ͽ� ����Ѵ�.
     *
     * @param output           MAC ����� ������ ����
     * @param outputLength     ��� MAC ���� (���� SHA256�̸� 32)
     * @param data             �Է� ������ (��: ��� ���̳ʸ�)
     * @param dataLength       �Է� ������ ����
     * @param key              MAC ���� Ű (HMAC�� ��� �ʼ�)
     * @param keyLength        Ű ����
     * @param alg              ��� �˰���
     */
    void Mac(
        BYTE* output,
        size_t outputLength,
        const BYTE* data,
        size_t dataLength,
        const BYTE* key,
        size_t keyLength,
        MAC_ALGORITHM alg
    );

    /**
     * @brief ���� ���� key�� ��ȯ
     * @return const BYTE* Ű ������ (���� or ���� �������� ����)
     */
    const BYTE* sudo_getMacKey(size_t* keyLength);

    /**
     * @brief ���� ��� ������ �ε��Ͽ� ��ü �����͸� ��ȯ
     * @param length ��ȯ�� ���� ���� ������
     * @return const BYTE* ���� ���� ������
     */
    const BYTE* sudo_getModule_macData(size_t* length);

#ifdef __cplusplus
}
#endif

#endif /* _INTEGRITY_TEST_H_ */
