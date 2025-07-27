#include "KISA_HMAC.h"
#include <assert.h>
#include "util.h"

int test_sha256()
{
	unsigned char msg[1024] = { 0, }, key[1024] = { 0, }, output[32] = { 0, }, hmac[32];
	unsigned int msgLen = 0, keyLen = 0, outputLen = 0, ret = 0;
	//void HMAC_SHA256(const u8* message, u32 mlen, const u8* key, u32 klen, u8 hmac[SHA256_DIGEST_VALUELEN]);

	printf("HMAC-SHA256-GENERATE _ case.1\n");
	keyLen = asc2hex(key, "C6F1D667A50AAEBA5A200A0A7CC24FFBB24984426AB8ABACCEE75162F3E1646B");
	msgLen = asc2hex(msg, "548A457280851ECA0F5476AFDAC102CF6C7DBE09B3083D74FBD03DA31E9D7F27F42CD656111A7D4BB005AD2EEAED6FB62CE0B0EBE7D6933189DA0B82AD6AA8FB8E21B19AC29374462579DA0F130E3EB8DAB87F726EEB54EB5F4AE087091087ED0BAFFFC6FAB7AAC156F823DBBCEB17DD5E4E5626B10F29AA656BE73B9A57C308");
	outputLen = asc2hex(output, "96C37F36CA0DEA3B2B3E60F1F6CDF79CFF72CA2A43A091C8105AE882A690EF2F");

	HMAC_SHA256(msg, msgLen, key, keyLen, hmac);

	assert(memcmp(hmac, output, outputLen) == 0);

	printf("HMAC-SHA256-VERIFY _ case.1\n");

	ret = Verify_HMAC_SHA256(msg, msgLen, key, keyLen, hmac);

	assert(ret == 0);
}