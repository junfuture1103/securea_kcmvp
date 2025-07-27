#ifndef _COMMON_H_
#define _COMMON_H_


#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define ENCRYPTION 1
#define DECRYPTION 2

typedef unsigned int u32;
typedef unsigned char u8;
typedef unsigned long long u64;

typedef struct _blk {
	u8* msg;
	u32 size;
}blk;


#define LROT(x,c) (((x) << (c)) | ((x) >> (32 - (c))))
#define ROTR(x,c) ((x)>>c) ^ ((x)<<(32-c)) //오른쪽 로테이션
#define SHR(x,c) ((x)>>c)					 //오른쪽 시프트
#define LROT64(x, c) (((u64)(x) << (c)) | ((u64)(x) >> (64 - (c))))
#define RROT64(x, c) LROT64((u64)(x), 64 - (c))

#else
#endif
