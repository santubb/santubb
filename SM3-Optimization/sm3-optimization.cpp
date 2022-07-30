#include "SM3.h"
#include <iostream>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <windows.h>
# include <immintrin.h>
using namespace std;

# define _mm_rotl_epi32(X,i) _mm_xor_si128(_mm_slli_epi32((X),(i)), _mm_srli_epi32((X),32-(i)))

#ifndef PUT_ULONG_BE
#define PUT_ULONG_BE(n,b,i)                             \
{                                                       \
    (b)[i    ] = (unsigned char) ( (n) >> 24 );       \
    (b)[i + 1] = (unsigned char) ( (n) >> 16 );       \
    (b)[i + 2] = (unsigned char) ( (n) >>  8 );       \
    (b)[i + 3] = (unsigned char) ( (n)       );       \
}
#endif

void SM3_Starts(sm3_context* context) {
    context->iplen = 0;

    context->state[0] = 0x7380166F;
    context->state[1] = 0x4914B2B9;
    context->state[2] = 0x172442D7;
    context->state[3] = 0xDA8A0600;
    context->state[4] = 0xA96F30BC;
    context->state[5] = 0x163138AA;
    context->state[6] = 0xE38DEE4D;
    context->state[7] = 0xB0FB0E4E;
}


void SM3_Process(sm3_context* context, uint8_t data[64]) {
    int j;
    unsigned long SS1, SS2, TT1, TT2, W1[68], W2[64];
    unsigned long A, B, C, D, E, F, G, H;
    unsigned long T[64];
    __m128i X, K, R;
    __m128i M = _mm_setr_epi32(0, 0, 0, 0xffffffff);
    __m128i V = _mm_setr_epi8(3, 2, 1, 0, 7, 6, 5, 4, 11, 10, 9, 8, 15, 14, 13, 12);
#ifdef _DEBUG
    int i;
#endif

    for (j = 0; j < 16; j++) {
        T[j] = 0x79CC4519;
    }
    for (j = 16; j < 64; j++) {
        T[j] = 0x7A879D8A;
    }

    for (j = 0; j < 16; j += 4) {
        X = _mm_loadu_si128((__m128i*)(data + j * 4));
        X = _mm_shuffle_epi8(X, V);
        _mm_storeu_si128((__m128i*)(W1 + j), X);
    }

#ifdef _DEBUG
    printf("Message with padding:\n");
    for (i = 0; i < 8; i++)
        printf("%08x ", W1[i]);
    printf("\n");
    for (i = 8; i < 16; i++)
        printf("%08x ", W1[i]);
    printf("\n");
#endif

#define FF0(x,y,z) ( (x) ^ (y) ^ (z))
#define FF1(x,y,z) (((x) & (y)) | ( (x) & (z)) | ( (y) & (z)))

#define GG0(x,y,z) ( (x) ^ (y) ^ (z))
#define GG1(x,y,z) (((x) & (y)) | ( (~(x)) & (z)) )


#define SHL(x,n) (((x) & 0xFFFFFFFF) << (n))
#define ROTL(x,n) (SHL((x),n) | ((x) >> (32 - n)))

#define P0(x) ((x) ^  ROTL((x),9) ^ ROTL((x),17))
#define P1(x) ((x) ^  ROTL((x),15) ^ ROTL((x),23))


    //消息扩展
    for (j = 16; j < 68; j += 4) {
        /* X = (W1[j - 3], W1[j - 2], W1[j - 1], 0) */
        X = _mm_loadu_si128((__m128i*)(W1 + j - 3));
        X = _mm_andnot_si128(M, X);

        X = _mm_rotl_epi32(X, 15);
        K = _mm_loadu_si128((__m128i*)(W1 + j - 9));
        X = _mm_xor_si128(X, K);
        K = _mm_loadu_si128((__m128i*)(W1 + j - 16));
        X = _mm_xor_si128(X, K);

        /* P1() */
        K = _mm_rotl_epi32(X, 8);
        K = _mm_xor_si128(K, X);
        K = _mm_rotl_epi32(K, 15);
        X = _mm_xor_si128(X, K);

        K = _mm_loadu_si128((__m128i*)(W1 + j - 13));
        K = _mm_rotl_epi32(K, 7);
        X = _mm_xor_si128(X, K);
        K = _mm_loadu_si128((__m128i*)(W1 + j - 6));
        X = _mm_xor_si128(X, K);

        /* W1[j + 3] ^= P1(ROL32(W1[j + 1], 15)) */
        R = _mm_shuffle_epi32(X, 0);
        R = _mm_and_si128(R, M);
        K = _mm_rotl_epi32(R, 15);
        K = _mm_xor_si128(K, R);
        K = _mm_rotl_epi32(K, 9);
        R = _mm_xor_si128(R, K);
        R = _mm_rotl_epi32(R, 6);
        X = _mm_xor_si128(X, R);

        _mm_storeu_si128((__m128i*)(W1 + j), X);
    }

#ifdef _DEBUG
    printf("Expanding message W0-67:\n");
    for (i = 0; i < 68; i++) {
        printf("%08x ", W1[i]);
        if (((i + 1) % 8) == 0) printf("\n");
    }
    printf("\n");
#endif
    /* W2 = W1[j] ^ W1[j+4] */
    for (int j = 0; j < 64; j += 4) {
        X = _mm_loadu_si128((__m128i*)(W1 + j));
        K = _mm_loadu_si128((__m128i*)(W1 + j + 4));
        X = _mm_xor_si128(X, K);
        _mm_storeu_si128((__m128i*)(W2 + j), X);
    }

#ifdef _DEBUG
    printf("Expanding message W'0-63:\n");
    for (i = 0; i < 64; i++) {
        printf("%08x ", W2[i]);
        if (((i + 1) % 8) == 0) printf("\n");
    }
    printf("\n");
#endif

    //迭代压缩
    A = context->state[0];
    B = context->state[1];
    C = context->state[2];
    D = context->state[3];
    E = context->state[4];
    F = context->state[5];
    G = context->state[6];
    H = context->state[7];
#ifdef _DEBUG
    printf("j     A       B        C         D         E        F        G       H\n");
    printf("   %08x %08x %08x %08x %08x %08x %08x %08x\n", A, B, C, D, E, F, G, H);
#endif

    //压缩函数
    for (j = 0; j < 16; j++) {
        SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)), 7);
        SS2 = SS1 ^ ROTL(A, 12);
        TT1 = FF0(A, B, C) + D + SS2 + W2[j];
        TT2 = GG0(E, F, G) + H + SS1 + W1[j];
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
#ifdef _DEBUG
        printf("%02d %08x %08x %08x %08x %08x %08x %08x %08x\n", j, A, B, C, D, E, F, G, H);
#endif
    }

    for (j = 16; j < 64; j++) {
        SS1 = ROTL((ROTL(A, 12) + E + ROTL(T[j], j)), 7);
        SS2 = SS1 ^ ROTL(A, 12);
        TT1 = FF1(A, B, C) + D + SS2 + W2[j];
        TT2 = GG1(E, F, G) + H + SS1 + W1[j];
        D = C;
        C = ROTL(B, 9);
        B = A;
        A = TT1;
        H = G;
        G = ROTL(F, 19);
        F = E;
        E = P0(TT2);
#ifdef _DEBUG
        printf("%02d %08x %08x %08x %08x %08x %08x %08x %08x\n", j, A, B, C, D, E, F, G, H);
#endif
    }

    context->state[0] ^= A;
    context->state[1] ^= B;
    context->state[2] ^= C;
    context->state[3] ^= D;
    context->state[4] ^= E;
    context->state[5] ^= F;
    context->state[6] ^= G;
    context->state[7] ^= H;
#ifdef _DEBUG
    printf("   %08x %08x %08x %08x %08x %08x %08x %08x\n", context->state[0], context->state[1], context->state[2],
        context->state[3], context->state[4], context->state[5], context->state[6], context->state[7]);
#endif
}


/*
 * SM3 process buffer
 */
void SM3_Update(sm3_context* context, unsigned char* input, int iplen_t) {
    /*
     * iplen_t 待填充data的长度
     * input 待填充的data
     */
    int insert;
    unsigned long lo;

    if (iplen_t <= 0)
        return;

    lo = context->iplen & 0x3F;       // 当前分组开始填充的位置
    insert = 64 - lo;               // 需要填充的位数

    context->iplen += iplen_t;             // 已经放入所有分块中的总长度

    if (lo && iplen_t >= insert) {
        memcpy((void*)(context->buffer + lo), (void*)input, insert);     // 补全当前分块到64字节
        SM3_Process(context, context->buffer);                              // 将补全的分块进行操作
        input += insert;                                              // 填入下一个分块的第一个表项位置更新
        iplen_t -= insert;                                               // 填入下一个分块的data的长度
        lo = 0;                                                   // 开始一个新的分组
    }

    while (iplen_t >= 64) {
        SM3_Process(context, input);
        input += 64;
        iplen_t -= 64;
    }// 若待填充data长度不小于64bit则将64bit填入一个块并进行操作，直至待填充data长度小于64bit

    if (iplen_t > 0) {
        memcpy((void*)(context->buffer + lo), (void*)input, iplen_t);
    }// 将待填充的消息填入buffer中
}

static const unsigned char SM3_Padding[64] =
{
        0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0
};

/*
 * SM3 final digest
 */
void SM3_Finish(sm3_context* context, unsigned char output[32]) {
    unsigned long last, need_len;
    unsigned long high, low;
    unsigned char message_len[8];        // 消息长度(大端存储)

    high = (context->iplen >> 29);
    low = (context->iplen << 3);

    PUT_ULONG_BE(high, message_len, 0);
    PUT_ULONG_BE(low, message_len, 4);


    last = context->iplen & 0x3F;     // 每64字节一个分组，此为最后一个分组中的的字节数(& 0x3F = % 64)
    need_len = (last < 56) ? (56 - last) : (120 - last);            // 需要补充的内容的长度

    SM3_Update(context, (unsigned char*)SM3_Padding, need_len);         // 用padding进行填充
    SM3_Update(context, message_len, 8);                                 // 最后填充8字节的消息长度

    PUT_ULONG_BE(context->state[0], output, 0);
    PUT_ULONG_BE(context->state[1], output, 4);
    PUT_ULONG_BE(context->state[2], output, 8);
    PUT_ULONG_BE(context->state[3], output, 12);
    PUT_ULONG_BE(context->state[4], output, 16);
    PUT_ULONG_BE(context->state[5], output, 20);
    PUT_ULONG_BE(context->state[6], output, 24);
    PUT_ULONG_BE(context->state[7], output, 28);
}

void SM3(unsigned char* input, int iplen_t, unsigned char output[32]) {
    sm3_context context;

    SM3_Starts(&context);
    SM3_Update(&context, input, iplen_t);
    SM3_Finish(&context, output);

    memset(&context, 0, sizeof(sm3_context));
}

int main(int argc, char* argv[])
{
    DWORD star_time = GetTickCount();
    auto* input = (unsigned char*)"qxy";   
    int iplen = 3;                  
    unsigned char output[32];       
    int i;
    sm3_context context;

    cout << "Message:" <<" " <<input<< endl;
    int num1 = iplen;
    if(num1==3)
    {
        SM3(input, iplen, output);
    }
    
    cout << "Hash:" << endl;
    for (i = 0; i < 32; i++)
    {
        printf("%02x", output[i]);
        if (((i + 1) % 4) == 0) printf(" ");
    }
    printf("\n");
    DWORD end_time = GetTickCount();
    cout << "The total time is:" << (end_time - star_time) << "ms." << endl;
}
