#include "sm3.h"
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
    auto* input = (unsigned char*)"xyz";   // input
    int iplen = 3;                   // input length
    unsigned char output[32];       // output
    int i;
    sm3_context context;

    cout << "Message:" << endl;
    cout << input << endl;

    SM3(input, iplen, output);
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




//
//#include <iostream>
//#include <string>
//#include <cmath>
//using namespace std;
//
////二进制转换为十六进制
//string BinToHex(string str) {
//	string hex = "";
//	int temp = 0;
//	while (str.size() % 4 != 0) {
//		str = "0" + str;
//	}
//	for (int i = 0; i < str.size(); i += 4) {
//		temp = (str[i] - '0') * 8 + (str[i + 1] - '0') * 4 + (str[i + 2] - '0') * 2 + (str[i + 3] - '0') * 1;
//		if (temp < 10) {
//			hex += to_string(temp);
//		}
//		else {
//			hex += 'A' + (temp - 10);
//		}
//	}
//	return hex;
//}
//
////十六进制转换为二进制
//string HexToBin(string str) {
//	string bin = "";
//	string table[16] = { "0000","0001","0010","0011","0100","0101","0110","0111","1000","1001","1010","1011","1100","1101","1110","1111" };
//	for (int i = 0; i < str.size(); i++) {
//		if (str[i] >= 'A' && str[i] <= 'F') {
//			bin += table[str[i] - 'A' + 10];
//		}
//		else {
//			bin += table[str[i] - '0'];
//		}
//	}
//	return bin;
//}
//
////二进制转换为十进制的函数实现
//int BinToDec(string str) {
//	int dec = 0;
//	for (int i = 0; i < str.size(); i++) {
//		dec += (str[i] - '0') * pow(2, str.size() - i - 1);
//	}
//	return dec;
//}
//
////十进制转换为二进制的函数实现
//string DecToBin(int str) {
//	string bin = "";
//	while (str >= 1) {
//		bin = to_string(str % 2) + bin;
//		str = str / 2;
//	}
//	return bin;
//}
//
////十六进制转换为十进制的函数实现
//int HexToDec(string str) {
//	int dec = 0;
//	for (int i = 0; i < str.size(); i++) {
//		if (str[i] >= 'A' && str[i] <= 'F') {
//			dec += (str[i] - 'A' + 10) * pow(16, str.size() - i - 1);
//		}
//		else {
//			dec += (str[i] - '0') * pow(16, str.size() - i - 1);
//		}
//	}
//	return dec;
//}
//
////十进制转换为十六进制的函数实现
//string DecToHex(int str) {
//	string hex = "";
//	int temp = 0;
//	while (str >= 1) {
//		temp = str % 16;
//		if (temp < 10 && temp >= 0) {
//			hex = to_string(temp) + hex;
//		}
//		else {
//			hex += ('A' + (temp - 10));
//		}
//		str = str / 16;
//	}
//	return hex;
//}
//
//string padding(string str) {//对数据进行填充 
//	string res = "";
//	for (int i = 0; i < str.size(); i++) {//首先将输入值转换为16进制字符串
//		res += DecToHex((int)str[i]);
//	}
//	/*
//	cout << "输入字符串的ASCII码表示为：" << endl;
//	for (int i = 0; i < res.size(); i++) {
//		cout << res[i];
//		if ((i + 1) % 8 == 0) {
//			cout << "  ";
//		}
//		if ((i + 1) % 64 == 0 || (i + 1) == res.size()) {
//			cout << endl;
//		}
//	}
//	cout << endl;*/
//	int res_length = res.size() * 4;//记录的长度为2进制下的长度
//	res += "8";//在获得的数据后面添1，在16进制下相当于是添加8
//	while (res.size() % 128 != 112) {
//		res += "0";//“0”数据填充
//	}
//	string res_len = DecToHex(res_length);//用于记录数据长度的字符串
//	while (res_len.size() != 16) {
//		res_len = "0" + res_len;
//	}
//	res += res_len;
//	return res;
//}
//
//string LeftShift(string str, int len) {//实现循环左移len位功能
//	string res = HexToBin(str);
//	res = res.substr(len) + res.substr(0, len);
//	return BinToHex(res);
//}
//
//string XOR(string str1, string str2) {//实现异或操作
//	string res1 = HexToBin(str1);
//	string res2 = HexToBin(str2);
//	string res = "";
//	for (int i = 0; i < res1.size(); i++) {
//		if (res1[i] == res2[i]) {
//			res += "0";
//		}
//		else {
//			res += "1";
//		}
//	}
//	return BinToHex(res);
//}
//
//string AND(string str1, string str2) {//实现与操作
//	string res1 = HexToBin(str1);
//	string res2 = HexToBin(str2);
//	string res = "";
//	for (int i = 0; i < res1.size(); i++) {
//		if (res1[i] == '1' && res2[i] == '1') {
//			res += "1";
//		}
//		else {
//			res += "0";
//		}
//	}
//	return BinToHex(res);
//}
//
//string OR(string str1, string str2) {//实现或操作
//	string res1 = HexToBin(str1);
//	string res2 = HexToBin(str2);
//	string res = "";
//	for (int i = 0; i < res1.size(); i++) {
//		if (res1[i] == '0' && res2[i] == '0') {
//			res += "0";
//		}
//		else {
//			res += "1";
//		}
//	}
//	return BinToHex(res);
//}
//
//string NOT(string str) {//实现非操作
//	string res1 = HexToBin(str);
//	string res = "";
//	for (int i = 0; i < res1.size(); i++) {
//		if (res1[i] == '0') {
//			res += "1";
//		}
//		else {
//			res += "0";
//		}
//	}
//	return BinToHex(res);
//}
//
//char binXor(char str1, char str2) {//实现单比特的异或操作
//	return str1 == str2 ? '0' : '1';
//}
//
//char binAnd(char str1, char str2) {//实现单比特的与操作
//	return (str1 == '1' && str2 == '1') ? '1' : '0';
//}
//
//string ModAdd(string str1, string str2) {//mod 2^32运算的函数实现
//	string res1 = HexToBin(str1);
//	string res2 = HexToBin(str2);
//	char temp = '0';
//	string res = "";
//	for (int i = res1.size() - 1; i >= 0; i--) {
//		res = binXor(binXor(res1[i], res2[i]), temp) + res;
//		if (binAnd(res1[i], res2[i]) == '1') {
//			temp = '1';
//		}
//		else {
//			if (binXor(res1[i], res2[i]) == '1') {
//				temp = binAnd('1', temp);
//			}
//			else {
//				temp = '0';
//			}
//		}
//	}
//	return BinToHex(res);
//}
//
//string P1(string str) {//实现置换功能P1（X）
//	return XOR(XOR(str, LeftShift(str, 15)), LeftShift(str, 23));
//}
//
//string P0(string str) {//实现置换功能P0（X）
//	return XOR(XOR(str, LeftShift(str, 9)), LeftShift(str, 17));
//}
//
//string T(int j) {//返回Tj常量值的函数实现
//	if (0 <= j && j <= 15) {
//		return "79CC4519";
//	}
//	else {
//		return "7A879D8A";
//	}
//}
//
//string FF(string str1, string str2, string str3, int j) {//实现布尔函数FF功能
//	if (0 <= j && j <= 15) {
//		return XOR(XOR(str1, str2), str3);
//	}
//	else {
//		return OR(OR(AND(str1, str2), AND(str1, str3)), AND(str2, str3));
//	}
//}
//
//string GG(string str1, string str2, string str3, int j) {//实现布尔函数GG功能
//	if (0 <= j && j <= 15) {
//		return XOR(XOR(str1, str2), str3);
//	}
//	else {
//		return OR(AND(str1, str2), AND(NOT(str1), str3));
//	}
//}
//string extension(string str) {//消息扩展函数
//	string res = str;//字符串类型存储前68位存储扩展字W值
//	for (int i = 16; i < 68; i++) {//根据公式生成第17位到第68位的W值
//		res += XOR(XOR(P1(XOR(XOR(res.substr((i - 16) * 8, 8), res.substr((i - 9) * 8, 8)), LeftShift(res.substr((i - 3) * 8, 8), 15))), LeftShift(res.substr((i - 13) * 8, 8), 7)), res.substr((i - 6) * 8, 8));
//	}
//	/*
//	cout << "扩展后的消息：" << endl;
//	cout << "W0,W1,……,W67的消息：" << endl;
//	for (int i = 0; i < 8; i++) {
//		for (int j = 0; j < 8; j++) {
//			cout << res.substr(i * 64 + j * 8, 8) << "  ";
//		}
//		cout << endl;
//	}
//	cout << res.substr(512, 8) << "  " << res.substr(520, 8) << "  " << res.substr(528, 8) << "  " << res.substr(536, 8) << endl;
//	cout << endl;
//	*/
//	for (int i = 0; i < 64; i++) {//根据公式生成64位W'值
//		res += XOR(res.substr(i * 8, 8), res.substr((i + 4) * 8, 8));
//	}
//	/*
//	cout << "W0',W1',……,W63'的消息：" << endl;
//	for (int i = 0; i < 8; i++) {
//		for (int j = 0; j < 8; j++) {
//			cout << res.substr(544 + i * 64 + j * 8, 8) << "  ";
//		}
//		cout << endl;
//	}
//	cout << endl;*/
//	return res;
//}
//
//string compress(string str1, string str2) {//消息压缩函数
//	string IV = str2;
//	string A = IV.substr(0, 8), B = IV.substr(8, 8), C = IV.substr(16, 8), D = IV.substr(24, 8), E = IV.substr(32, 8), F = IV.substr(40, 8), G = IV.substr(48, 8), H = IV.substr(56, 8);
//	string SS1 = "", SS2 = "", TT1 = "", TT2 = "";
//	/*
//	cout << "迭代压缩中间值: " << endl;
//	cout << "    A         B         C         D         E         F        G         H " << endl;
//	cout << A << "  " << B << "  " << C << "  " << D << "  " << E << "  " << F << "  " << G << "  " << H << endl;*/
//	for (int j = 0; j < 64; j++) {
//		SS1 = LeftShift(ModAdd(ModAdd(LeftShift(A, 12), E), LeftShift(T(j), (j % 32))), 7);
//		SS2 = XOR(SS1, LeftShift(A, 12));
//		TT1 = ModAdd(ModAdd(ModAdd(FF(A, B, C, j), D), SS2), str1.substr((j + 68) * 8, 8));
//		TT2 = ModAdd(ModAdd(ModAdd(GG(E, F, G, j), H), SS1), str1.substr(j * 8, 8));
//		D = C;
//		C = LeftShift(B, 9);
//		B = A;
//		A = TT1;
//		H = G;
//		G = LeftShift(F, 19);
//		F = E;
//		E = P0(TT2);
//		//cout << A << "  " << B << "  " << C << "  " << D << "  " << E << "  " << F << "  " << G << "  " << H << endl;
//	}
//	string res = (A + B + C + D + E + F + G + H);
//	//cout << endl;
//	return res;
//}
//
//string iteration(string str) {//迭代压缩函数实现
//	int num = str.size() / 128;
//	/*
//	cout << "消息经过填充之后共有 " + to_string(num) + " 个消息分组。" << endl;
//	cout << endl;*/
//	string V = "7380166F4914B2B9172442D7DA8A0600A96F30BC163138AAE38DEE4DB0FB0E4E";
//	string B = "", extensionB = "", compressB = "";
//	for (int i = 0; i < num; i++) {
//		//cout << "第 " << to_string(i + 1) << " 个消息分组：" << endl;
//		//cout << endl;
//		B = str.substr(i * 128, 128);
//		extensionB = extension(B);
//		compressB = compress(extensionB, V);
//		V = XOR(V, compressB);
//	}
//	return V;
//}
//
//int main() {//主函数
//	string str;
//	str = "1248431438a31bcdacd343";
//	cout << "输入消息为字符串: " + str << endl;
//	cout << endl;
//	string paddingValue = padding(str);
//	cout << "填充：" << endl;
//	for (int i = 0; i < paddingValue.size() / 64; i++) {
//		for (int j = 0; j < 8; j++) {
//			cout << paddingValue.substr(i * 64 + j * 8, 8) << "  ";
//		}
//		cout << endl;
//	}
//	cout << endl;
//	string result = iteration(paddingValue);
//	cout << "杂凑值：" << endl;
//	for (int i = 0; i < 8; i++) {
//		cout << result.substr(i * 8, 8) << "  ";
//	}
//	cout << endl;
//}