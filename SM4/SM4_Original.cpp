#include <iostream>
#include<string>
#include<thread>
#include <chrono>  
#include<immintrin.h>
const int thread_num = 16;
#define CROL(value, bits) ((value << bits) | (value >> (32 - bits)))
using namespace std;
using namespace chrono;
#define u8 unsigned char;
#define u32 unsigned long;
//plaintext=0x4920646f 6e277420 77616e74 20746f21
//MK=0xee423900 d74ad474 9bf87fc1 fd285e61
void son_key(int n);
void plaintext(unsigned long x0, unsigned long x1, unsigned long x2, unsigned long x3, int n);
void crypt_enc(int q, unsigned long input[]);
void crypt_enc_for(int q, unsigned long input[]);
void crypt_enc_1(int q, unsigned long input[]);
void crypt_enc_thread(int num1, int num2, unsigned long input[]);
//int MK0 = 0x01234567;
//int MK1 = 0x89abcdef;
//int MK2 = 0xfedcba98;
//int MK3 = 0x76543210;
unsigned long MK[400000] = { 0 };
unsigned long cipher[36] = { 0x01234567,0x89abcdef,
0xfedcba98,0x76543210
};
const unsigned long FK[4] =
{
	0xa3b1bac6,
	0x56aa3350,
	0x677d9197,
	0xb27022dc
};
const unsigned long CK[32] =
{
0x00070e15,0x1c232a31,0x383f464d,0x545b6269,
0x70777e85,0x8c939aa1,0xa8afb6bd,0xc4cbd2d9,
0xe0e7eef5,0xfc030a11,0x181f262d,0x343b4249,
0x50575e65,0x6c737a81,0x888f969d,0xa4abb2b9,
0xc0c7ced5,0xdce3eaf1,0xf8ff060d,0x141b2229,
0x30373e45,0x4c535a61,0x686f767d,0x848b9299,
0xa0a7aeb5,0xbcc3cad1,0xd8dfe6ed,0xf4fb0209,
0x10171e25,0x2c333a41,0x484f565d,0x646b7279
};
unsigned long K[36] = { 0 };

const unsigned char SBOX[256] = {
0xd6,0x90,0xe9,0xfe,0xcc,0xe1,0x3d,0xb7,0x16,0xb6,0x14,0xc2,0x28,0xfb,0x2c,0x05,
0x2b,0x67,0x9a,0x76,0x2a,0xbe,0x04,0xc3,0xaa,0x44,0x13,0x26,0x49,0x86,0x06,0x99,
0x9c,0x42,0x50,0xf4,0x91,0xef,0x98,0x7a,0x33,0x54,0x0b,0x43,0xed,0xcf,0xac,0x62,
0xe4,0xb3,0x1c,0xa9,0xc9,0x08,0xe8,0x95,0x80,0xdf,0x94,0xfa,0x75,0x8f,0x3f,0xa6,
0x47,0x07,0xa7,0xfc,0xf3,0x73,0x17,0xba,0x83,0x59,0x3c,0x19,0xe6,0x85,0x4f,0xa8,
0x68,0x6b,0x81,0xb2,0x71,0x64,0xda,0x8b,0xf8,0xeb,0x0f,0x4b,0x70,0x56,0x9d,0x35,
0x1e,0x24,0x0e,0x5e,0x63,0x58,0xd1,0xa2,0x25,0x22,0x7c,0x3b,0x01,0x21,0x78,0x87,
0xd4,0x00,0x46,0x57,0x9f,0xd3,0x27,0x52,0x4c,0x36,0x02,0xe7,0xa0,0xc4,0xc8,0x9e,
0xea,0xbf,0x8a,0xd2,0x40,0xc7,0x38,0xb5,0xa3,0xf7,0xf2,0xce,0xf9,0x61,0x15,0xa1,
0xe0,0xae,0x5d,0xa4,0x9b,0x34,0x1a,0x55,0xad,0x93,0x32,0x30,0xf5,0x8c,0xb1,0xe3,
0x1d,0xf6,0xe2,0x2e,0x82,0x66,0xca,0x60,0xc0,0x29,0x23,0xab,0x0d,0x53,0x4e,0x6f,
0xd5,0xdb,0x37,0x45,0xde,0xfd,0x8e,0x2f,0x03,0xff,0x6a,0x72,0x6d,0x6c,0x5b,0x51,
0x8d,0x1b,0xaf,0x92,0xbb,0xdd,0xbc,0x7f,0x11,0xd9,0x5c,0x41,0x1f,0x10,0x5a,0xd8,
0x0a,0xc1,0x31,0x88,0xa5,0xcd,0x7b,0xbd,0x2d,0x74,0xd0,0x12,0xb8,0xe5,0xb4,0xb0,
0x89,0x69,0x97,0x4a,0x0c,0x96,0x77,0x7e,0x65,0xb9,0xf1,0x09,0xc5,0x6e,0xc6,0x84,
0x18,0xf0,0x7d,0xec,0x3a,0xdc,0x4d,0x20,0x79,0xee,0x5f,0x3e,0xd7,0xcb,0x39,0x48
};
int main()

{

	int length = sizeof(MK) / sizeof(MK[0]);
	for (int i = 0; i < length; i++)
	{
		MK[i] = 0x01234567;
	}
	auto start1 = system_clock::now();
	for (int i = 0; i < length; i += 4)
	{
		crypt_enc_for(i, MK);
	}
	auto end1 = system_clock::now();
	auto duration1 = duration_cast<microseconds>(end1 - start1);
	//cout << "For Spent" << 1000 * double(duration1.count()) * microseconds::period::num / microseconds::period::den << " ms." << endl;
	cout << "初始SM4 " << 1000 * double(duration1.count()) * microseconds::period::num / microseconds::period::den << " ms." << endl;

	auto start4 = system_clock::now();
	for (int i = 0; i < length; i += 4)
	{
		crypt_enc(i, MK);
	}
	auto end4 = system_clock::now();
	auto duration4 = duration_cast<microseconds>(end4 - start4);
	//cout << "For Spent" << 1000 * double(duration1.count()) * microseconds::period::num / microseconds::period::den << " ms." << endl;
	cout << "流水线SM4 " << 1000 * double(duration4.count()) * microseconds::period::num / microseconds::period::den << " ms." << endl;

	auto start3 = system_clock::now();
	//int i;
	//for ( i = 0; i < length; i += 8)
	//{
	//	crypt_enc_1(i, MK);
	//	crypt_enc_1(i + 4, MK);
	//}
	//for (i; i < length; i++)
	//{
	//	crypt_enc_1(i, MK);
	//}
	for (int i = 0; i < length; i += 4)
	{
		crypt_enc_1(i, MK);
	}

	auto end3 = system_clock::now();
	auto duration3 = duration_cast<microseconds>(end3 - start3);
	//cout << "crypt_enc_1 " << 1000 * double(duration3.count()) * microseconds::period::num / microseconds::period::den << " ms." << endl;
	cout << "循环展开 " << 1000 * double(duration3.count()) * microseconds::period::num / microseconds::period::den << " ms." << endl;

	int step = (length / thread_num) / 4;
	thread threads[thread_num];
	int n = 0;
	for (int i = 0; i < thread_num; i++)
	{
		threads[i] = thread(crypt_enc_thread, n * 4, (n + step) * 4, MK);
		n = n + step;
	}
	auto start2 = system_clock::now();
	for (int q = 0; q < thread_num; q++)
	{
		threads[q].join();
	}
	auto end2 = system_clock::now();
	auto duration2 = duration_cast<microseconds>(end2 - start2);
	//cout << "crypt_enc_thread" << 1000 * double(duration2.count()) * microseconds::period::num / microseconds::period::den << " ms." << endl;
	cout << "多线程 " << 1000 * double(duration2.count()) * microseconds::period::num / microseconds::period::den << " ms." << endl;

	//for (int i = 1; i < 33; i++)
	//{
	//	son_key(i);
	//	plaintext(cipher[i - 1], cipher[i], cipher[i + 1], cipher[i + 2], i);
	//	cout << "turn: " << i << "\nkey: 0x" << hex << K[i + 3] << "\ncipher: 0x" << hex << cipher[i + 3] << endl;
	//}
	//cout << "Finalcipher: 0x" << hex << cipher[35] << cipher[34] << cipher[33] << cipher[32] << endl;
	return 0;
}

void son_key(int n)//n为轮数
{
	unsigned long kk = K[n] ^ K[n + 1] ^ K[n + 2] ^ CK[n - 1];
	unsigned char b0 = SBOX[unsigned char(kk / 0x1000000)];
	unsigned char b1 = SBOX[unsigned char(kk / 0x10000)];
	unsigned char b2 = SBOX[unsigned char(kk / 0x100)];
	unsigned char b3 = SBOX[unsigned char(kk)];
	kk = b0 * 0x1000000 + b1 * 0x10000 + b2 * 0x100 + b3;
	K[n + 3] = kk ^ CROL(kk, 13) ^ CROL(kk, 23) ^ K[n - 1];
}




void plaintext(unsigned long x0, unsigned long x1, unsigned long x2, unsigned long x3, int n)
{
	unsigned long kk = K[n + 3] ^ x1 ^ x2 ^ x3;
	unsigned char b0 = SBOX[unsigned char(kk / 0x1000000)];
	unsigned char b1 = SBOX[unsigned char(kk / 0x10000)];
	unsigned char b2 = SBOX[unsigned char(kk / 0x100)];
	unsigned char b3 = SBOX[unsigned char(kk)];
	kk = b0 * 0x1000000 + b1 * 0x10000 + b2 * 0x100 + b3;
	cipher[n + 3] = (kk ^ CROL(kk, 2) ^ CROL(kk, 10) ^ CROL(kk, 18) ^ CROL(kk, 24)) ^ x0;
}
void crypt_enc_for(int q, unsigned long input[])//初始SM4
{

	K[0] = input[q] ^ FK[0];
	K[1] = input[q + 1] ^ FK[1];
	K[2] = input[q + 2] ^ FK[2];
	K[3] = input[q + 3] ^ FK[3];
	for (int i = 1; i < 33; i++)
	{
		son_key(i);
	}
	for (int i = 1; i < 33; i++)
	{
		plaintext(cipher[i - 1], cipher[i], cipher[i + 1], cipher[i + 2], i);
	}
	//cout << "Finalcipher: 0x" << hex << cipher[35] << cipher[34] << cipher[33] << cipher[32] << endl;

}
