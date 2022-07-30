void crypt_enc(int q, unsigned long input[])//流水线SM4
{

	K[0] = input[q] ^ FK[0];
	K[1] = input[q + 1] ^ FK[1];
	K[2] = input[q + 2] ^ FK[2];
	K[3] = input[q + 3] ^ FK[3];
	for (int i = 1; i < 33; i++)
	{
		son_key(i);
		plaintext(cipher[i - 1], cipher[i], cipher[i + 1], cipher[i + 2], i);
	}
	//cout << "Finalcipher: 0x" << hex << cipher[35] << cipher[34] << cipher[33] << cipher[32] << endl;

}
