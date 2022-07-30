void crypt_enc_1(int q, unsigned long input[])//循环展开
{

	K[0] = input[q] ^ FK[0];
	K[1] = input[q + 1] ^ FK[1];
	K[2] = input[q + 2] ^ FK[2];
	K[3] = input[q + 3] ^ FK[3];
	int i;
	for (i = 1; i < 30; i += 4)
	{
		son_key(i);
		plaintext(cipher[i - 1], cipher[i], cipher[i + 1], cipher[i + 2], i);
		son_key(i + 1);
		plaintext(cipher[i], cipher[i + 1], cipher[i + 2], cipher[i + 3], i + 1);
		son_key(i + 2);
		plaintext(cipher[i + 1], cipher[i + 2], cipher[i + 3], cipher[i + 4], i + 2);
		son_key(i + 3);
		plaintext(cipher[i + 2], cipher[i + 3], cipher[i + 4], cipher[i + 5], i + 3);

		//cout << "turn: " << i << "\nkey: 0x" << hex << K[i + 3] << "\ncipher: 0x" << hex << cipher[i + 3] << endl;
	}
	//i -= 2;
	for (i; i < 33; i++)
	{
		son_key(i);
		plaintext(cipher[i - 1], cipher[i], cipher[i + 1], cipher[i + 2], i);
	}
	//cout << "Finalcipher: 0x" << hex << cipher[35] << cipher[34] << cipher[33] << cipher[32] << endl;

}
