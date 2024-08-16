#include <assert.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

#define BLOCK_SIZE 64
#define ROUNDS 16
#define SUBKEY_SIZE 48

int pc1[8][7] = {
	{57, 49, 41, 33, 25, 17, 9},
	{1, 58, 50, 42, 34, 26, 18},
	{10, 2, 59, 51, 43, 35, 27},
	{19, 11, 3, 60, 52, 44, 36},
	{63, 55, 47, 39, 31, 23, 15},
	{7, 62, 54, 46, 38, 30, 22},
	{14, 6, 61, 53, 45, 37, 29},
	{21, 13, 5, 28, 20, 12, 4}
};

int pc2[8][6] = {
	{14, 17, 11, 24, 1, 5},
	{3, 28, 15, 6, 21, 10},
	{23, 19, 12, 4, 26, 8},
	{16, 7, 27, 20, 13, 2},
	{41, 52, 31, 37, 47, 55},
	{30, 40, 51, 45, 33, 48},
	{44, 49, 39, 56, 34, 53},
	{46, 42, 50, 36, 29, 32}
};

int e_table[8][6] = {
	{32, 1, 2, 3, 4, 5},
	{4, 5, 6, 7, 8, 9},
	{8, 9, 10, 11, 12, 13},
	{12, 13, 14, 15, 16, 17},
	{16, 17, 18, 19, 20, 21},
	{20, 21, 22, 23, 24, 25},
	{24, 25, 26, 27, 28, 29},
	{28, 29, 30, 31, 32, 1}
};

int s1[4][16] = {
	{14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7},
	{0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8},
	{4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0},
	{15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13}
};

int s2[4][16] = {
	{15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10},
	{3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5},
	{0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15},
	{13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9}
};

int s3[4][16] = {
	{10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8},
	{13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1},
	{13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7},
	{1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12}
};

int s4[4][16] = {
	{7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15},
	{13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9},
	{10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4},
	{3, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14}
};

int s5[4][16] = {
	{2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9},
	{14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 9, 8, 6},
	{4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14},
	{11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3}
};

int s6[4][16] = {
	{12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11},
	{10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8},
	{9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6},
	{4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 7, 6, 0, 8, 13}
};

int s7[4][16] = {
	{4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1},
	{13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6},
	{1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2},
	{6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12}
};

int s8[4][16] = {
	{13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7},
	{1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2},
	{7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8},
	{2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11}
};

int p[8][4] = {
	{16, 7, 20, 21},
	{29, 12, 28, 17},
	{1, 15, 23, 26},
	{5, 18, 31, 10},
	{2, 8, 24, 14},
	{32, 27, 3, 9},
	{19, 13, 30, 6},
	{22, 11, 4, 25}
};

int ip[8][8] = {
	{58, 50, 42, 34, 26, 18, 10, 2},
	{60, 52, 44, 36, 28, 20, 12, 4},
	{62, 54, 46, 38, 30, 22, 14, 6},
	{64, 56, 48, 40, 32, 24, 16, 8},
	{57, 49, 41, 33, 25, 17, 9, 1},
	{59, 51, 43, 35, 27, 19, 11, 3},
	{61, 53, 45, 37, 29, 21, 13, 5},
	{63, 55, 47, 39, 31, 23, 15, 7}
};

int ipInverse[8][8] = {
	{40, 8, 48, 16, 56, 24, 64, 32},
	{39, 7, 47, 15, 55, 23, 63, 31},
	{38, 6, 46, 14, 54, 22, 62, 30},
	{37, 5, 45, 13, 53, 21, 61, 29},
	{36, 4, 44, 12, 52, 20, 60, 28},
	{35, 3, 43, 11, 51, 19, 59, 27},
	{34, 2, 42, 10, 50, 18, 58, 26},
	{33, 1, 41, 9, 49, 17, 57, 25}
};

int* intToBin(uint64_t hex, int n) {
	int* bin = (int*)malloc(sizeof(int) * n);
	for (int i = 0; i < n; i++)
		bin[n - 1 - i] = (hex >> i) & 1;
	return bin;
}

uint64_t binToDec(int* bin, int n) {
	uint64_t decimal = 0;
	for (int i = 0; i < n; i++)
		decimal = decimal * 2 + bin[i];
	return decimal;
}

int* permute(int* block, int* table, int rows, int cols) {
	int* permutation = (int*)malloc(sizeof(int) * rows * cols);
	for (int i = 0; i < rows; i++) {
		for (int j = 0; j < cols; j++) {
			int index = *(table + i * cols + j) ;
			permutation[i * cols + j] = block[index - 1];
		}
	}
	return permutation;
}

void leftShift(int* arr, int n, int shift) {
	int temp[shift];
	for (int i = 0; i < shift; i++)
		temp[i] = arr[i];
	for (int i = 0; i < n - shift; i++)
		arr[i] = arr[i + shift];
	for (int i = 0; i < shift; i++)
		arr[n - shift + i] = temp[i];
}

int** generateSubkeys(int* keyBits) {
	int* keyPlus = permute(keyBits, (int*)pc1, 8, 7);
	int c0[28], d0[28];
	memcpy(c0, keyPlus, sizeof(int) * 28);
	memcpy(d0, keyPlus + 28, sizeof(int) * 28);
	free(keyPlus);

	int **subkeys = (int**)malloc(sizeof(int*) * ROUNDS);
	int shifts[ROUNDS] = {1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1};
	for (int i = 0; i < ROUNDS; i++) {
		subkeys[i] = (int*)malloc(sizeof(int) * SUBKEY_SIZE);

		leftShift(c0, 28, shifts[i]);
		leftShift(d0, 28, shifts[i]);

		int temp[56];
		memcpy(temp, c0, sizeof(c0));
		memcpy(temp + 28, d0, sizeof(d0));

		int* permutation = permute(temp, (int*)pc2, 8, 6);
		memcpy(subkeys[i], permutation, sizeof(int) * SUBKEY_SIZE);
		free(permutation);
	}
	return subkeys;
}

int* substitute(int* block, int* table) {
	int row = binToDec((int[]){block[0], block[5]}, 2);
	int col = binToDec((int[]){block[1], block[2], block[3], block[4]}, 4);
	int element = *(table + row * 16 + col);
	int* bin = intToBin(element, 4);
	return bin;
}

int* feistel(int* block, int* subkey) {
	int *e = permute(block, (int*)e_table, 8, 6);

	int fx[SUBKEY_SIZE];
	for (int i = 0; i < SUBKEY_SIZE; i++)
		fx[i] = e[i] ^ subkey[i];
	free(e);

	int fs[32];
	int (*sTables[8])[16] = {s1, s2, s3, s4, s5, s6, s7, s8};
	for (int i = 0; i < 8; i++) {
		int temp[6];
		memcpy(temp, fx + i * 6, sizeof(int) * 6);
		int* si = substitute(temp, (int*)sTables[i]);
		memcpy(fs + i * 4, si, sizeof(int) * 4);
		free(si);
	}

	int* f = permute(fs, (int*)p, 8, 4);
	return f;
}

int* desRounds(int* initialPermutation, int** subkeys) {
	int l[32], r[32];
	memcpy(l, initialPermutation, sizeof(int) * 32);
	memcpy(r, initialPermutation + 32, sizeof(int) * 32);

	for (int i = 0; i < ROUNDS; i++) {
		int* f = feistel(r, subkeys[i]);
		int ri[32];
		for (int j = 0; j < 32; j++)
			ri[j] = l[j] ^ f[j];
		free(f);
		// Ln = Rn-1
		// Rn = Ln-1 + f(Rn-1, Kn)
		memcpy(l, r, sizeof(r));
		memcpy(r, ri, sizeof(r));
	}

	int* block = (int*)malloc(sizeof(int) * 64);
	memcpy(block, r, sizeof(r));
	memcpy(block + 32, l, sizeof(l));
	return block;
}

int* desEncrypt(uint64_t message, uint64_t key) {
	int* keyBits = intToBin(key, BLOCK_SIZE);
	int* messageBits = intToBin(message, BLOCK_SIZE);
	int** subkeys = generateSubkeys(keyBits);
	int* initialPermutation = permute(messageBits, (int*)ip, 8, 8);
	int* encrypted = desRounds(initialPermutation, subkeys);
	int* finalPermutation = permute(encrypted, (int*)ipInverse, 8, 8);

	free(keyBits);
	free(messageBits);
	for (int i = 0; i < ROUNDS; i++)
		free(subkeys[i]);
	free(subkeys);
	free(initialPermutation);
	free(encrypted);

	return finalPermutation;
}

void reverse(int** subkeys, int n) {
	for (int i = 0; i < n / 2; i++) {
		int* temp = subkeys[i];
		subkeys[i] = subkeys[n - 1 - i];
		subkeys[n - 1 - i] = temp;
	}
}

int* desDecrypt(uint64_t message, uint64_t key) {
	int* keyBits = intToBin(key, BLOCK_SIZE);
	int* messageBits = intToBin(message, BLOCK_SIZE);
	int** subkeys = generateSubkeys(keyBits);
	reverse(subkeys, ROUNDS);
	int* initialPermutation = permute(messageBits, (int*)ip, 8, 8);
	int* decrypted = desRounds(initialPermutation, subkeys);
	int* finalPermutation = permute(decrypted, (int*)ipInverse, 8, 8);

	free(keyBits);
	free(messageBits);
	for (int i = 0; i < ROUNDS; i++)
		free(subkeys[i]);
	free(subkeys);
	free(initialPermutation);
	free(decrypted);

	return finalPermutation;
}

int main() {
	uint64_t key = 0x133457799BBCDFF1;
	uint64_t message = 0x6D61686972616161;

	int* encrypted = desEncrypt(message, key);
	assert(binToDec(encrypted, BLOCK_SIZE) == 0x8C5AEBACBF330817);

	int* decrypted = desDecrypt(0x8C5AEBACBF330817, key);
	assert(binToDec(decrypted, BLOCK_SIZE) == message);

	free(encrypted);
	free(decrypted);
	return 0;
}
