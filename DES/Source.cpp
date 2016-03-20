#include <iostream>
#include <Windows.h>
using namespace std;

void Encode(void*, void*, int, void*);
void Decode(void*, void*, int, void*);

int main(int argc, char ** argv)
{
	//SetCurrentDirectory(L"E:\\VisualStudioProjects\\DES\\Debug");

	const int keylen = 8 + 1;
	//cout << "DES\nenter key (8 characters):\n";

	if (argc < 5)
	{
		cout << "usage: DES in out keyfile (encode ? 1 : 0)";
		return 0;
	}

	const int msglen = 8192;
	char * message = new char[msglen * 2];
	char * crypted = message + msglen;

	char * key = new char[9];

	DWORD len = 0;

	HANDLE hKey = CreateFileA(argv[3], GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
	ReadFile(hKey, key, 8, &len, 0);
	CloseHandle(hKey);

	memset(message, 0, msglen * 2);

	HANDLE hIn = CreateFileA(argv[1], GENERIC_READ, FILE_SHARE_READ, 0, OPEN_EXISTING, 0, 0);
	HANDLE hOut = CreateFileA(argv[2], GENERIC_WRITE, FILE_SHARE_READ, 0, CREATE_NEW, 0, 0);

	do
	{
		ReadFile(hIn, message, msglen, &len, 0);
		if (len % 8 > 0)
		{
			len += (8 - len % 8);
		}

		if (argv[4][0] == '0')
		{
			Decode(key, message, len, crypted);
		}
		else
		{
			Encode(key, message, len, crypted);
		}

		WriteFile(hOut, crypted, len, &len, 0);

	} while (len == msglen);

	CloseHandle(hIn);
	CloseHandle(hOut);

	delete[] key;
	delete[] message;
	return 0;
}

void GenerateKeys(__int64*, void*);
inline int Shift28(int, int);
void EncodeBlock(__int64*, void*, void*);
int FModule(int, __int64);
void Code(void*, void*, int, void*, bool);

void Encode(void* key, void* message, int len, void* output)
{
	Code(key, message, len, output, true);
}

void Decode(void* key, void* message, int len, void* output)
{
	Code(key, message, len, output, false);
}

void Code(void* key, void* message, int len, void* output, bool encode)
{
	__int64 * keys = new __int64[16];
	GenerateKeys(keys, key);
	if (!encode)
	{
		for (int i = 0; i < 8; ++i)
		{
			swap(keys[i], keys[15 - i]);
		}
	}

	for (int i = 0; i < len; i += 8)
	{
		EncodeBlock(keys, (char*)message + i, (char*)output + i);
	}

	delete[] keys;
}

struct des_block
{
	int L;
	int R;
	void swap()
	{
		int t = L;
		L = R;
		R = t;
	}
};

union des_block_union
{
	__int64 LR64;
	des_block LR;
};

void EncodeBlock(__int64 * keys, void* message, void* output)
{
	const int InitialPermutation[] = { 57, 49, 41, 33, 25, 17, 9, 1, 59, 51, 43, 35, 27, 19, 11, 3, 61, 53, 45, 37, 29, 21, 13, 5, 63, 55, 47, 39, 31, 23, 15, 7, 56, 48, 40, 32, 24, 16, 8, 0, 58, 50, 42, 34, 26, 18, 10, 2, 60, 52, 44, 36, 28, 20, 12, 4, 62, 54, 46, 38, 30, 22, 14, 6 };

	des_block_union data = { 0 };

	{
		__int64 _message = *((__int64*)message);
		for (int i = 0; i < 64; ++i)
		{
			data.LR64 |= ((_message >> InitialPermutation[i]) & 1) << i;
		}
	}

	for (int i = 0; i < 16; ++i)
	{
		data.LR.L = FModule(data.LR.R, keys[i]) ^ data.LR.L;
		data.LR.swap();
	}

	data.LR.swap();

	const int LastPermutation[] = { 39, 7, 47, 15, 55, 23, 63, 31, 38, 6, 46, 14, 54, 22, 62, 30, 37, 5, 45, 13, 53, 21, 61, 29, 36, 4, 44, 12, 52, 20, 60, 28, 35, 3, 43, 11, 51, 19, 59, 27, 34, 2, 42, 10, 50, 18, 58, 26, 33, 1, 41, 9, 49, 17, 57, 25, 32, 0, 40, 8, 48, 16, 56, 24 };

	__int64 _output = 0;

	for (int i = 0; i < 64; ++i)
	{
		_output |= ((data.LR64 >> LastPermutation[i]) & 1) << i;
	}

	*((__int64*)output) = _output;
}

int FModule(int R, __int64 key)
{
	const int PermutationE[] = { 31, 0, 1, 2, 3, 4, 3, 4, 5, 6, 7, 8, 7, 8, 9, 10, 11, 12, 11, 12, 13, 14, 15, 16, 15, 16, 17, 18, 19, 20, 19, 20, 21, 22, 23, 24, 23, 24, 25, 26, 27, 28, 27, 28, 29, 30, 31, 0 };
	__int64 ER = 0;
	for (int i = 0; i < 48; ++i)
	{
		ER |= ((__int64)((R >> PermutationE[i]) & 1)) << i;
	}

	ER ^= key;

	const int S[8][64] = { { 14, 4, 13, 1, 2, 15, 11, 8, 3, 10, 6, 12, 5, 9, 0, 7, 0, 15, 7, 4, 14, 2, 13, 1, 10, 6, 12, 11, 9, 5, 3, 8, 4, 1, 14, 8, 13, 6, 2, 11, 15, 12, 9, 7, 3, 10, 5, 0, 15, 12, 8, 2, 4, 9, 1, 7, 5, 11, 3, 14, 10, 0, 6, 13 },
	{ 15, 1, 8, 14, 6, 11, 3, 4, 9, 7, 2, 13, 12, 0, 5, 10, 3, 13, 4, 7, 15, 2, 8, 14, 12, 0, 1, 10, 6, 9, 11, 5, 0, 14, 7, 11, 10, 4, 13, 1, 5, 8, 12, 6, 9, 3, 2, 15, 13, 8, 10, 1, 3, 15, 4, 2, 11, 6, 7, 12, 0, 5, 14, 9 },
	{ 10, 0, 9, 14, 6, 3, 15, 5, 1, 13, 12, 7, 11, 4, 2, 8, 13, 7, 0, 9, 3, 4, 6, 10, 2, 8, 5, 14, 12, 11, 15, 1, 13, 6, 4, 9, 8, 15, 3, 0, 11, 1, 2, 12, 5, 10, 14, 7, 1, 10, 13, 0, 6, 9, 8, 7, 4, 15, 14, 3, 11, 5, 2, 12 },
	{ 7, 13, 14, 3, 0, 6, 9, 10, 1, 2, 8, 5, 11, 12, 4, 15, 13, 8, 11, 5, 6, 15, 0, 3, 4, 7, 2, 12, 1, 10, 14, 9, 10, 6, 9, 0, 12, 11, 7, 13, 15, 1, 3, 14, 5, 2, 8, 4, 13, 15, 0, 6, 10, 1, 13, 8, 9, 4, 5, 11, 12, 7, 2, 14 },
	{ 2, 12, 4, 1, 7, 10, 11, 6, 8, 5, 3, 15, 13, 0, 14, 9, 14, 11, 2, 12, 4, 7, 13, 1, 5, 0, 15, 10, 3, 8, 9, 6, 4, 2, 1, 11, 10, 13, 7, 8, 15, 9, 12, 5, 6, 3, 0, 14, 11, 8, 12, 7, 1, 14, 2, 13, 6, 15, 0, 9, 10, 4, 5, 3 },
	{ 12, 1, 10, 15, 9, 2, 6, 8, 0, 13, 3, 4, 14, 7, 5, 11, 10, 15, 4, 2, 7, 12, 9, 5, 6, 1, 13, 14, 0, 11, 3, 8, 9, 14, 15, 5, 2, 8, 12, 3, 7, 0, 4, 10, 1, 13, 11, 6, 4, 3, 2, 12, 9, 5, 15, 10, 11, 14, 1, 4, 6, 0, 8, 13 },
	{ 4, 11, 2, 14, 15, 0, 8, 13, 3, 12, 9, 7, 5, 10, 6, 1, 13, 0, 11, 7, 4, 9, 1, 10, 14, 3, 5, 12, 2, 15, 8, 6, 1, 4, 11, 13, 12, 3, 7, 14, 10, 15, 6, 8, 0, 5, 9, 2, 6, 11, 13, 8, 1, 4, 10, 7, 9, 5, 0, 15, 14, 2, 3, 12 },
	{ 13, 2, 8, 4, 6, 15, 11, 1, 10, 9, 3, 14, 5, 0, 12, 7, 1, 15, 13, 8, 10, 3, 7, 4, 12, 5, 6, 11, 0, 14, 9, 2, 7, 11, 4, 1, 9, 12, 14, 2, 0, 6, 10, 13, 15, 3, 5, 8, 2, 1, 14, 7, 4, 10, 8, 13, 15, 12, 9, 0, 3, 5, 6, 11 } };

	int PR = 0;

	for (int i = 0; i < 8; ++i)
	{
		int t = (ER >> (i * 6)) & 0x3f;
		t = ((t >> 1) & 0xf) | ((t << 4) & 0x10) | (t & 0x20);
		PR |= S[i][t] << (i * 4);
	}

	const int PermutationP[] = { 15, 6, 19, 20, 28, 11, 27, 16, 0, 4, 22, 25, 4, 17, 30, 9, 1, 7, 23, 13, 31, 26, 2, 8, 18, 12, 29, 5, 21, 10, 3, 24 };
	int P = 0;

	for (int i = 0; i < 32; ++i)
	{
		P |= ((PR >> PermutationP[i]) & 1) << i;
	}

	return P;
}

void GenerateKeys(__int64* keys, void* _key)
{
	__int64 key = *((__int64*)_key);

	int * C = new int[32];
	int * D = C + 16;

	const int PermutatedChoice1C[] = { 56, 48, 40, 32, 24, 16, 8, 0, 57, 49, 41, 33, 25, 17, 9, 1, 58, 50, 42, 34, 26, 18, 10, 2, 59, 51, 43, 35 };
	const int PermutatedChoice1D[] = { 62, 54, 46, 38, 30, 22, 14, 6, 61, 53, 45, 37, 29, 21, 13, 5, 60, 52, 44, 36, 28, 20, 12, 4, 27, 19, 11, 3 };

	const int PermutatedChoice2[] { 13, 16, 10, 23, 0, 4, 2, 27, 14, 5, 20, 9, 22, 18, 11, 3, 25, 7, 15, 6, 26, 19, 12, 1, 40, 51, 30, 36, 46, 54, 29, 39, 50, 44, 32, 47, 43, 48, 38, 55, 33, 52, 45, 41, 49, 35, 28, 31 };

	const int KeysGeneratorShifts[] = { 1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1 };

	C[15] = 0;
	D[15] = 0;

	for (int i = 0; i < 28; ++i)
	{
		C[15] |= ((key >> PermutatedChoice1C[i]) & 1) << i;
		D[15] |= ((key >> PermutatedChoice1D[i]) & 1) << i;
	}

	C[0] = Shift28(C[15], 1);
	D[0] = Shift28(D[15], 1);

	for (int i = 1; i < 16; ++i)
	{
		C[i] = Shift28(C[i - 1], KeysGeneratorShifts[i]);
		D[i] = Shift28(D[i - 1], KeysGeneratorShifts[i]);
	}

	for (int i = 0; i < 16; ++i)
	{
		keys[i] = 0;
		__int64 CD = ((__int64)C[i]) | (((__int64)D[i]) << 28);
		for (int j = 0; j < 48 /*sizeof(PermutatedChoice2) / sizeof(PermutatedChoice2[0])*/; ++j)
		{
			keys[i] |= (((CD >> PermutatedChoice2[j]) & 1) << j);
		}
	}

	delete[] C;
}

inline int Shift28(int value, int n)
{
	return ((value >> n) | (value << (28 - n))) & 0x0fffffff;
}