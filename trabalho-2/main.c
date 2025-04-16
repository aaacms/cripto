#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <ctype.h>

#define MAX_KEYSIZE 40
#define MIN_KEYSIZE 2
#define NUM_BLOCKS 4

// Frequência de letras em português
float pt_letter_freq[256];

void init_pt_frequency_table() {
    memset(pt_letter_freq, 0, sizeof(pt_letter_freq));
    pt_letter_freq[' '] = 0.183;
    pt_letter_freq['a'] = 0.1463; pt_letter_freq['A'] = 0.1463;
    pt_letter_freq['e'] = 0.1257; pt_letter_freq['E'] = 0.1257;
    pt_letter_freq['o'] = 0.0973; pt_letter_freq['O'] = 0.0973;
    pt_letter_freq['s'] = 0.0781; pt_letter_freq['S'] = 0.0781;
    pt_letter_freq['r'] = 0.0653; pt_letter_freq['R'] = 0.0653;
    pt_letter_freq['n'] = 0.0494; pt_letter_freq['N'] = 0.0494;
    pt_letter_freq['i'] = 0.0618; pt_letter_freq['I'] = 0.0618;
    pt_letter_freq['d'] = 0.0499; pt_letter_freq['D'] = 0.0499;
    pt_letter_freq['m'] = 0.0474; pt_letter_freq['M'] = 0.0474;
    pt_letter_freq['u'] = 0.0463; pt_letter_freq['U'] = 0.0463;
    pt_letter_freq['t'] = 0.0434; pt_letter_freq['T'] = 0.0434;
    pt_letter_freq['c'] = 0.0388; pt_letter_freq['C'] = 0.0388;
    pt_letter_freq['l'] = 0.0278; pt_letter_freq['L'] = 0.0278;
    pt_letter_freq['p'] = 0.0252; pt_letter_freq['P'] = 0.0252;
    pt_letter_freq['v'] = 0.0167; pt_letter_freq['V'] = 0.0167;
    pt_letter_freq['g'] = 0.0130; pt_letter_freq['G'] = 0.0130;
    pt_letter_freq['h'] = 0.0128; pt_letter_freq['H'] = 0.0128;
    pt_letter_freq['q'] = 0.0120; pt_letter_freq['Q'] = 0.0120;
    pt_letter_freq['b'] = 0.0104; pt_letter_freq['B'] = 0.0104;
    pt_letter_freq['f'] = 0.0102; pt_letter_freq['F'] = 0.0102;
    pt_letter_freq['z'] = 0.0047; pt_letter_freq['Z'] = 0.0047;
    pt_letter_freq['j'] = 0.0040; pt_letter_freq['J'] = 0.0040;
    pt_letter_freq['x'] = 0.0021; pt_letter_freq['X'] = 0.0021;
    pt_letter_freq['k'] = 0.0002; pt_letter_freq['K'] = 0.0002;
    pt_letter_freq['w'] = 0.0001; pt_letter_freq['W'] = 0.0001;
    pt_letter_freq['y'] = 0.0001; pt_letter_freq['Y'] = 0.0001;
}

// Base64
unsigned char base64_table[256];

void init_base64_table() {
    memset(base64_table, 0x80, 256);
    for (int i = 'A'; i <= 'Z'; i++) base64_table[i] = i - 'A';
    for (int i = 'a'; i <= 'z'; i++) base64_table[i] = i - 'a' + 26;
    for (int i = '0'; i <= '9'; i++) base64_table[i] = i - '0' + 52;
    base64_table['+'] = 62;
    base64_table['/'] = 63;
    base64_table['='] = 0;
}

unsigned char* base64_decode(const char* input, size_t* out_len) {
    init_base64_table();
    size_t len = strlen(input);
    unsigned char* output = malloc(len * 3 / 4);
    if (!output) return NULL;

    size_t i = 0, j = 0;
    while (i < len) {
        unsigned char a = base64_table[(unsigned char)input[i++]];
        unsigned char b = base64_table[(unsigned char)input[i++]];
        unsigned char c = base64_table[(unsigned char)input[i++]];
        unsigned char d = base64_table[(unsigned char)input[i++]];

        if ((a | b | c | d) & 0x80) continue;

        output[j++] = (a << 2) | (b >> 4);
        if (input[i - 2] != '=') output[j++] = (b << 4) | (c >> 2);
        if (input[i - 1] != '=') output[j++] = (c << 6) | d;
    }

    *out_len = j;
    return output;
}

// Hamming distance
int hamming_distance(const unsigned char* a, const unsigned char* b, int len) {
    int dist = 0;
    for (int i = 0; i < len; i++) {
        unsigned char val = a[i] ^ b[i];
        while (val) {
            dist += val & 1;
            val >>= 1;
        }
    }
    return dist;
}

float normalized_distance(const unsigned char* data, int keysize) {
    float total = 0.0;
    for (int i = 0; i < NUM_BLOCKS - 1; i++) {
        const unsigned char* block1 = data + (i * keysize);
        const unsigned char* block2 = data + ((i + 1) * keysize);
        total += hamming_distance(block1, block2, keysize) / (float)keysize;
    }
    return total / (NUM_BLOCKS - 1);
}

int estimate_keysize(const unsigned char* data, int len) {
    float min_score = INFINITY;
    int best_keysize = 0;

    for (int keysize = MIN_KEYSIZE; keysize <= MAX_KEYSIZE; keysize++) {
        if (keysize * NUM_BLOCKS >= len) break;
        float score = normalized_distance(data, keysize);
        if (score < min_score) {
            min_score = score;
            best_keysize = keysize;
        }
    }

    return best_keysize;
}

// Análise de frequência com tabela pt-BR
float score_text_pt(const unsigned char* data, int len) {
    float score = 0;
    for (int i = 0; i < len; i++) {
        score += pt_letter_freq[data[i]];
    }
    return score;
}

unsigned char break_single_byte_xor_pt(const unsigned char* data, int len) {
    float best_score = -1;
    unsigned char best_key = 0;

    for (int k = 0; k < 256; k++) {
        unsigned char* decoded = malloc(len);
        for (int i = 0; i < len; i++) decoded[i] = data[i] ^ k;
        float s = score_text_pt(decoded, len);
        if (s > best_score) {
            best_score = s;
            best_key = k;
        }
        free(decoded);
    }

    return best_key;
}

void xor_decrypt(const unsigned char* data, int len, const unsigned char* key, int keysize) {
    printf("\nMensagem decifrada:\n");
    for (int i = 0; i < len; i++) {
        putchar(data[i] ^ key[i % keysize]);
    }
    printf("\n");
}

int main() {
    printf("Iniciando análise...\n");
    init_pt_frequency_table();

    FILE* fp = fopen("cifra.base64", "rb");
    if (!fp) {
        perror("Erro ao abrir o arquivo");
        return 1;
    }

    fseek(fp, 0, SEEK_END);
    long fsize = ftell(fp);
    rewind(fp);

    char* base64_data = malloc(fsize + 1);
    fread(base64_data, 1, fsize, fp);
    base64_data[fsize] = '\0';
    fclose(fp);

    size_t decoded_len;
    unsigned char* decoded = base64_decode(base64_data, &decoded_len);
    free(base64_data);

    if (!decoded) {
        printf("Erro ao decodificar base64\n");
        return 1;
    }

    int keysize = estimate_keysize(decoded, decoded_len);
    printf("Tamanho estimado da chave: %d\n", keysize);

    unsigned char* key = malloc(keysize);
    for (int i = 0; i < keysize; i++) {
        int count = 0;
        for (int j = i; j < decoded_len; j += keysize) count++;

        unsigned char* block = malloc(count);
        int idx = 0;
        for (int j = i; j < decoded_len; j += keysize)
            block[idx++] = decoded[j];

        key[i] = break_single_byte_xor_pt(block, count);
        free(block);
    }

    printf("Chave estimada: ");
    for (int i = 0; i < keysize; i++) printf("%c", isprint(key[i]) ? key[i] : '.');
    printf("\n");

    xor_decrypt(decoded, decoded_len, key, keysize);

    free(decoded);
    free(key);
    return 0;
}