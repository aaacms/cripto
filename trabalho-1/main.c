#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

static const char hex_digits[] = "0123456789abcdef";

static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

const char portuguese_common_chars[] = " AEOSRINDMUTCLPVGHQBFZJXKWYaeosrindmutclpvghqbfzjxkwy";

char *raw_to_hex(const unsigned char *raw_data, size_t len)
{
    char *hex_str = malloc((len * 2) + 1);
    if (!hex_str)
        return NULL;

    for (size_t i = 0; i < len; i++)
    {
        hex_str[i * 2] = hex_digits[raw_data[i] >> 4];       // isola os 4 bits mais significativos
        hex_str[i * 2 + 1] = hex_digits[raw_data[i] & 0x0F]; // isola os 4 bits menos significativos com máscara AND
    }
    hex_str[len * 2] = '\0';
    return hex_str;
}

unsigned char *hex_to_raw(const char *hex_str, size_t *out_len)
{
    size_t hex_len = strlen(hex_str);
    if (hex_len % 2 != 0)
        return NULL;

    size_t len = hex_len / 2;
    unsigned char *raw_data = malloc(len);
    if (!raw_data)
        return NULL;

    for (size_t i = 0; i < len; i++)
    {
        char byte_str[3] = {hex_str[i * 2], hex_str[i * 2 + 1], '\0'};
        raw_data[i] = (unsigned char)strtol(byte_str, NULL, 16);
    }

    if (out_len)
        *out_len = len;
    return raw_data;
}

char *raw_to_base64(const unsigned char *data, size_t len)
{
    size_t out_len = 4 * ((len + 2) / 3);
    char *base64_str = malloc(out_len + 1);
    if (!base64_str)
        return NULL;

    size_t i, j;
    for (i = 0, j = 0; i < len;)
    {
        // Lê até três bytes; se não houver bytes suficientes, utiliza 0 para preencher.
        unsigned int octet_a = i < len ? data[i++] : 0;
        unsigned int octet_b = i < len ? data[i++] : 0;
        unsigned int octet_c = i < len ? data[i++] : 0;

        // Combina os três bytes em um inteiro de 24 bits.
        unsigned int triple = (octet_a << 16) | (octet_b << 8) | octet_c;

        // 0x3F == 0011 1111
        base64_str[j++] = base64_chars[(triple >> 18) & 0x3F];
        base64_str[j++] = base64_chars[(triple >> 12) & 0x3F];
        base64_str[j++] = base64_chars[(triple >> 6) & 0x3F];
        base64_str[j++] = base64_chars[triple & 0x3F];
    }

    // calcula quantos '=' são necessários (0, 1 ou 2)
    size_t pad = (3 - (len % 3)) % 3;

    if (pad > 0)
    {
        // preenche os últimos 'pad' caracteres com '='
        memset(base64_str + out_len - pad, '=', pad);
    }

    base64_str[out_len] = '\0';
    return base64_str;
}

void build_decoding_table(unsigned char *decoding_table)
{
    for (int i = 0; i < 64; i++)
    {
        decoding_table[(unsigned char)base64_chars[i]] = i;
    }
}

unsigned char *base64_to_raw(const char *base64_str, size_t *out_len)
{
    size_t len = strlen(base64_str);
    if (len % 4 != 0)
        return NULL; // O comprimento deve ser múltiplo de 4.

    // Verifica os caracteres de padding '=' no final.
    size_t padding = 0;
    if (len > 0 && base64_str[len - 1] == '=')
        padding++;
    if (len > 1 && base64_str[len - 2] == '=')
        padding++;

    size_t decoded_len = (len / 4) * 3 - padding;
    unsigned char *data = malloc(decoded_len);
    if (!data)
        return NULL;

    unsigned char decoding_table[256] = {0};
    build_decoding_table(decoding_table);

    size_t i, j;
    for (i = 0, j = 0; i < len;)
    {
        // Converte cada caractere Base64 para o seu valor de 6 bits.
        unsigned int sextet_a = base64_str[i] == '=' ? 0 : decoding_table[(unsigned char)base64_str[i]];
        i++;
        unsigned int sextet_b = base64_str[i] == '=' ? 0 : decoding_table[(unsigned char)base64_str[i]];
        i++;
        unsigned int sextet_c = base64_str[i] == '=' ? 0 : decoding_table[(unsigned char)base64_str[i]];
        i++;
        unsigned int sextet_d = base64_str[i] == '=' ? 0 : decoding_table[(unsigned char)base64_str[i]];
        i++;

        // Concatena os 4 sextetos em 24 bits
        unsigned int tresBytes = (sextet_a << 18) | (sextet_b << 12) | (sextet_c << 6) | sextet_d;

        // Extraí os bytes (8 bits cada) dos 24 bits formados
        if (j < decoded_len)
            data[j++] = (tresBytes >> 16) & 0xFF;
        if (j < decoded_len)
            data[j++] = (tresBytes >> 8) & 0xFF;
        if (j < decoded_len)
            data[j++] = tresBytes & 0xFF;
    }
    if (out_len)
        *out_len = decoded_len;
    return data;
}

// parte 2
void xor_cipher(const unsigned char *plaintext,
                const unsigned char *key,
                unsigned char *ciphertext,
                size_t len)
{
    for (size_t i = 0; i < len; i++)
    {
        ciphertext[i] = plaintext[i] ^ key[i];
    }
    ciphertext[len] = '\0'; // Adiciona o terminador nulo
}

void xor_cipher_byte(const unsigned char *in,
                     unsigned char key,
                     unsigned char *out,
                     size_t len)
{
    for (size_t i = 0; i < len; i++)
        out[i] = in[i] ^ key;
}

// parte 3
unsigned char find_xor_key(const unsigned char *ciphertext, size_t len)
{
    unsigned char best_key = 0;
    double best_score = 0;

    int key; // Declaração movida para fora do loop
    for (key = 0; key < 256; key++)
    {
        double score = 0;

        size_t i; // Declaração movida para fora do loop interno
        for (i = 0; i < len; i++)
        {
            char decoded_char = ciphertext[i] ^ key;
            if (strchr(portuguese_common_chars, decoded_char))
            {
                score++;
            }
        }

        if (score > best_score)
        {
            best_score = score;
            best_key = key;
        }
    }
    return best_key;
}

int main()
{
    // parte 1
    const char *base64_input = "QWNvcmRhUGVkcmluaG9RdWVob2pldGVtY2FtcGVvbmF0bw==";

    size_t raw_len;
    unsigned char *raw_data = base64_to_raw(base64_input, &raw_len);

    char *hex_output = raw_to_hex(raw_data, raw_len);

    printf("Base64     : %s\n", base64_input);
    printf("Hexadecimal: %s\n", hex_output);
    printf("Raw        : %s\n", raw_data);

    free(raw_data);
    free(hex_output);

    // parte 2
    const char *hex_plaintext = "41636f72646150656472696e686f517565686f6a6574656d63616d70656f6e61746f";
    const char *hex_key = "0b021e0701003e0a0d060c0807063d1a0b0f0e060a1a020c0f0e03170403010f130e";

    size_t key_len, plaintext_len;
    unsigned char *plaintext = hex_to_raw(hex_plaintext, &plaintext_len);
    unsigned char *key = hex_to_raw(hex_key, &key_len);

    unsigned char *raw_ciphertext = (unsigned char *)malloc(plaintext_len + 1);
    xor_cipher(plaintext, key, raw_ciphertext, plaintext_len);

    char *hex_ciphertext = raw_to_hex(raw_ciphertext, plaintext_len);
    printf("Texto cifrado (hex): %s\n", hex_ciphertext);

    printf("Texto cifrado: %s\n", raw_ciphertext);

    free(raw_ciphertext);
    free(hex_ciphertext);
    free(plaintext);

    // parte 3
    const char *hex_ciphertext2 = "072c232c223d2c3e3e2c2328232538202e2c3f3f223d223f2c3c3824072c232c223d2c3e3e2c2328232538202b24212028232c191b1b222e283c382828233f22212c2238393f222e242a2c3f3f223d223f2c2408232c22292c2f22212c3d3f223c38283b2c242c2e222339282e283f002c243e38203d22382e2228202c243e38203e282e38212239283f2024232c002c3e38202122382e223d222928393f222e22232c283e3c3824232c19382922243e3e22272c2b2c373d2c3f3928292c3f223924232c082c3f223924232c272c2b2c373d2c3f392829283b222e281c3828392820242928242c3e392c22202229283f232c3e082220283e202225222028203c38283b243b242c232c3e2e2c3b283f232c3e";
    size_t len2;
    unsigned char *ciphertext2 = hex_to_raw(hex_ciphertext2, &len2);

    unsigned char key2 = find_xor_key(ciphertext2, len2);
    printf("Chave encontrada: %02x (%c)\n", key2, key2);

    unsigned char *decoded = (unsigned char *)malloc(len2 + 1);
    if (!decoded)
    {
        printf("Erro ao alocar memória\n");
        free(ciphertext2);
        return 1;
    }

    xor_cipher_byte(ciphertext2, key2, decoded, len2);

    printf("Texto decifrado: %s\n", decoded);
    free(decoded);
    free(ciphertext2);

    return 0;
}