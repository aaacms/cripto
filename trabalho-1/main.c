#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

static const char hex_digits[] = "0123456789abcdef";

static const char base64_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

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

    unsigned char decoding_table[64] = {0};
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

int main()
{

    const char *base64_input = "QWNvcmRhUGVkcmluaG9RdWVob2pldGVtY2FtcGVvbmF0bw==";

    size_t raw_len;
    unsigned char *raw_data = base64_to_raw(base64_input, &raw_len);

    char *hex_output = raw_to_hex(raw_data, raw_len);

    printf("Base64     : %s\n", base64_input);
    printf("Hexadecimal: %s\n", hex_output);
    printf("Raw        : %s\n", raw_data);

    free(raw_data);
    free(hex_output);

    return 0;
}