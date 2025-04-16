#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Parte 1: ConversÃ£o entre hexadecimal e bytes
void bytes_to_hex(const uint8_t *bytes, size_t len, char *hex)
{
    size_t i; // Declara a variável antes do loop
    for (i = 0; i < len; i++)
    {
        sprintf(hex + i * 2, "%02x", bytes[i]);
    }
    hex[len * 2] = '\0';
}

void hex_to_bytes(const char *hex, uint8_t *bytes, size_t len)
{
    size_t i; // Declaração movida para fora do loop
    for (i = 0; i < len; i++)
    {
        sscanf(hex + i * 2, "%2hhx", &bytes[i]);
    }
}

// Parte 2: ImplementaÃ§Ã£o da cifra XOR
void xor_buffers(const uint8_t *buf1, const uint8_t *buf2, uint8_t *output, size_t len)
{
    size_t i; // Declaração movida para fora do loop
    for (i = 0; i < len; i++)
    {
        output[i] = buf1[i] ^ buf2[i];
    }
}

void xor_single_byte(const uint8_t *input, uint8_t key, uint8_t *output, size_t len)
{
    size_t i; // Declaração movida para fora do loop
    for (i = 0; i < len; i++)
    {
        output[i] = input[i] ^ key;
    }
}

// Parte 3: Descoberta automÃ¡tica da chave XOR por anÃ¡lise de frequÃªncia
uint8_t find_xor_key(const uint8_t *ciphertext, size_t len)
{
    uint8_t best_key = 0;
    double best_score = 0;
    const char *common_chars = " ETAOINSHRDLUetaoinshrdlu";

    int key; // Declaração movida para fora do loop
    for (key = 0; key < 256; key++)
    {
        double score = 0;

        size_t i; // Declaração movida para fora do loop interno
        for (i = 0; i < len; i++)
        {
            char decoded_char = ciphertext[i] ^ key;
            if (strchr(common_chars, decoded_char))
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
    printf("Iniciando o programa...\n");
    // Parte 4: Decifrando a mensagem com a chave descoberta
    const char *cipher_hex = "072c232c223d2c3e3e2c2328232538202e2c3f3f223d223f2c3c3824072c232c223d2c3e3e2c2328232538202b24212028232c191b1b222e283c382828233f22212c2238393f222e242a2c3f3f223d223f2c2408232c22292c2f22212c3d3f223c38283b2c242c2e222339282e283f002c243e38203d22382e2228202c243e38203e282e38212239283f2024232c002c3e38202122382e223d222928393f222e22232c283e3c3824232c19382922243e3e22272c2b2c373d2c3f3928292c3f223924232c082c3f223924232c272c2b2c373d2c3f392829283b222e281c3828392820242928242c3e392c22202229283f232c3e082220283e202225222028203c38283b243b242c232c3e2e2c3b283f232c3e";
    size_t len = strlen(cipher_hex) / 2;
    uint8_t *ciphertext = (uint8_t *)malloc(len);
    if (!ciphertext)
    {
        fprintf(stderr, "Erro ao alocar memÃ³ria\n");
        return 1;
    }
    hex_to_bytes(cipher_hex, ciphertext, len);
    
    uint8_t key = find_xor_key(ciphertext, len);
    printf("Chave encontrada: %02x (%c)\n", key, key);

    uint8_t *decoded = (uint8_t *)malloc(len + 1);
    if (!decoded)
    {
        fprintf(stderr, "Erro ao alocar memÃ³ria\n");
        free(ciphertext);
        return 1;
    }
    xor_single_byte(ciphertext, key, decoded, len);
    decoded[len] = '\0';

    printf("Mensagem decifrada: %s\n", decoded);

    free(ciphertext);
    free(decoded);
    return 0;
}