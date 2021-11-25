#include <stdio.h>
#include <mbedtls/aes.h>
#include <mbedtls/cipher.h>
#include <string.h>
#include <math.h>
#include <stdlib.h>
#include <mbedtls/base64.h>


#define KEY  "JNb8bOOnlFonD49n"
#define IV  "NFvFrmHqwI8cuzWv"

#define BLOCK_SIZE 16
#define KEY_IV_SIZE 17
//密钥
uint8_t key[KEY_IV_SIZE] = "JNb8bOOnlFonD49n\0";
uint8_t iv[KEY_IV_SIZE] = "NFvFrmHqwI8cuzWv\0";
//明文
const unsigned char *plain = "Caldremch";
//密文
unsigned char cipher[2048] = {0};
//解密后的明文
unsigned char plain_decrypt[96] = {0};


int hex2str(char *digest, char *result, int len) {
    int i;
    char *app = malloc(sizeof(char));
    result = malloc(strlen(digest));

    for (i = 0; i < len; i++) {
        sprintf(app, "%02x", digest[i]);
        strcat(result, app);
    }

    printf("result=%s\n", result);

}


void printHex(unsigned char *array) {
    for (int i = 0; i < strlen(array); ++i) {
        printf("%02x", array[i]);
    }
    printf("\n");
}

uint8_t const hex_chars[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};

char *getHex(unsigned char *array) {
    int len = strlen(array);
    int out_len = 2 * len;
    uint8_t *out = NULL;
    out = (uint8_t *) malloc(out_len * sizeof(uint8_t));
    int j = 0;
    for (int i = 0; i < len; ++i) {
        char temp[5] = {0};
        sprintf(temp, "%02x", array[i]);
        strncat(out, temp, strlen(temp));
//        uint8_t c = array[i];
//        out[j++] =  hex_chars[c & 0xF0 >> 4];
//        out[j++] =  hex_chars[c & 0x0F >> 0];
    }
    return out;
}

void printHexArray(unsigned char *array) {
    printf("{");
    int len = strlen(array);
    for (int i = 0; i < len; ++i) {
        printf("0x%02x", array[i]);
        if (i != len - 1) {
            printf(",");
        }
    }
    printf("}");
    printf("\n");
}


void aes_encrypt(char *content,  uint8_t *out) {

    uint8_t my_key[KEY_IV_SIZE];
    uint8_t my_iv[KEY_IV_SIZE];

    memcpy(my_key, key, KEY_IV_SIZE);
    memcpy(my_iv, iv, KEY_IV_SIZE);

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    //传递对象, 会被改动
    mbedtls_aes_setkey_enc(&aes, my_key, 128); //设置加密密钥

    size_t plain_txt_len = strlen(content);
    size_t block_length = (plain_txt_len / 16) * 16;
    size_t padding_len = plain_txt_len % 16; // 9

    uint8_t *in = NULL;
    uint8_t *cipher = NULL;

    block_length = padding_len > 0 ? (block_length + 16) : block_length;
    int remain = BLOCK_SIZE - padding_len; //16-9 = 7

    size_t malloc_size = block_length*sizeof (uint8_t) +1;

    in = (uint8_t*)malloc(malloc_size);
    cipher = (uint8_t*)malloc(malloc_size);

    memset(in, 0, block_length);
    memset(cipher, 0, block_length);

    //设置终止符, 防止读取越界, 乱码
    in[malloc_size-1] = '\0';
    cipher[malloc_size - 1] = '\0';
    out[malloc_size - 1] = '\0';

    memcpy(in, content, plain_txt_len);

    //add padding
//    for (int i = 0; i < padding_len; ++i) {
//        in[plain_txt_len + i] = remain;
//    }

    /*mbedtls_cipher_info_t  cipher_info;
    mbedtls_cipher_context_t ctx_enc;
    mbedtls_cipher_init(&ctx_enc);
    cipher_info.mode = MBEDTLS_MODE_CBC;
    ctx_enc.cipher_info = &cipher_info;
    mbedtls_cipher_set_padding_mode(&ctx_enc, MBEDTLS_PADDING_PKCS7);
    ctx_enc.add_padding(in, block_length,  plain_txt_len);*/


    mbedtls_cipher_info_t  *cipher_info;
    cipher_info = (mbedtls_cipher_info_t  *)mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CBC);
    mbedtls_cipher_context_t ctx_enc;
    mbedtls_cipher_init(&ctx_enc);
    mbedtls_cipher_setup(&ctx_enc, cipher_info);
    ctx_enc.add_padding(in, block_length,  plain_txt_len);


    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, block_length, my_iv, in, cipher);//ECB加密

    printHex(cipher);
    memcpy(out, cipher, malloc_size);
    printHex(out);

}

void aes_decrypt(uint8_t *content) {

    uint8_t my_key[KEY_IV_SIZE];
    uint8_t my_iv[KEY_IV_SIZE];

    memcpy(my_key, key, KEY_IV_SIZE);
    memcpy(my_iv, iv, KEY_IV_SIZE);

    mbedtls_aes_context aes;
    mbedtls_aes_init(&aes);

    //传递对象, 会被改动
    mbedtls_aes_setkey_dec(&aes, my_key, 128); //设置加密密钥

    size_t plain_txt_len = strlen(content);
    size_t block_length = (plain_txt_len / 16) * 16;
    size_t padding_len = plain_txt_len % 16; // 9

    uint8_t *in = NULL;
    uint8_t *out = NULL;


    block_length = padding_len > 0 ? (block_length + 16) : block_length;
    int remain = BLOCK_SIZE - padding_len; //16-9 = 7

    size_t malloc_size = block_length*sizeof (uint8_t) +1;

    in = (uint8_t*)malloc(malloc_size);
    out = (uint8_t*)malloc(malloc_size);

    memset(in, 0, block_length);
    memset(out, 0, block_length);

    //设置终止符, 防止读取越界, 乱码
    in[malloc_size-1] = '\0';
    out[malloc_size-1] = '\0';

    memcpy(in, content, plain_txt_len);

    //add padding
    for (int i = 0; i < padding_len; ++i) {
        in[plain_txt_len + i] = remain;
    }

//    mbedtls_cipher_set_padding_mode()
    mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_DECRYPT, block_length, my_iv, in, out);//ECB加密

    mbedtls_cipher_info_t  *cipher_info;
    cipher_info = (mbedtls_cipher_info_t  *)mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CBC);
    mbedtls_cipher_context_t ctx_dec;
    mbedtls_cipher_init(&ctx_dec);
    mbedtls_cipher_setup(&ctx_dec, cipher_info);
    //todo need to change to a dynamic value
    size_t out_len = block_length;  //out_len最终会返回真实的长度
    int a = ctx_dec.get_padding(out, block_length, &out_len);
    printf("padding-length=%d, %d\n", a, out_len);

    if(a == 0){
        //has padding
        out[out_len] = '\0';
    }

    printHex(out);
}

int main() {

    uint8_t out[33];
    out[12] = '\0';
    aes_encrypt("Caldremch1234567890abcd", out); //19
    printHex(out);
    printf("解密");
    aes_decrypt(out);


    return 0;
}




