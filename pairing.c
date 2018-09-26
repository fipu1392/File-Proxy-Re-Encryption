// gcc -o pairing pairing.c -ltepla -lssl -lgmp -lcrypto -std=c99
#include <sys/time.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>

#include <gmp.h>
#include <dirent.h>
#include <tepla/ec.h>
#include "settings.h"
//#include "encrypto.h"
//#include "openssl/ec.h"
#include "openssl/evp.h"

EC_PAIRING p;
EC_POINT P, Q;
mpz_t limit, a, b, r;

void output_base_variable();

// ペアリングに関する値をセットする関数
void set_crypto_data(){
    /* --- ペアリング初期化 --- */
    pairing_init(p, "ECBN254a");
    /* --- 上限値を設定 --- */
    char limit_char[78]; get_str_data(limit_char, "limit");
    mpz_init(limit); mpz_set_str(limit, limit_char, 10);
    /* --- 点P, Qを設定 --- */
    char P_char[132]; get_str_data(P_char, "P");
    point_init(P, p->g1); point_set_str(P, P_char);
    char Q_char[261]; get_str_data(Q_char, "Q");
    point_init(Q, p->g2); point_set_str(Q, Q_char);
    /* --- 秘密鍵a,bと乱数rを設定 --- */
    char a_char[78], b_char[78], r_char[78] ;
    get_str_data(a_char, "a"); get_str_data(b_char, "b"); get_str_data(r_char, "r");
    mpz_init(a); mpz_init(b); mpz_init(r);
    mpz_set_str(a, a_char, 10); mpz_set_str(b, b_char, 10); mpz_set_str(r, r_char, 10);
    /* --- 出力テスト --- */
//  output_base_variable();
}

// ファイルのサイズを計測する関数
unsigned long GetFileSize(char *fname){
    long size;
    FILE *fgetfilesize;
    if((fgetfilesize = fopen(fname, "rb")) == NULL ){
        printf("ファイル %s が開けませんでした。\n", fname);
        return -1;
    }
    fseek(fgetfilesize, 0, SEEK_END);
    size = ftell(fgetfilesize);
    fclose(fgetfilesize);
    return size;
}

// AESを実際に行う関数
int AES(char *in_fname, char *out_fname, unsigned char *key, unsigned char *iv, int do_encrypt){
    // do_encrypt: 1:暗号化 / 0:復号
    // Allow enough space in output buffer for additional block
    // Bogus key and IV: we'd normally set these from another source.

    // unsigned char inbuf[1024], outbuf[1024 + EVP_MAX_BLOCK_LENGTH];
    unsigned char *inbuf, *outbuf;
    int inlen, outlen;

    FILE *fin, *fout;
    fin  = fopen(in_fname, "rb");
    fout = fopen(out_fname, "wb");

    //バッファサイズの設定
    unsigned long in_size;
    in_size = GetFileSize(in_fname);
    printf("size = %lu\n", in_size);

    if((inbuf = malloc(sizeof(char)*in_size)) == NULL){
        printf("inbufのメモリが確保できませんでした。\n");
        exit(-1);
    }
    if((outbuf = malloc(sizeof(char)*(int)(in_size+EVP_MAX_BLOCK_LENGTH))) == NULL) {
        printf("outbufのメモリが確保できませんでした。\n");
        exit(-1);
    }

    EVP_CIPHER_CTX ctx;
    EVP_CIPHER_CTX_init(&ctx);
    EVP_CipherInit_ex(&ctx, EVP_aes_128_cbc(), NULL, NULL, NULL, do_encrypt);
    OPENSSL_assert(EVP_CIPHER_CTX_key_length(&ctx) == 16);
    OPENSSL_assert(EVP_CIPHER_CTX_iv_length(&ctx) == 16);

    //AES128の鍵と初期ベクトルを設定
    EVP_CipherInit_ex(&ctx, NULL, NULL, key, iv, do_encrypt);
    for(;;){
        // ファイルポインタfinからバッファinbufにサイズ1のデータin_size個を読み込む
        // inlenには読み込んだ個数を返却
        inlen = fread(inbuf, 1, in_size, fin);
        if(inlen <= 0) break;
        if(!EVP_CipherUpdate(&ctx, outbuf, &outlen, inbuf, inlen)){ // Error
            EVP_CIPHER_CTX_cleanup(&ctx);
            fcloses(fin, fout, NULL);
            frees(inbuf, outbuf, NULL);
            return 0;
        }
        fwrite(outbuf, 1, outlen, fout);
    }
    if(!EVP_CipherFinal_ex(&ctx, outbuf, &outlen)){ // Error
        EVP_CIPHER_CTX_cleanup(&ctx);
        fcloses(fin, fout, NULL);
        frees(inbuf, outbuf, NULL);
        return 0;
    }
    fwrite(outbuf, 1, outlen, fout);
    EVP_CIPHER_CTX_cleanup(&ctx);
    fcloses(fin, fout, NULL);
    frees(inbuf, outbuf, NULL);
    return 1;
}

// 暗号化時に鍵をメモに出力する関数
void make_crypted_AES_key_memo(unsigned char *key, unsigned char *outfolda) {
    FILE *outfile;
    char openfilename[1000];
    sprintf(openfilename,"%s/key.txt",outfolda);
    outfile = fopen(openfilename, "w+");
    if (outfile == NULL) {
        printf("cannot open\n");
        exit(1);
    }
    fprintf(outfile, "%s", key);
    fclose(outfile);
}

// 復号時に鍵を読み込む関数　(今は復号の関数もある deprecated)
void load_and_decrypto_AES_key(unsigned char *key, unsigned char *infolda) {
    FILE *loadfile;
    char loadfilename[1000];
    sprintf(loadfilename,"%s/key.txt",infolda);
    loadfile = fopen(loadfilename, "r");
    if (loadfile == NULL) {
        printf("cannot open\n");
        exit(1);
    }

    unsigned char str[1024];
//    while((fgets(str,1024,loadfile))!=NULL){
//        printf("str: %s\n",str);
//    }
    fgets(str,1024,loadfile);
    strcpy(key, str);
    fclose(loadfile);
}

void AES_folda_inputkey(int mode, char *infolda, char *outfolda, unsigned char *iv){
    DIR *indir;
    struct dirent *dp;
    char original[100];
    char operated[100];
    unsigned char key[128];

    if((indir = opendir(infolda)) == NULL) {
        printf("フォルダ %s が開けませんでした。\n", infolda);
        exit(-1);
    } else if((opendir(outfolda)) == NULL) {
        printf("フォルダ %s が開けませんでした。\n", outfolda);
        exit(-1);
    }

    if(mode == 1) {
        printf("暗号化を行います\n鍵の入力: ");
        scanf("%s",key);
        make_crypted_AES_key_memo(key, outfolda);
    } else {
        printf("データを復号します\n");
        load_and_decrypto_AES_key(key, infolda); //TODO: 鍵長に注意
        printf("鍵を読み込みました．key: %s\n", key);
        // TODO: 復号する関数
        printf("鍵を復号しました．key: %s\n", key);
    }

    for(dp=readdir(indir); dp!=NULL; dp=readdir(indir)){
        if(*dp->d_name != '.') {
            if(strcmp(dp->d_name, "key.txt")) continue;     // key.txtの復号は必要ない
            sprintf(original,"%s/%s",infolda,dp->d_name);   // オリジナルのファイル名生成
            sprintf(operated,"%s/%s",outfolda,dp->d_name);  // 処理ファイル名生成
            printf("%s -> %s\n", original, operated);
            AES(original, operated, key, iv, mode);
        }
    }
    closedir(indir);
}

int main(void){
    int mode;
    while (1) {
        printf("暗号化するなら1, 復号するなら0を入力: ");
        scanf("%d", &mode);
        if(mode == 0 || mode == 1) break;
        printf("0か1を入力してください。\n");
    }

    char infolda[6]  = "";
    char outfolda[6] = "";
    unsigned char iv[] ="0123456789abcdef";

    switch (mode) {
        case 1:
            strcpy(infolda,  "Plain");
            strcpy(outfolda, "Enc");
            break;
        case 0:
            strcpy(infolda,  "Enc");
            strcpy(outfolda, "Dec");
            break;
    }
    set_crypto_data();
    AES_folda_inputkey(mode, infolda, outfolda, iv);
    return 0;
}

void output_base_variable() {
    print_green_color("---------------- CRYPTO DATA ----------------\n");
    print_green_color("limit : "); gmp_printf ("%Zd\n", limit);
    print_green_color("P     : "); point_print(P);
    print_green_color("Q     : "); point_print(Q);
    print_green_color("a     : "); gmp_printf ("%Zd\n", a);
    print_green_color("b     : "); gmp_printf ("%Zd\n", b);
    print_green_color("r     : "); gmp_printf ("%Zd\n", r);
    print_green_color("---------------------------------------------\n");
}
