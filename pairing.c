// gcc -o pairing pairing.c -ltepla -lssl -lgmp -lcrypto -std=c99
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include <gmp.h>
#include <dirent.h>
#include <tepla/ec.h>
#include "settings.h"
#include "openssl/evp.h"

#define MESSAGE_SIZE 10000
#define CODE_SIZE MESSAGE_SIZE/sizeof(long)

EC_PAIRING p;
EC_POINT P, Q;
mpz_t limit, a, b, r;

void output_base_variable();
void calc_result_str_convert_to_key_origin(char *key, char * calc_result_str);

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
    FILE *fgetfilesize;
    if((fgetfilesize = fopen(fname, "rb")) == NULL ){
        printf("ファイル %s が開けませんでした。\n", fname);
        return -1;
    }
    fseek(fgetfilesize, 0, SEEK_END);
    long size = ftell(fgetfilesize);
    fclose(fgetfilesize);
    return size;
}

// AESを実際に行う関数
int AES(char *in_fname, char *out_fname, unsigned char *key, unsigned char *iv, int do_encrypt){
    // do_encrypt: 1:暗号化 / 0:復号
    if(do_encrypt == 3 || do_encrypt == 4) do_encrypt = 0;

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

// 鍵を出力する関数
void output_key_txt(int mode, unsigned char *key, unsigned char *outfolda) {
    FILE *outfile;
    char openfilename[1000];
    sprintf(openfilename,"%s/key.txt",outfolda);
    outfile = fopen(openfilename, "w+");
    if (outfile == NULL) {
        printf("鍵を書き出す時にkey.txtを開けませんでした．\n");
        exit(1);
    }
    fprintf(outfile, "%s", key);
    fclose(outfile);
}

// 鍵を読み込む関数
void load_key_txt(int mode, unsigned char *key, unsigned char *infolda) {
    FILE *loadfile;
    char loadfilename[1000];
    sprintf(loadfilename,"%s/key.txt",infolda);
    loadfile = fopen(loadfilename, "r");
    if (loadfile == NULL) {
        printf("鍵を読み込む時にkey.txtを開けませんでした．\n");
        exit(1);
    }
    unsigned char str[1024];
    fgets(str,1024,loadfile);
    strcpy(key, str);
    fclose(loadfile);
}

// 鍵を暗号化する関数
void encipher_key(unsigned char *msg) {
    int i, msg_len = strlen(msg), roop_num = msg_len/sizeof(long) + 1;
    /* -- g = e(P, Q)^r を生成 --- */
    Element g; element_init(g, p->g3);
    pairing_map(g, P, Q, p); element_pow(g, g, r);
    /* --- 平文をlong型にした後、16進数表記のchar型に変換 --- */
    unsigned long enc_msg_long[CODE_SIZE];
    memset(enc_msg_long,0,sizeof(enc_msg_long)); memcpy(enc_msg_long,msg,msg_len);
    /* --- 16進数表記のchar型平文をElement型に変換 --- */
    Element element_msg; element_init(element_msg, p->g3);
    char element_assign_str[1000] = "";
    for(i=0;i<12;i++){
        if(roop_num>i) {
            char tmp[100];
            convert_long_type_into_hex_string(tmp, enc_msg_long[i]);
            strcat(element_assign_str, tmp);
        } else strcat(element_assign_str, "0");
        if(i!=11) strcat(element_assign_str, " ");
    }
    element_set_str(element_msg, element_assign_str);
    /* --- 文字列と鍵を掛け算 --- */
    Element element_msg_key_calc_result;
    element_init(element_msg_key_calc_result, p->g3);
    element_mul(element_msg_key_calc_result, element_msg, g);
    /* --- 計算結果をmsgに挿入 --- */
    element_get_str(msg, element_msg_key_calc_result);
    /* --- 領域解放 --- */
    element_clear(g); element_clear(element_msg);
    element_clear(element_msg_key_calc_result);
}

// 通常の復号を行う関数
void decode_key(char *key) {
    int i;
    /* --- r(aQ) を計算 --- */
    EC_POINT raQ; point_init(raQ, p->g2);
    point_mul(raQ, a, Q); point_mul(raQ, r, raQ);
    /* --- 1/aを計算 --- */
    mpz_t a_one; mpz_init(a_one); mpz_invert(a_one, a, limit);
    /* --- (1/a)Pを計算 --- */
    EC_POINT a1P; point_init(a1P, p->g1); point_mul(a1P, a_one, P);
    /* --- g2 = e((1/a)P, raQ) = e(P, Q)^r --- */
    Element g2; element_init(g2, p->g3); pairing_map(g2, a1P, raQ, p);
    /* --- g2の逆元を計算 --- */
    Element g2_inv; element_init(g2_inv, p->g3); element_inv(g2_inv, g2);
    /* --- 鍵をElementにセットする --- */
    Element mgr; element_init(mgr, p->g3); element_set_str(mgr, key);
    /* --- 割り算する(mg^r/g^r) --- */
    Element calc_result; element_init(calc_result, p->g3);
    element_mul(calc_result, mgr, g2_inv);
    /* --- Elementを16進数文字列に変換 --- */
    int calc_result_str_size = element_get_str_length(calc_result);
    char *calc_result_str;
    if((calc_result_str = (char *)malloc(calc_result_str_size+1)) == NULL) {
        printf("Memory could not be secured.\n"); exit(1);
    }
    element_get_str(calc_result_str, calc_result);
    /* --- 変換 --- */
    calc_result_str_convert_to_key_origin(key, calc_result_str);
    /* --- 領域解放 --- */
    mpz_clears(a_one,NULL);
    point_clear(raQ);point_clear(a1P);
    element_clear(g2);element_clear(g2_inv);element_clear(mgr);
    element_clear(calc_result);
    free(calc_result_str);
}

// 再暗号化の復号を行う関数
void decode_re_key(char *key) {
    int i;
    /* --- r(aQ) を計算 --- */
    EC_POINT raQ; point_init(raQ, p->g2);
    point_mul(raQ, a, Q); point_mul(raQ, r, raQ);
    /* --- 1/aを計算 --- */
    mpz_t a_one; mpz_init(a_one); mpz_invert(a_one, a, limit);
    /* --- (1/a)bP を計算(再暗号化鍵) --- */
    EC_POINT reEncKey; point_init(reEncKey, p->g1);
    point_mul(reEncKey, b, P); point_mul(reEncKey, a_one, reEncKey);
    /* --- raQをg^(rb)に変換 --- */
    Element grb; element_init(grb, p->g3); pairing_map(grb, reEncKey, raQ, p);
    /* --- 1/bを計算 --- */
    mpz_t b_one; mpz_init(b_one); mpz_invert(b_one, b, limit);
    /* --- (g^(rb))^(1/b) = g^r --- */
    Element g3; element_init(g3, p->g3); element_pow(g3, grb, b_one);
    /* --- g3の逆元を計算 --- */
    Element g3_inv; element_init(g3_inv, p->g3); element_inv(g3_inv, g3);
    /* --- 鍵をElementにセットする --- */
    Element mgr; element_init(mgr, p->g3); element_set_str(mgr, key);
    /* --- 割り算する(mg^r/g^r) --- */
    Element calc_result; element_init(calc_result, p->g3);
    element_mul(calc_result, mgr, g3_inv);
    /* --- Elementを16進数文字列に変換 --- */
    int calc_result_str_size = element_get_str_length(calc_result);
    char *calc_result_str;
    if((calc_result_str = (char *)malloc(calc_result_str_size+1)) == NULL) {
        printf("Memory could not be secured.\n"); exit(1);
    }
    element_get_str(calc_result_str, calc_result);
    /* --- 変換 --- */
    calc_result_str_convert_to_key_origin(key, calc_result_str);
    /* --- 領域解放 --- */
    mpz_clears(a_one,b_one,NULL);
    point_clear(raQ);point_clear(reEncKey);
    element_clear(grb);element_clear(g3);element_clear(g3_inv);element_clear(mgr);
    element_clear(calc_result);
    free(calc_result_str);
}

void calc_result_str_convert_to_key_origin(char *key, char * calc_result_str) {
    /* --- strをスペースで分割してlong型に変換 --- */
    int i=1;
    unsigned long dec_msg_long[12];
    char dec_msg_str[12][128], *ptr = strtok(calc_result_str, " ");
    strcpy(dec_msg_str[0], ptr);
    while(ptr != NULL) {
        ptr = strtok(NULL, " ");
        if(ptr != NULL) strcpy(dec_msg_str[i], ptr);
        i++;
    }
    for(i=0;i<12;i++) if(strcmp(dec_msg_str[i], "0")!=0)
        dec_msg_long[i] = convert_hex_string_into_long_type(dec_msg_str[i]);
    /* --- decode --- */
    char msg_decode[CODE_SIZE];
    memset(msg_decode,0,sizeof(msg_decode));
    memcpy(msg_decode,dec_msg_long,sizeof(char)*70); // TODO: 70でいいの？
    print_green_color("plain key = "); printf("%s\n", msg_decode);
    strcpy(key, msg_decode);
}

void AES_folda_inputkey(int mode, char *infolda, char *outfolda, unsigned char *iv){
    DIR *indir;
    struct dirent *dp;
    char original[100];
    char operated[100];
    unsigned char key[1024];

    if((indir = opendir(infolda)) == NULL) {
        printf("フォルダ %s が開けませんでした。\n", infolda);
        exit(-1);
    } else if((opendir(outfolda)) == NULL) {
        printf("フォルダ %s が開けませんでした。\n", outfolda);
        exit(-1);
    }

    if(mode == 1) {
        while(1){
            printf("暗号化を行います\n鍵の入力(15-70文字): "); scanf("%s",key);
            if(15<=strlen(key) && strlen(key)<=70) break;
            else printf("15文字以上70文字以内で入力してください．\n");
        }
    }else if(mode == 2){
//        printf("再暗号化を行います\n");
        printf("再暗号化にデータの変換は必要ありません．\n");
    } else {
        printf("データを復号します\n");
        load_key_txt(mode, key, infolda);
        if(mode == 3) decode_key(key);
        if(mode == 4) decode_re_key(key);
    }
    if(mode != 2){
        for(dp=readdir(indir); dp!=NULL; dp=readdir(indir)){
            if(*dp->d_name != '.') {
                if(strcmp(dp->d_name, "key.txt") != 0) {     // txtの暗号化・復号は必要ない
                    sprintf(original,"%s/%s",infolda,dp->d_name);   // オリジナルのファイル名生成
                    sprintf(operated,"%s/%s",outfolda,dp->d_name);  // 処理ファイル名生成
                    printf("%s -> %s\n", original, operated);
                    AES(original, operated, key, iv, mode);         // ここでファイルの暗号化・復号処理
                }
            }
        }
    }
    if(mode == 1) {
        encipher_key(key);
        output_key_txt(mode, key, outfolda);
    }
    closedir(indir);
}

int main(void){
    int mode;
    int decrypt_mode;
    while (1) {
        printf("暗号化するなら1, 再暗号化するなら2, 復号するなら0を入力: ");
        scanf("%d", &mode);
        if(mode == 0 || mode == 1 || mode == 2) break;
        printf("0,1,2のいずれかを入力してください。\n");
    }

    char infolda[6]  = "";
    char outfolda[6] = "";
    unsigned char iv[] ="0123456789abcdef";

    switch (mode) {
        case 1:
            strcpy(infolda,  "Plain");
            strcpy(outfolda, "Enc");
            break;
        case 2:
            strcpy(infolda,  "Enc");
            strcpy(outfolda, "Enc");
            break;
        case 0:
            while (1) {
                printf("暗号化したものを復号するなら1, 再暗号化したものを復号するなら2を入力: ");
                scanf("%d", &decrypt_mode);
                if(decrypt_mode == 1 || decrypt_mode == 2) break;
                printf("1か2を入力してください。\n");
            }
            if(decrypt_mode == 1) mode = 3; else mode = 4;
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
