// gcc -o pairing pairing.c -ltepla -lssl -lgmp -lcrypto -fopenmp
#include <sys/time.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <omp.h>

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
char str[1000];

void set_crypto_data();
char *get_str_data(char *user, char *data);
void calc_result_str_convert_to_key_origin(char *key, char * calc_result_str);

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
    in_size = get_file_size(in_fname);
    printf("[size = %9lu]", in_size);

    if((inbuf = malloc(sizeof(char)*in_size)) == NULL)
        error_notice(1000, "inbuf", __func__, __LINE__);
    if((outbuf = malloc(sizeof(char)*(int)(in_size+EVP_MAX_BLOCK_LENGTH))) == NULL)
        error_notice(1000, "outbuf", __func__, __LINE__);

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
void output_key_txt(char *output_name, unsigned char *outfolda, unsigned char *key) {
    FILE *outfile;
    char openfilename[1000];
    sprintf(openfilename,"%s/%s.txt", outfolda, output_name);
    outfile = fopen(openfilename, "w+");
    if (outfile == NULL) error_notice(1001, output_name, __func__, __LINE__);
    fprintf(outfile, "%s", key);
    fclose(outfile);
}

// 鍵を読み込む関数
void load_key_txt(char *load_name, unsigned char *infolda, unsigned char *key){
    FILE *loadfile;
    char loadfilename[1000];
    sprintf(loadfilename,"%s/%s.txt",infolda, load_name);
    loadfile = fopen(loadfilename, "r");
    if (loadfile == NULL) error_notice(1002, load_name, __func__, __LINE__);
    unsigned char str[1024]; fgets(str,1024,loadfile); strcpy(key, str);
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

// 鍵を再暗号化する関数
void re_encipher_key(unsigned char *raQ_char, char *keyC) {
/* --- r(aQ) をセット --- */
    EC_POINT raQ; point_init(raQ, p->g2); point_set_str(raQ, raQ_char);
/* --- 再暗号化鍵((1/a)bP)を作成 --- */
    /* --- aをセット --- */
    mpz_set_str(a, get_str_data("A", "a"), 10);
    /* --- 1/aを計算 --- */
    mpz_t a_one; mpz_init(a_one); mpz_invert(a_one, a, limit);
    /* --- bPをセット --- */
    EC_POINT bP; point_init(bP, p->g1); point_set_str(bP, get_str_data("A", "bP"));
    /* --- 再暗号化鍵の生成 --- */
    EC_POINT re_Key; point_init(re_Key, p->g1);
    point_mul(re_Key, a_one, bP);
/* --- grb = e((1/a)bP, raQ) = e(P, Q)^rb --- */
    Element grb; element_init(grb, p->g3); pairing_map(grb, re_Key, raQ, p);
    int grb_char_size = element_get_str_length(grb);
    char *grb_char;
    if((grb_char = (char *)malloc(element_get_str_length(grb)+1)) == NULL)
        error_notice(1000, "grb_char", __func__, __LINE__);
    element_get_str(grb_char, grb);
    strcpy(keyC, grb_char);
/* --- 領域解放 --- */
    point_clear(bP); point_clear(re_Key);
    mpz_clear(a_one); element_clear(grb);
}

// 通常の復号を行う関数
void decode_key(char *key, const char *raQ_char) {
    /* --- r(aQ) をセット --- */
    EC_POINT raQ; point_init(raQ, p->g2);
    point_set_str(raQ, raQ_char);
    /* --- aをセット --- */
    mpz_set_str(a, get_str_data("A", "a"), 10);
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
    if((calc_result_str = (char *)malloc(calc_result_str_size+1)) == NULL)
        error_notice(1000, "calc_result_str", __func__, __LINE__);
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
void decode_re_key(char *key, char *grb_char) {
    /* --- g^(rb)をセット --- */
    Element grb; element_init(grb, p->g3); element_set_str(grb, grb_char);
    /* --- bをセット --- */
    mpz_set_str(b, get_str_data("B", "b"), 10);
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
    if((calc_result_str = (char *)malloc(calc_result_str_size+1)) == NULL)
        error_notice(1000, "calc_result_str", __func__, __LINE__);
    element_get_str(calc_result_str, calc_result);
    /* --- 変換 --- */
    calc_result_str_convert_to_key_origin(key, calc_result_str);
    /* --- 領域解放 --- */
    element_clear(grb);element_clear(g3);element_clear(g3_inv);element_clear(mgr);
    mpz_clear(b_one); element_clear(calc_result); free(calc_result_str);
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

// 暗号化・復号に必要なデータを揃える関数
void AES_folda_inputkey(int mode, int crypt_mode, char *infolda, char *outfolda, unsigned char *iv){
    DIR *indir;
    struct dirent *dp;
    char original[100];
    char operated[100];
    unsigned char keyA[1024], keyB[1024], keyC[1024]; // A: mg^r, B: r(aQ), C: g^rb

    if((indir = opendir(infolda)) == NULL) error_notice(1003, infolda, __func__, __LINE__);
    else if((opendir(outfolda)) == NULL) error_notice(1003, outfolda, __func__, __LINE__);

    if(mode == 1 || mode == 2) {
        while(1){
            printf("暗号化を行います．\nAES鍵の入力(15-70文字): "); scanf("%s",keyA);
            if(15<=strlen(keyA) && strlen(keyA)<=70) break;
            else printf("15文字以上70文字以内で入力してください．\n");
        }
    } else if(mode == 3){
            printf("再暗号化中です．\n");
            load_key_txt("keyB", infolda, keyB);
            re_encipher_key(keyB, keyC);
        output_key_txt("keyC", outfolda, keyC);
        printf("再暗号化が完了しました．\n");
    } else {
        printf("データを復号します．\n");
        load_key_txt("keyA", infolda, keyA);
        if(mode == 4 ) {
            //TODO: 計算関数を作る
        } else if(mode == 5){
            load_key_txt("keyB", infolda, keyB);
            decode_key(keyA, keyB);
        } else if(mode == 6){
            load_key_txt("keyC", infolda, keyC);
            decode_re_key(keyA, keyC);
        }
    }
    
    if(mode != 3){
        for(dp=readdir(indir); dp!=NULL; dp=readdir(indir)){
            if(*dp->d_name != '.') {
                if(strcmp(dp->d_name, "keyA.txt") == 0){
                    if(mode == 1) printf("仕様上 \"keyA.txt\" は暗号化できません．暗号化をスキップします．\n");
                    continue;
                }
                if(strcmp(dp->d_name, "keyB.txt") == 0){
                    if(mode == 1) printf("仕様上 \"keyB.txt\" は暗号化できません．暗号化をスキップします．\n");
                    continue;
                }
                if(strcmp(dp->d_name, "keyC.txt") == 0){
                    if(mode == 1) printf("仕様上 \"keyC.txt\" は暗号化できません．暗号化をスキップします．\n");
                    continue;
                }
                sprintf(original,"%s/%s",infolda,dp->d_name);   // オリジナルのファイル名生成
                sprintf(operated,"%s/%s",outfolda,dp->d_name);  // 処理ファイル名生成
                
                double start, end;
                start = omp_get_wtime();
                AES(original, operated, keyA, iv, crypt_mode);         // ここでファイルの暗号化・復号処理
                end = omp_get_wtime();
                printf("[time = %.20lf] ", end-start);
                printf("%s -> %s\n", original, operated);
            }
        }
    }
    
    if(mode == 1 || mode == 2) {
        /* --- keyAを暗号化 --- */
        encipher_key(keyA);
        if(mode == 1) {
            // TODO: g^(ra)を計算
        } else if(mode == 2) {
            /* --- r(aQ) を計算 --- */
            EC_POINT raQ; point_init(raQ, p->g2);
            point_set_str(raQ, get_str_data("A", "aQ"));
            point_mul(raQ, r, raQ); point_get_str(keyB, raQ);
        }
        /* --- アウトプット --- */
        output_key_txt("keyA", outfolda, keyA);
        output_key_txt("keyB", outfolda, keyB);
    } else if(mode != 3){
        printf("データの復号が完了しました．\n");
    }

    closedir(indir);
}

int main(void){
    char infolda[6]  = "";
    char outfolda[6] = "";
    unsigned char iv[] ="0123456789abcdef";
    int input, mode;
    int crypt_mode;

    // モード決定
    while (1) {
    loopA:
        printf("暗号化するなら1, 復号するなら0を入力: "); scanf("%d", &input);
        if(input == 1) goto loopB;
        else if(input == 0) goto loopC;
        else { printf("0または1を入力してください。\n"); goto loopA; }
    loopB:
        crypt_mode = 1;
        printf("暗号化するなら1, 再暗号化するなら2を入力: "); scanf("%d", &input);
        if(input == 1) goto loopD;
        else if(input == 2) { mode = 3; break; }
        else { printf("1または2を入力してください。\n"); goto loopB; }
    loopC:
        crypt_mode = 0;
        printf("暗号化したものを復号するなら1, 再暗号化したものを復号するなら2を入力: "); scanf("%d", &input);
        if(input == 1) goto loopE;
        else if(input == 2) { mode = 6; break; }
        else { printf("1または2を入力してください。\n"); goto loopC; }
    loopD:
        printf("再暗号化できないようにするなら1, 再暗号化できるようにするなら2を入力: "); scanf("%d", &input);
        if(input == 1) { mode = 1; break; }
        else if(input == 2) { mode = 2; break; }
        else { printf("1または2を入力してください。\n"); goto loopD; }
    loopE:
        printf("再暗号化できないものなら1, 再暗号化していないものなら2を入力: "); scanf("%d", &input);
        if(input == 1) { mode = 4; break; }
        else if(input == 2) { mode = 5; break; }
        else { printf("1または2を入力してください。\n"); goto loopE; }
    }
    
    // フォルダ決定
    switch (mode) {
        case 1:
        case 2:
            strcpy(infolda,  "Plain");
            strcpy(outfolda, "Enc");
            break;
        case 3:
            strcpy(infolda,  "Enc");
            strcpy(outfolda, "Enc");
            break;
        case 4:
        case 5:
        case 6:
            strcpy(infolda,  "Enc");
            strcpy(outfolda, "Dec");
            break;
        default:
            error_notice(9999, "", __func__, __LINE__);
            return 1;
    }

    set_crypto_data();
    AES_folda_inputkey(mode, crypt_mode, infolda, outfolda, iv);
    return 0;
}

void set_crypto_data(){
    /* --- 初期化 --- */
    pairing_init(p, "ECBN254a");
    point_init(P, p->g1);
    point_init(Q, p->g2);
    mpz_init(a); mpz_init(b); mpz_init(r); mpz_init(limit);
    /* --- 上限値を設定 --- */
    char limit_char[78];
    get_str_std_data(limit_char, "limit"); mpz_set_str(limit, limit_char, 10);
    /* --- 乱数rを設定 --- */
    create_mpz_t_random(r, limit);
    /* --- 点P, Qを設定 --- */
    char P_char[132]; get_str_std_data(P_char, "P");
    point_init(P, p->g1); point_set_str(P, P_char);
    char Q_char[261]; get_str_std_data(Q_char, "Q");
    point_init(Q, p->g2); point_set_str(Q, Q_char);
}

char *get_str_data(char *user, char *data){
    /* --- 通知 --- */
    printf("\x1b[46m\x1b[30m");
    printf("User %s が知る %s を利用します．", user, data);
    printf("\x1b[49m\x1b[39m\n");
    
    /* --- 読み込み --- */
    FILE *loadfile;
    char loadfilename[1000];
    sprintf(loadfilename,"stakeholder/%s/%s.txt",user, data);
    loadfile = fopen(loadfilename, "r");
    if (loadfile == NULL) {
        printf("%s/%s.txtを開けませんでした．\n", user, data);
        exit(1);
    }
    fgets(str,1000,loadfile);
    fclose(loadfile);
    return str;
}
