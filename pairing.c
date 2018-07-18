// gcc -o pairing pairing.c -ltepla -lssl -lgmp -lcrypto -std=c99

#include <gmp.h>
#include <dirent.h>
#include <sys/time.h>
#include <tepla/ec.h>
#include "settings.h"

#define DEBUG 1 // 0: false 1: true

/* --- memo
    limit要る？
    file open各種はoperate_fileでできるのではないか
 */
EC_PAIRING p;
EC_POINT P, Q;
mpz_t limit, a, b, r;

void output_base_variable();

// ファイルを暗号化する関数
void encryption_file(char *in_file_name, char *out_file_name) {

    FILE *fin, *fout;
    fin  = fopen(in_file_name, "rb");
    fout = fopen(out_file_name, "wb");
    
    unsigned long in_size = get_file_size(in_file_name);
    printf("size = %lu\n", in_size);
    
    unsigned char *inbuf, *outbuf;
    if((inbuf = malloc(sizeof(char)*in_size)) == NULL){
        printf("inbufのメモリ確保に失敗しました。\n");
        exit(-1);
    }
    if((outbuf = malloc(sizeof(char)*(int)(in_size))) == NULL) {
        printf("outbufのメモリ確保に失敗しました。\n");
        exit(-1);
    }
    
    /* -- g = e(P, Q)^r を生成 --- */
    Element g; element_init(g, p->g3);
    pairing_map(g, P, Q, p);
    element_pow(g, g, r);
    print_green_color("g     : "); element_print(g);

    int inlen, outlen;

    //    for(;;){
    //        // ファイルポインタfinからバッファinbufにサイズ1のデータin_size個を読み込む
    //        // inlenには読み込んだ個数を返却
    //        inlen = fread(inbuf, 1, in_size, fin);
    //        if(inlen <= 0) break;
    //        fwrite(outbuf, 1, outlen, fout);
    //    }

    /* --- 後片付け --- */
    fcloses(fin, fout, NULL);
    frees(inbuf, outbuf, NULL);
    element_clear(g);
}

// ファイルを再暗号化する関数
void re_encryption_file(char *in_file_name, char *out_file_name) {
    
}

// ファイルを復号する
void decode_encryption_file(char *in_file_name, char *out_file_name) {
    
}

// 再暗号化されたファイルを復号する
void decode_re_encryption_file(char *in_file_name, char *out_file_name) {
    
}

// ファイル操作の指定をする関数
void operate_file(int mode, char *in_file_name, char *out_file_name) {
    switch (mode) {
        case 1:
            encryption_file(in_file_name, out_file_name);
            break;
        case 2:
            re_encryption_file(in_file_name, out_file_name);
            break;
        case 4:
            decode_encryption_file(in_file_name, out_file_name);
            break;
        case 5:
            decode_re_encryption_file(in_file_name, out_file_name);
            break;
    }
}

// フォルダの中のファイルパスを取り出す関数
void open_folder(int mode, char *in_folder, char *out_folder) {
    DIR *dir;
    struct dirent *dp;
    char original_file_path[100];
    char operated_file_path[100];

    if((dir = opendir(in_folder)) == NULL) {
        printf("フォルダ %s を開けませんでした。\n", in_folder);
        exit(-1);
    }
    if((opendir(out_folder)) == NULL) {
        printf("フォルダ %s を開けませんでした。\n", out_folder);
        exit(-1);
    }

    if(mode == 1) printf("暗号化を行います。\n");
    if(mode == 2) printf("再暗号化を行います。\n");
    if(mode == 4 || mode == 5) printf("復号を行います。\n");

    for(dp=readdir(dir); dp!=NULL; dp=readdir(dir)){
        if(*dp->d_name != '.') {
            sprintf(original_file_path,"%s/%s",in_folder,dp->d_name);   // オリジナルのファイル名生成
            sprintf(operated_file_path,"%s/%s",out_folder,dp->d_name);  // 処理ファイル名生成
            printf("%s -> %s\n", original_file_path, operated_file_path);
            operate_file(mode, original_file_path, operated_file_path);
        }
    }
    closedir(dir);
}

int main(void) {
/* --- Setting --- */
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
    if(DEBUG) output_base_variable();

/* --- メイン出力 --- */
    int mode;
    while (1) {
        printf("暗号化するなら1, 再暗号化するなら2, 復号するなら3を入力: ");
        scanf("%d", &mode);
        if(mode == 1 || mode == 2 || mode == 3) break;
        printf("1, 2, 3のいずれかを入力してください。\n");
    }

    char in_folder[6]  = "";
    char out_folder[6] = "";

    switch (mode) {
        case 1:
            strcpy(in_folder,  "Plain");
            strcpy(out_folder, "Enc");
            break;
        case 2:
            strcpy(in_folder,  "Enc");
            strcpy(out_folder, "ReEnc");
            break;
        case 3:
            while(1) {
                printf("再暗号化していないものを復号するなら1, 再暗号化したものを復号するなら2を入力: ");
                scanf("%d", &mode);
                if(mode == 1 || mode == 2) break;
                printf("1か2を入力してください。\n");
            }
            if(mode == 1){
                mode = 4;
                strcpy(in_folder,  "Enc");
                strcpy(out_folder, "Dec");
            } else {
                mode = 5;
                strcpy(in_folder,  "ReEnc");
                strcpy(out_folder, "Dec");
            }
            break;
    }
    open_folder(mode, in_folder, out_folder);

/* --- 後片付け --- */
    mpz_clears(limit, a, b, r, NULL);
    point_clear(P);
    point_clear(Q);
    pairing_clear(p);
    print_green_color("--- 正常終了 ---\n");
    return 0;
}

void output_base_variable() {
    print_green_color("limit : "); gmp_printf ("%Zd\n", limit);
    print_green_color("P     : "); point_print(P);
    print_green_color("Q     : "); point_print(Q);
    print_green_color("a     : "); gmp_printf ("%Zd\n", a);
    print_green_color("b     : "); gmp_printf ("%Zd\n", b);
    print_green_color("r     : "); gmp_printf ("%Zd\n", r);
}


