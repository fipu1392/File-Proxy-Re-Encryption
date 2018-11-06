#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

// 緑色の文字を出力する
void print_green_color(const char *text){printf("\x1b[32m%s\x1b[39m",text);}

// 指定されたmodeの固定値をdataにセットする
void get_str_std_data(char *data, char *mode) {
    /* --- 通知 --- */
    printf("\x1b[46m\x1b[30m");
    printf("データ %s を取得しました．", mode);
    printf("\x1b[49m\x1b[39m\n");
    
    if(strcmp(mode, "limit") == 0){
        strcpy(data, "16030569034403128277756688287498649515510226217719936227669524443298095169537");
        return;
    }
    if(strcmp(mode, "P") == 0){
        strcpy(data, "[166a82a8bdcf172d07489bb331884cb84219c8c78abea91882d1a90d91ea3392,20122d20a8de010910499cca045fb32ae34a4f39bdf57c64c94520b77f9b36de]");
        return;
    }
    if(strcmp(mode, "Q") == 0){
        strcpy(data, "[130cf6ed98a2f60ace65816b3c4551e8054d5e0a5f30d61328ca4ddbb9f1a25d 1530df173e2999c6413fc6470fdcfb96e9ecdf7fe0f84cecaf53f0f018a99506,13c2d21337f30594c9a1970cc711693570d6ffa529d88edfc88fddf225b89d51 445217dc156274c6666196d89479069e89dda42451ff8b41cd2e634ad0d1502]");
        return;
    }
}

// ファイルのサイズを計測する関数
unsigned long get_file_size(char *fname){
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

// fcloseの複数ファイル指定対応版
// 引数の最後は必ずNULLにすること
int fcloses(FILE *fps, ...) {
    FILE *fp;
    va_list ap;
    va_start(ap, fps);
    for (fp = fps; fp != NULL; fp = va_arg(ap, FILE *)) {
        if (fclose(fp) != 0) {
            printf("fclose時にエラーが発生しました。");
            va_end(ap);
            return -1;
        }
    }
    va_end(ap);
    return 0;
}

// freeの複数ポインタ指定対応版
// 引数の最後は必ずNULLにすること
int frees(void *ptrs, ...) {
    FILE *ptr;
    va_list ap;
    va_start(ap, ptrs);
    for (ptr = ptrs; ptr != NULL; ptr = va_arg(ap, void *)) free(ptr);
    va_end(ap);
    return 0;
}

/* -----------------------------------------------
 * 符号なしlong型整数を16進数表記のchar型文字列に変換する関数
 * $0 変換結果を入れるchar型配列のアドレス
 * $1 変換したい符号なしlong型整数
 -----------------------------------------------*/
void convert_long_type_into_hex_string(char *result, const unsigned long x){
    unsigned long original = x;
    *result = '\0';
    do{
        char tmp;
        sprintf(&tmp, "%X", original%16);
        strcat(result, &tmp);
    }while((original /= 16) != 0);
    char t, *p, *q;
    for (p = result, q = &(result[strlen(result)-1]); p < q; p++, q--) t = *p, *p = *q, *q = t;
}

/* -----------------------------------------------
 * 16進数表記のchar型文字列を符号なしlong型整数に変換する関数
 * $0 変換したいchar型配列のアドレス
 * @return 変換結果の符号なしlong型整数
 -----------------------------------------------*/
unsigned long convert_hex_string_into_long_type(const char *x){
    unsigned long result=0, exp=1;
    int length = strlen(x)-1, i;
    for(i=length; i>=0; i--){
        char tmp_char = *(x+i);
        unsigned long tmp_long;
        sscanf(&tmp_char, "%X", &tmp_long);
        result += tmp_long*exp;
        exp *= 16;
    }
    return result;
}

/* -----------------------------------------------
 * mpz_tでランダムな値を生成する関数
 * $0 生成した値を入れる変数
 * $1 上限値
 * 参考サイト: https://sehermitage.web.fc2.com/etc/gmp_src.html
 -----------------------------------------------*/
void create_mpz_t_random(mpz_t op, const mpz_t n) {
    gmp_randstate_t state;
    gmp_randinit_default(state);
    
    struct timeval tv, tv2;
    gettimeofday(&tv2, NULL);
    
    do {
        gettimeofday(&tv, NULL);
    } while (tv.tv_usec == tv2.tv_usec);
    
    gmp_randseed_ui(state, tv.tv_usec);
    mpz_urandomm(op, state, n);
    
    gmp_randclear(state);
}

// mpz_t型の数値の桁数を取得する(小数点以下は未対応)
unsigned long get_length_type_mpz_t(mpz_t num){
    unsigned long length = 0;
    mpz_t q, ori, ten;
    mpz_init(q);
    mpz_init_set(ori, num);
    mpz_init_set_ui (ten, 10);

    while (1) {
        mpz_tdiv_q(q, ori, ten);
        mpz_set(ori, q);
        length++;
        if(mpz_cmp_ui(ori, 0) == 0) break;
    }
    return length;
}

// エラー内容を出力する関数
//format: error_notice(code, memo, __func__, __LINE__);
void error_notice(int error_code, char *memo, const char *func_name, int line) {
    printf("\x1b[31m");
    printf("ERROR CODE(%d) :", error_code);
    switch (error_code) {
        case 1000:
            printf("MEMORY ALLOCATION ERROR\n");
            printf("%sのメモリが確保できませんでした。\n", memo);
            break;
        case 1001:
            printf("FILE OPEN ERROR\n");
            printf("鍵を書き出す時に %s.txt を開けませんでした．\n", memo);
            break;
        case 1002:
            printf("FILE OPEN ERROR\n");
            printf("鍵を読み込む時に %s.txt を開けませんでした．\n", memo);
            break;
        case 1003:
            printf("FOLDER OPEN ERROR\n");
            printf("フォルダ %s が開けませんでした。\n", memo);
            break;
        case 9999:
            printf("UNKNOWN ERROR\n");
            printf("予期していないエラーが発生しました．");
            break;
        default:
            printf("UNKNOWN ERROR\n");
            break;
    }
    printf("[debug info] %d: %s\n", line, func_name);
    printf("\x1b[39m");
    exit(1);
}
