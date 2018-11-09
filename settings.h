#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>
#include <dirent.h>

// 緑色の文字を出力する
void print_green_color(const char *text){printf("\x1b[32m%s\x1b[39m",text);}

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

// ファイルの存在を確認する関数(0: false, 1: true)
int file_existence(char *dir_path, char *filename){
    DIR *dir;
    struct dirent *dp;
    int ret = 0;
    
    dir=opendir(dir_path);
    for(dp=readdir(dir); dp!=NULL; dp=readdir(dir))
        if(strcmp(dp->d_name, filename)==0) ret = 1;
    closedir(dir);
    
    return ret;
}

// エラー内容を出力する関数
//format: error_notice(code, memo, __func__, __LINE__);
void error_notice(int error_code, char *memo, const char *func_name, int line) {
    printf("\x1b[31m");
    printf("ERROR CODE(%d): ", error_code);
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
            printf("鍵を読み込む時に %s を開けませんでした．\n", memo);
            if(strcmp(memo, "keyC")==0) printf("再暗号化の処理を行なっていない可能性があります．\n");
            break;
        case 1003:
            printf("FOLDER OPEN ERROR\n");
            printf("フォルダ %s が開けませんでした．\n", memo);
            break;
        case 2000:
            printf("DATA FORMAT ERROR\n");
            printf("再暗号化できないデータフォーマットです．\n");
            break;
        case 2001:
            printf("DATA FORMAT ERROR\n");
            printf("再暗号化が可能なデータフォーマットです．\n");
            break;
        case 2002:
            printf("DATA FORMAT ERROR\n");
            printf("一度しか暗号化ができないデータフォーマットです．\n");
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
