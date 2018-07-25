#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdarg.h>

// 緑色の文字を出力する
void print_green_color(const char *text){printf("\x1b[32m%s\x1b[39m",text);}

// 指定されたmodeの固定値をdataにセットする
void get_str_data(char *data, char *mode) {
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
    if(strcmp(mode, "a") == 0){
        strcpy(data, "10266595110251627465233837651207859925915002503102420868484386842263941091801");
        return;
    }
    if(strcmp(mode, "b") == 0){
        strcpy(data, "15575247102814595268991362522128798238579927044546364420695723202568034604417");
        return;
    }
    if(strcmp(mode, "r") == 0){
        strcpy(data, "15833325551303335696826520837210818211886400884180425394003914246575514612145");
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
    va_list ap;
    va_start(ap, fps);
    for (FILE *fp = fps; fp != NULL; fp = va_arg(ap, FILE *)) {
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
    va_list ap;
    va_start(ap, ptrs);
    for (FILE *ptr = ptrs; ptr != NULL; ptr = va_arg(ap, void *)) free(ptr);
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

/*                                                            64|
 2147fdedc3256195664ed146bdb5ccd114ff8d9670f068e77e6fd3a2658af687
 1f32dbadc49af3d787c90b7817e20f6b0c29f6b638da827a1de8b07145409cd0
 1226c56cf43e1df35716f02bd97b3110fae42f775bfbbd4350d25015d7400763
 7305b48d42d1b2dab240d92c21d316b87b174fdde75355323a36fe682bf8d60
 22939394ee80742665648566994545320dd9d66cfd91c2f56079004847862cdc
 1203705e099ae8f0d2a44c486fae1d7ef95644472fa2da8f2b67292f117bd31d
 15b034210091c0456cc2d60fc66fceaf78b80e5148348c28e7c9f6b6cd06efb6
 a35bacd4b2575afbee8826f2ade018cd0b83b4d384dc7f3ae0ea18c8fdd787e
 20568ec161c61ffb829ea9cd43dd8f4740bc1fea71c08fbd5d4477f06ffb5704
 21c6d7c0c4e247e0daa942939e442aac95c9da52660a78733e68ddbe856eeea0
 11728796ef8637a2f355a324386302a536dd9328487f01f9a8f1574fdca64ac7
 140c1a6d689e77400ac0b1d970aac8dff77d8a4dfce6122de1b35d47d364c50f
 */
