/*
*   Jacob Urick
*   urick.9@osu.edu
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

char* charToHex(char* ciphertext, int len){
    char* retval = calloc(2*len + 1, sizeof(char));
    int i = 0;
    for(i = 0; i < len; i++){
        sprintf(retval + 2*i, "%02X", (int)ciphertext[i]);
    }
    return retval;
}

char* crypt(char* key, char* plaintext){
    char* ciphertext = calloc(strlen(plaintext), sizeof(char));
    char k_char = key[0];
    char pt_char = plaintext[0];
    int k_index = 0;
    int k_bit_index = 0;
    int t_index = 0;
    do{
        if(((1 << k_bit_index) & ((int)(k_char))) != 0){
            ciphertext[t_index] = (char) ((int)(plaintext[t_index]) ^ (int) (key[k_index]));
            printf("A: %d\n", (int)(k_char));
        }else{
            printf("B\n");
            ciphertext[t_index] = plaintext[t_index];
        }
        t_index = t_index + 1;
        k_bit_index = k_bit_index + 1;
        if(k_bit_index == 7){
            k_bit_index = 0;
            k_index = k_index + 1;
        }
        if(k_index == strlen(key)){
            k_index = 0;
        }
        k_char = key[k_index];
    }while(t_index < strlen(plaintext));
    ciphertext = charToHex(ciphertext, strlen(plaintext));
    return ciphertext;
}



int main()
{
    printf("%s", (crypt("Thisismysecretkey", "Hello! Here is a secret message :)")));

}
