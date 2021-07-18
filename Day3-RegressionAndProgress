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

char* crypt(int p, int q, char* plaintext){
    char* ciphertext = calloc(strlen(plaintext), sizeof(char));
    int index = 0;
    do{
        char plaintext_char = plaintext[index];
        if((index % (p+q)) > p - 1){
            ciphertext[index] = (int)plaintext_char - 1;
        }else{
            ciphertext[index] = (int)plaintext_char + 1;
        }
        index = index + 1;
    }while(index < strlen(plaintext));
    ciphertext = charToHex(ciphertext, strlen(plaintext));
    return ciphertext;
}



int main()
{
    printf("%s", (crypt(2, 1, "Hello, this a secret message :)")));

}
