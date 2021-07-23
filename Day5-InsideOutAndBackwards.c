/*
*   Jacob Urick
*   urick.9@osu.edu
*   This will flip bits in key[i mod |key|] bytes before skipping n bytes, where i ranges from 0 to |key| - 1.
*   The bytes order is flipped before returning.
*/
#include <stdio.h>
#include <string.h>
#include <stdlib.h>


char* rev(char* input, int len){
    char* retval = calloc(len, sizeof(char));
    int i = 0;
    for(i = 0; i < len - 1; i++){
        retval[i] = input[len - 2 - i ];
    }
    return retval;
}

char* charToHex(char* ciphertext, int len){
    char* retval = calloc(2*len + 1, sizeof(char));
    int i = 0;
    for(i = 0; i < len; i++){
        sprintf(retval + 2*i, "%02X", (int)ciphertext[i]) ;
    }
    return rev(retval, 2*len + 1);
}


char* crypt(char* key, int n, char* plaintext){
    char* ciphertext = calloc(strlen(plaintext), sizeof(char));
    int char_index = 0;
    int repeat_index = 0;
    int skip_index = 0;
    int key_index = 0;
    int skip = 0; 
    int* keys = calloc(strlen(key), sizeof(char));
    do{
        if(skip){
            skip_index = skip_index + 1;
            skip = skip_index < n;
            if(!skip){
                skip_index = 0;
            }
            ciphertext[char_index] = plaintext[char_index];
        }else{
            ciphertext[char_index] = (unsigned char)((((unsigned int)plaintext[char_index]) ^127 ));
            repeat_index = repeat_index + 1;
            skip = repeat_index < ((int)key[key_index] - 48);
            if(skip){
                repeat_index = 0;
                key_index = key_index + 1;
                if(key_index > strlen(key)){
                    key_index = 0;
                }
            }
        }
        char_index = char_index + 1;
    }while(char_index < strlen(plaintext));
    ciphertext = charToHex(ciphertext, strlen(plaintext));
    return ciphertext;
}



int main()
{
    printf("%s", (crypt("8675309", 1, "Hello, this a secret message :)")));

}
