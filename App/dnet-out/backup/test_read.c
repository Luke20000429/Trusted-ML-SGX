#include <stdio.h>
#include <string.h>
#include <stdlib.h>

int main () {
    FILE *fp;
    float *buffer;
    buffer = (float *)malloc(sizeof(float) * 2360000);
    printf("alloc succ ~\n");
    /* Open file for both reading and writing */
    fp = fopen("resnet18.weights", "r+");
    if( fp == NULL ) {
        perror("Error opening file");
        return(-1);
    }
    fread(buffer, sizeof(float), 2359296, fp);
    printf("read succ ~\n");
    printf("%f\n", buffer[2359290]);
    fclose(fp);
    
    return(0);
}