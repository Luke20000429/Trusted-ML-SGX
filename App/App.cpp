
#include <stdio.h>
#include <string.h>
#include <pwd.h>
#include <thread>

#include <sgx_urts.h>
#include "App.h"
#include "ErrorSupport.h"
#include <time.h>
#include "sgx_tseal.h"
#include "Persistence.h"
/* For romulus */
#define MAX_PATH FILENAME_MAX
// #define MAX_IMAGE 10
/* Global EID shared by multiple threads */
sgx_enclave_id_t global_eid = 0;
static int stack_val = 10;

/* Darknet variables */
data training_data, test_data;

//---------------------------------------------------------------------------------
/**
 * Config files
 */
#define CIFAR_CFG_FILE "./App/dnet-out/cfg/cifar.cfg"
#define CIFAR_TEST_DATA "./App/dnet-out/data/cifar/cifar-10-batches-bin/test_batch.bin"
#define TINY_IMAGE "./App/dnet-out/data/dog.jpg"
// #define TINY_CFG "./App/dnet-out/cfg/tiny.cfg"
#define TINY_CFG "./App/dnet-out/cfg/resnet152.cfg"
// #define DATA_CFG "./App/dnet-out/data/tiny.data"
#define DATA_CFG "./App/dnet-out/data/tiny.data"
#define MNIST_TRAIN_IMAGES "./App/dnet-out/data/mnist/train-images-idx3-ubyte"
#define MNIST_TRAIN_LABELS "./App/dnet-out/data/mnist/train-labels-idx1-ubyte"
#define MNIST_TEST_IMAGES "./App/dnet-out/data/mnist/t10k-images-idx3-ubyte"
#define MNIST_TEST_LABELS "./App/dnet-out/data/mnist/t10k-labels-idx1-ubyte"
#define MNIST_CFG "./App/dnet-out/cfg/mnist.cfg"

char* IMAGENET_CFG_FILE = "";
char* IMAGENET_TEST_DATA = "";
char* IMAGENET_IMAGE = "";
char* IMAGENET_WEIGHTS = "";
int NUM_IMAGES = 0;

//---------------------------------------------------------------------------------------------------------------------------------------
/**
 * Classify an image with a trained Tiny Darknet model
 * Define path to weightfile in trainer.c
 */
void test_imagenet(char *cfgfile)
{
    printf("Classification starts..\n");
    //read network config file
    list *sections = read_cfg(cfgfile);
    //read labels
    list *options = read_data_cfg(IMAGENET_TEST_DATA);
    char *name_list = option_find_str(options, "names", 0);
    list *plist = get_paths(name_list);

    //read image file
    image *im = (image *)calloc(NUM_IMAGES, sizeof(image));


    FILE * image_fp;
    char * line = NULL;
    size_t len = 256;

    image_fp = fopen(IMAGENET_IMAGE, "r");
    if (image_fp == NULL)
        exit(EXIT_FAILURE);

    for (int i = 0; i < NUM_IMAGES; i++) {
        if (getline(&line, &len, image_fp) == -1) {
            exit(1);
        }
        size_t last_idx = strlen(line) - 1;
        if( line[last_idx] == '\n' ) {
            line[last_idx] = '\0';
        }
        // printf("Image from %s\n", line);
        char buff[256];
        char *input = buff;
        strncpy(input, line, 256);
        im[i] = load_image_color(input, 0, 0);
    }
    printf("Enclave starts..\n");
    timespec start_tp;
    timespec end_tp;
    int timestamp = clock_gettime(1, &start_tp);
    // strcpy(weights, IMAGENET_WEIGHTS);
    // printf("%s\n", weights);
    Persistence sealed_file(IMAGENET_WEIGHTS);
    if (!sealed_file.exists()) {
        printf("Sealed file does not exist\n");
        exit(1);
    }
    unsigned int sealed_size = sealed_file.size();
    char *sealed_weights = (char*) malloc(sealed_size);
    sealed_file.load((uint8_t *) sealed_weights, sealed_size);
    sgx_status_t ecall_status;
    sgx_status_t status = unseal(global_eid, &ecall_status,
                               (sgx_sealed_data_t*) sealed_weights, sealed_size);
    if (status != SGX_SUCCESS || ecall_status != SGX_SUCCESS) {
        printf("Unseal failed %d %d\n", status, ecall_status);
        exit(1);
    }
    printf("Unseal Success\n");
    ecall_classify(global_eid, sections, plist, im, sealed_weights, NUM_IMAGES);
    printf("Enclave ends..\n");
    timestamp = clock_gettime(1, &end_tp);
    fprintf(stderr, "Run Time: %ld ms\n", ((end_tp.tv_sec-start_tp.tv_sec)  * (long)1e9 + (end_tp.tv_nsec-start_tp.tv_nsec)) / 1000000);
    //free data
    for (int i = 0; i < NUM_IMAGES; i++) {
        free_image(im[i]);
    }
    free(sealed_weights);
    fclose(image_fp);
    printf("Classification complete..\n");
}

//--------------------------------------------------------------------------------------------------------------

/* Initialize the enclave:
 * Call sgx_create_enclave to initialize an enclave instance
 */
int initialize_enclave(void)
{
    sgx_status_t ret = SGX_ERROR_UNEXPECTED;

    /* Call sgx_create_enclave to initialize an enclave instance */
    /* Debug Support: set 2nd parameter to 1 */
    ret = sgx_create_enclave(ENCLAVE_FILENAME, SGX_DEBUG_FLAG, NULL, NULL, &global_eid, NULL);
    if (ret != SGX_SUCCESS)
    {
        print_error_message(ret);
        return -1;
    }

    return 0;
}

/* Application entry */
int SGX_CDECL main(int argc, char *argv[])
{
    // (void)argc;
    // (void)argv;

    sgx_status_t ret;

    IMAGENET_CFG_FILE = argv[1];
    IMAGENET_TEST_DATA = argv[2];
    IMAGENET_IMAGE = argv[3];
    IMAGENET_WEIGHTS = argv[4];
    NUM_IMAGES = atoi(argv[5]);
    /* Initialize the enclave */
    timespec start_tp;
    timespec end_tp;
    int timestamp = clock_gettime(0, &start_tp);
    if (initialize_enclave() < 0)
    {
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }
    timestamp = clock_gettime(0, &end_tp);
    fprintf(stderr, "Init Time: %ld ms\n", ((end_tp.tv_sec-start_tp.tv_sec)  * (long)1e9 + (end_tp.tv_nsec-start_tp.tv_nsec)) / 1000000);
    
    test_imagenet(IMAGENET_CFG_FILE);
    
    //Destroy enclave
    sgx_destroy_enclave(global_eid);
    return 0;
}
