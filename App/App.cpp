
#include <stdio.h>
#include <string.h>
#include <pwd.h>
#include <thread>

#include <sgx_urts.h>
#include "App.h"
#include "ErrorSupport.h"

/* For romulus */
#define MAX_PATH FILENAME_MAX
#define MAX_IMAGE 30
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

#define IMAGENET_CFG_FILE "./App/dnet-out/cfg/resnet18.cfg"
#define IMAGENET_TEST_DATA "./App/dnet-out/data/imagenet.data"
#define IMAGENET_IMAGES "./App/dnet-out/data/imagenet/imagenet.image.list"
#define IMAGENET_IMAGE "./App/dnet-out/data/person.jpg"
/* Thread function --> only for testing purposes */
void thread_func()
{
    size_t tid = std::hash<std::thread::id>()(std::this_thread::get_id());
    printf("Thread ID: %d\n", tid);
    stack_val++; // implement mutex/atomic..just for testing anyway
    //ecall_nvram_worker(global_eid, stack_val, tid);
    //ecall_tester(global_eid,NULL,NULL,0);
}

//------------------------------------------------------------------------------------------------------------------------
/**
 * Train cifar network in the enclave:
 * We first parse the model config file in untrusted memory; we can read it in the enclave via ocalls but it's expensive
 * so we prefer to do it here as it has no obvious issues in terms of security
 * The parsed values are then passed to the enclave runtime and use to create the secure network in enclave memory
 */
void train_cifar(char *cfgfile)
{

    list *sections = read_cfg(cfgfile);

    //Load training data
    training_data = load_all_cifar10();
    /**
     * The enclave will create a secure network struct in enclave memory
     * using the parameters in the sections variable
     */
    ecall_trainer(global_eid, sections, &training_data, 0);
    printf("Training complete..\n");
    free_data(training_data);
}

/**
 * Test a trained cifar model
 * Define path to weighfile in trainer.c
 */
void test_cifar(char *cfgfile)
{

    list *sections = read_cfg(cfgfile);

    //Load test data
    test_data = load_cifar10_data(CIFAR_TEST_DATA);
    /**
     * The enclave will create a secure network struct in enclave memory
     * using the parameters in the sections variable
     */
    ecall_tester(global_eid, sections, &test_data, 0);
    printf("Testing complete..\n");
    free_data(test_data);
}
//---------------------------------------------------------------------------------------------------------------------------------------
/**
 * Classify an image with a trained Tiny Darknet model
 * Define path to weightfile in trainer.c
 */
void test_tiny(char *cfgfile)
{
    printf("Classification starts..\n");
    //read network config file
    list *sections = read_cfg(cfgfile);
    //read labels
    list *options = read_data_cfg(DATA_CFG);
    char *name_list = option_find_str(options, "names", 0);
    list *plist = get_paths(name_list);

    //read image file
    char *file = TINY_IMAGE;
    char buff[256];
    char *input = buff;
    strncpy(input, file, 256);
    image im = load_image_color(input, 0, 0);
    printf("Enclave starts..\n");
    //classify image in enclave
    // ecall_classify(global_eid, sections, plist, &im);
    printf("Enclave ends..\n");
    //free data
    free_image(im);
    printf("Classification complete..\n");
}
//--------------------------------------------------------------------------------------------------------------
/**
 * Train mnist classifier inside the enclave
 * mnist: digit classification
 */

void train_mnist(char *cfgfile)
{

    std::string img_path = MNIST_TRAIN_IMAGES;
    std::string label_path = MNIST_TRAIN_LABELS;
    data train = load_mnist_images(img_path);
    train.y = load_mnist_labels(label_path);
    list *sections = read_cfg(cfgfile);
    ecall_trainer(global_eid, sections, &train, 0);
    printf("Mnist training complete..\n");
    free_data(train);
}

/**
 * Test a trained mnist model
 * Define path to weighfile in trainer.c
 */
void test_mnist(char *cfgfile)
{
    printf("Mnist testing starts.\n");
    std::string img_path = MNIST_TEST_IMAGES;
    std::string label_path = MNIST_TEST_LABELS;
    data test = load_mnist_images(img_path);
    test.y = load_mnist_labels(label_path);
    list *sections = read_cfg(cfgfile);

    ecall_tester(global_eid, sections, &test, 0);
    printf("Mnist testing complete..\n");
    free_data(test);
}

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

    image *im = (image *)calloc(MAX_IMAGE, sizeof(image));


    FILE * image_fp;
    char * line = NULL;
    size_t len = 256;

    image_fp = fopen(IMAGENET_IMAGES, "r");
    if (image_fp == NULL)
        exit(EXIT_FAILURE);

    int i = 0;
    for (i = 0; i < MAX_IMAGE; i++) {
        if (getline(&line, &len, image_fp) == -1) {
            break;
        }
        size_t last_idx = strlen(line) - 1;
        if( line[last_idx] == '\n' ) {
            line[last_idx] = '\0';
        }
        printf("Image from %s\n", line);
        char buff[256];
        char *input = buff;
        strncpy(input, line, 256);
        im[i] = load_image_color(input, 0, 0);
        // printf("Addr: %p", (void*)im[i].data);
    }
    
    //free data
    for (int ii = 0; ii < i; ii++) {
        printf("Enclave starts %d / %d ..\n", ii+1, i);
        ecall_classify(global_eid, sections, plist, im+ii);
        printf("Enclave ends..\n");
        free_image(im[ii]);
    }
    free(im);
    fclose(image_fp);
    printf("Classification complete..\n");
}

/**
 * Classify an image with a trained Tiny Darknet model
 * Define path to weightfile in trainer.c
 */
void test_batch_imagenet(char *cfgfile)
{
    printf("Batch Classification starts..\n");
    //read network config file
    list *sections = read_cfg(cfgfile);
    //read labels
    list *options = read_data_cfg(IMAGENET_TEST_DATA);
    char *name_list = option_find_str(options, "names", 0);
    list *plist = get_paths(name_list);

    // read image file
    // NOTE: TEST ON BATCH
    char *file = IMAGENET_IMAGE;
    char buff[256];
    char *input = buff;
    strncpy(input, file, 256);
    image imgs[3];
    for (int i = 0; i < 3; i++)
    {
        imgs[i] = load_image_color(input, 0, 0);;
    }
    printf("Enclave starts..\n");
    ecall_batch_classify(global_eid, sections, plist, imgs, 3);
    printf("Enclave ends..\n");
    //free data
    for (int i = 0; i < 3; i++)
    {
        free_image(imgs[i]);
    }
    
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
    (void)argc;
    (void)argv;

    sgx_status_t ret;

    /* Initialize the enclave */
    if (initialize_enclave() < 0)
    {
        printf("Enter a character before exit ...\n");
        getchar();
        return -1;
    }

    //Create NUM_THRREADS threads
    //std::thread trd[NUM_THREADS];

    //train_cifar(CIFAR_CFG_FILE);
    //test_cifar(CIFAR_CFG_FILE);
    // test_tiny(TINY_CFG);
    test_batch_imagenet(IMAGENET_CFG_FILE);
    test_imagenet(IMAGENET_CFG_FILE);
    //train_mnist(MNIST_CFG);
    // test_mnist(MNIST_CFG);

    /*  
    for (int i = 0; i < NUM_THREADS; i++)
    {
        trd[i] = std::thread(thread_func);
    }
    for (int i = 0; i < NUM_THREADS; i++)
    {
        trd[i].join();
    } */

    //Destroy enclave
    sgx_destroy_enclave(global_eid);
    return 0;
}
