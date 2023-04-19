
#include "dnet_sgx_utils.h"
#include "darknet.h"
#include "trainer.h"
#include "checks.h"

#define CIFAR_WEIGHTS "./App/dnet-out/backup/cifar.weights"
// #define TINY_WEIGHTS "/home/liuxs/workarea/sgx-dnet/App/dnet-out/backup/tiny.weights"
#define TINY_WEIGHTS "./App/dnet-out/backup/resnet152.weights"
#define MNIST_WEIGHTS "./App/dnet-out/backup/mnist.weights"

//global network model
network *net = NULL;

/**
 * Pxxx
 * The network training avg accuracy should decrease
 * as the network learns
 * Batch size: the number of data samples read for one training epoch/iteration
 * If accuracy not high enough increase max batch
 */

void ecall_trainer(list *sections, data *training_data, int pmem)
{

    CHECK_REF_POINTER(sections, sizeof(list));
    CHECK_REF_POINTER(training_data, sizeof(data));
    /**
     * load fence after pointer checks ensures the checks are done 
     * before any assignment 
     */
    sgx_lfence();
    train_mnist(sections, training_data, pmem);
    //train_cifar(sections, training_data, pmem);
}

/**
 * Training algorithms for different models
 */

void train_mnist(list *sections, data *training_data, int pmem)
{
    //TODO: pointer checks
    printf("Training mnist in enclave..\n");
    network *net = create_net_in(sections);
    printf("Done creating network in enclave...\n");

    srand(12345);
    float avg_loss = -1;
    printf("Learning Rate: %g, Momentum: %g, Decay: %g\n", net->learning_rate, net->momentum, net->decay);
    int classes = 10;
    int N = 60000; //number of training images
    int epoch = (*net->seen) / N;
    int cur_batch = 0;
    float progress = 0;
    data train = *training_data;
    printf("Max batches: %d\n", net->max_batches);
    char *path = MNIST_WEIGHTS;

    while (cur_batch < net->max_batches || net->max_batches == 0)
    {
        cur_batch = get_current_batch(net);
        float loss = train_network_sgd(net, train, 1);
        if (avg_loss == -1)
            avg_loss = loss;
        avg_loss = avg_loss * .95 + loss * .05;

        progress = ((double)cur_batch / net->max_batches) * 100;
        printf("Batch num: %ld, Seen: %.3f: Loss: %f, Avg loss: %f avg, L. rate: %f, Progress: %.2f%% \n",
               cur_batch, (float)(*net->seen) / N, loss, avg_loss, get_current_rate(net), progress);

        if (cur_batch % 5 == 0)
        {
            printf("Saving weights to weight file..\n");
            save_weights(net, path);
        }
    }

    printf("Done training mnist network..\n");
    free_network(net);
}

void train_cifar(list *sections, data *training_data, int pmem)
{
    //TODO: pointer checks

    network *net = create_net_in(sections);
    printf("Done creating network in enclave...\n");

    srand(12345);
    float avg_loss = -1;
    printf("Learning Rate: %g, Momentum: %g, Decay: %g\n", net->learning_rate, net->momentum, net->decay);
    char **labels = {"airplane", "automobile", "bird", "cat", "deer", "dog", "frog", "horse", "ship", "truck"};
    int classes = 10;
    int N = 50000;
    int epoch = (*net->seen) / N;
    data train = *training_data;
    float progress = 0;
    int cur_batch = 0;
    char *path = CIFAR_WEIGHTS;
    printf("Max batches: %d\n", net->max_batches);

    while (cur_batch < net->max_batches || net->max_batches == 0)
    {
        cur_batch = get_current_batch(net);
        float loss = train_network_sgd(net, train, 1);
        if (avg_loss == -1)
            avg_loss = loss;
        avg_loss = avg_loss * .95 + loss * .05;

        progress = ((double)cur_batch / net->max_batches) * 100;
        printf("Batch num: %ld, Seen: %.3f: Loss: %f, Avg loss: %f avg, L. rate: %f, Progress: %.2f%% \n",
               cur_batch, (float)(*net->seen) / N, loss, avg_loss, get_current_rate(net), progress);

        if (cur_batch % 5 == 0)
        {
            printf("Saving weights to weight file..\n");
            save_weights(net, path);
        }
    }

    printf("Done training cifar model..\n");
    free_network(net);
}

void ecall_tester(list *sections, data *test_data, int pmem)
{
    CHECK_REF_POINTER(sections, sizeof(list));
    CHECK_REF_POINTER(test_data, sizeof(data));   
    /**
     * load fence after pointer checks ensures the checks are done 
     * before any assignment 
     */
    sgx_lfence();
    test_mnist(sections, test_data, pmem);
}

void ecall_classify(list *sections, list *labels, image *im, char *weights, int image_num)
{
    CHECK_REF_POINTER(sections, sizeof(list));
    CHECK_REF_POINTER(labels, sizeof(list));
    CHECK_REF_POINTER(im, sizeof(image));
    /**
     * load fence after pointer checks ensures the checks are done 
     * before any assignment 
     */
    sgx_lfence();
    predict_classifier(sections, labels, im, 5, weights, image_num);
    // predict_classifier_batch(sections, labels, im, 5, weights, image_num);
    printf("Classify finished!\n");
}

/**
 * Test trained mnist model
 */
void test_mnist(list *sections, data *test_data, int pmem)
{
    if (pmem)
    {
        //test on pmem model
        return;
    }
    printf("Testing mnist model..\n");

    char *weightfile = MNIST_WEIGHTS;
    network *net = load_network(sections, MNIST_WEIGHTS, 0);
    if (net == NULL)
    {
        printf("No neural network in enclave..\n");
        return;
    }
    srand(12345);
    float avg_acc = 0;
    data test = *test_data;
    float *acc = network_accuracies(net, test, 2);
    avg_acc += acc[0];

    printf("Avg. accuracy: %f%%, %d images\n", avg_acc * 100, test.X.rows);
    free_network(net);

    /**
     * Test multi mnist
     *
    float avg_acc = 0;
    data test = *test_data;
    image im;

    for (int i = 0; i < test.X.rows; ++i)
    {
        im = float_to_image(28, 28, 1, test.X.vals[i]);

        float pred[10] = {0};

        float *p = network_predict(net, im.data);
        axpy_cpu(10, 1, p, 1, pred, 1);
        flip_image(im);
        p = network_predict(net, im.data);
        axpy_cpu(10, 1, p, 1, pred, 1);

        int index = max_index(pred, 10);
        int class = max_index(test.y.vals[i], 10);
        if (index == class)
            avg_acc += 1;

        printf("%4d: %.2f%%\n", i, 100. * avg_acc / (i + 1)); //un/comment to see/hide accuracy progress
    }
    printf("Overall prediction accuracy: %2f%%\n", 100. * avg_acc / test.X.rows);
    free_network(net);
    */
}

void test_cifar(list *sections, data *test_data, int pmem)
{

    if (pmem)
    {
        //test on pmem model
        return;
    }

    char *weightfile = CIFAR_WEIGHTS;
    network *net = load_network(sections, CIFAR_WEIGHTS, 0);
    srand(12345);

    float avg_acc = 0;
    float avg_top5 = 0;
    data test = *test_data;

    float *acc = network_accuracies(net, test, 2);
    avg_acc += acc[0];
    avg_top5 += acc[1];
    printf("top1: %f, xx seconds, %d images\n", avg_acc, test.X.rows);
    free_network(net);
}
/**
 * Classify an image with Tiny Darknet 
 * Num of classes in model: 1000
 */
void classify_tiny(list *sections, list *labels, image *img, int top)
{

    network *net = load_network(sections, TINY_WEIGHTS, 0);
    printf("Done loading trained network model in enclave..\n");
    set_batch_network(net, 1);
    srand(54321);

    //get label names; e.g dog, person, giraffe etc
    char **names = (char **)list_to_array(labels);

    int *indexes = calloc(top, sizeof(int));
    image im = *img;
    image r = letterbox_image(im, net->w, net->h);

    float *X = r.data;

    float *predictions = network_predict(net, X);

    if (net->hierarchy)
        hierarchy_predictions(predictions, net->outputs, net->hierarchy, 1, 1);
    top_k(predictions, net->outputs, top, indexes);

    printf("Predictions: \n");
    for (int i = 0; i < top; ++i)
    {
        int index = indexes[i];
        printf("%5.2f%%: %s \n", predictions[index] * 100, names[index]);
    }

    if (r.data != im.data)
        free_image(r);
}
//For testing my enclave file I/O ocall wrapper fxns..
void test_fio()
{
    ocall_open_file("file.txt", O_WRONLY);
    char c[] = "enclave file i/o test";
    fwrite(c, strlen(c) + 1, 1, 0);
    ocall_close_file();
    //dont have fseek ocall so I close and reopen for now :-)
    char buffer[100];

    ocall_open_file("file.txt", O_RDONLY);

    fread(buffer, strlen(c) + 1, 1, 0);
    printf("String: %s\n", buffer);
    ocall_close_file();
}


void predict_classifier(list *sections, list *labels, image *img, int top, char *weights, int image_num)
{
    if (net == NULL) {
        printf("No neural network in enclave..\n");
        printf("%s %d\n", weights, image_num);
        char *local_weights = (char *) calloc(256, sizeof(char));
        for (int i = 0; weights[i] != '\0'; ++i) {
            local_weights[i] = weights[i];
        }
        net = load_network(sections, local_weights, 0);
        set_batch_network(net, 1);
        srand(2222222);
        free(local_weights);
        printf("Done loading trained network model in enclave..\n");
    }
    // list *options = read_data_cfg(datacfg);

    // char *name_list = option_find_str(options, "names", 0);
    // if(!name_list) name_list = option_find_str(options, "labels", "data/labels.list");
    // if(top == 0) top = option_find_int(options, "top", 1);
    // char **names = get_labels(name_list);
    char **names = (char **)list_to_array(labels);
    int *indexes = calloc(top, sizeof(int));
    int i = 0;
    for (int image_idx = 0; image_idx < image_num; image_idx++) {
        printf("Infer image %d of total %d\n", image_idx, image_num);
        image im = img[image_idx];
        image r = letterbox_image(im, net->w, net->h);

        //image r = resize_min(im, 320);
        //printf("%d %d\n", r.w, r.h);
        //resize_network(net, r.w, r.h);
        //printf("%d %d\n", r.w, r.h);

        float *X = r.data;

        // float *predictions = network_predict(net, X);
        // if(net->hierarchy) hierarchy_predictions(predictions, net->outputs, net->hierarchy, 1, 1);
        // top_k(predictions, net->outputs, top, indexes);
        // for(i = 0; i < top; ++i){
        //     int index = indexes[i];
        //     //if(net->hierarchy) printf("%d, %s: %f, parent: %s \n",index, names[index], predictions[index], (net->hierarchy->parent[index] >= 0) ? names[net->hierarchy->parent[index]] : "Root");
        //     //else printf("%s: %f\n",names[index], predictions[index]);
        //     printf("%5.2f%%: %s\n", predictions[index]*100, names[index]);
        // }
        if(r.data != im.data) free_image(r);
    }
}

void predict_classifier_batch(list *sections, list *labels, image *imgs, int top, char *weights, int batch)
{
    if (net == NULL) {
        printf("No neural network in enclave..\n");
        printf("%s %d\n", weights, batch);
        char *local_weights = (char *) calloc(256, sizeof(char));
        for (int i = 0; weights[i] != '\0'; ++i) {
            local_weights[i] = weights[i];
        }
        net = load_network(sections, local_weights, 0);
        set_batch_network(net, 1);
        srand(2222222);
        free(local_weights);
        printf("Done loading trained network model in enclave..\n");
    }
    if (batch == 0) return;
    set_batch_network(net, batch);
    srand(2222222);

    int i = 0;
    char **names = (char **)list_to_array(labels);
    int *indexes = calloc(top, sizeof(int));
    
    size_t img_size = net->w * net->h * net->c;
    printf("img_size: %d = %d * %d * %d, batch %d\n", img_size, net->w, net->h, net->c, net->batch);
    float *X = calloc(batch * img_size, sizeof(float));
    for (int b=0; b < batch; ++b) {
        image im = imgs[b];
        image r = letterbox_image(im, net->w, net->h); // resize image to network size
        assert(img_size == r.h * r.w * r.c); // must be consistent
        memcpy(X + b * img_size, r.data, img_size * sizeof(float));
        free_image(r);
    }

    float *batch_predictions = network_predict(net, X);

    for (int b = 0; b < batch; ++b) {
        float* predictions = batch_predictions + net->outputs * b;
        top_k(predictions, net->outputs, top, indexes);
        // for(i = 0; i < top; ++i){
        //     int index = indexes[i];
        //     printf("%5.2f%%: %s\n", predictions[index]*100, names[index]);
        // }
    }
    free(X);
    free(indexes);
    free_network(net);
    net = NULL;
}

