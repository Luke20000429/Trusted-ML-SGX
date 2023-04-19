
#include "dnet_sgx_utils.h"
#include "darknet.h"
#include "trainer.h"
#include "checks.h"

//global network model
network *net = NULL;

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

    char **names = (char **)list_to_array(labels);
    int *indexes = calloc(top, sizeof(int));
    int i = 0;
    for (int image_idx = 0; image_idx < image_num; image_idx++) {
        printf("Infer image %d of total %d\n", image_idx, image_num);
        image im = img[image_idx];
        image r = letterbox_image(im, net->w, net->h);

        float *X = r.data;

        float *predictions = network_predict(net, X);
        if(net->hierarchy) hierarchy_predictions(predictions, net->outputs, net->hierarchy, 1, 1);
        top_k(predictions, net->outputs, top, indexes);
        for(i = 0; i < top; ++i){
            int index = indexes[i];
            printf("%5.2f%%: %s\n", predictions[index]*100, names[index]);
        }
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
        for(i = 0; i < top; ++i){
            int index = indexes[i];
            printf("%5.2f%%: %s\n", predictions[index]*100, names[index]);
        }
    }
    free(X);
    free(indexes);
    free_network(net);
    net = NULL;
}

