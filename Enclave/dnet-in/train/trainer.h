
#ifndef TRAINER_IN_H
#define TRAINER_IN_H

#if defined(__cplusplus)
extern "C"
{
#endif

    void train_cifar(list *sections, data *training_data, int pmem);
    void train_mnist(list *sections, data *training_data, int pmem);
    void test_cfiar(list *sections, data *test_data, int pmem);
    void test_mnist(list *sections, data *test_data, int pmem);
    void classify_tiny(list *sections, list *labels, image *im, int top);
    void predict_classifier(list *sections, list *labels, image *img, int top, char* wegiths, int image_num);
    
#if defined(__cplusplus)
}
#endif

#endif