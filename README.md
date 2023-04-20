### Introduction
This is an adaptation of darknet to TEE based on Intel-SGX.
To protect the privacy of model provider, the weights of a model is sealed and store in `<model_name>.seal`. The program will unseal the weights in enclave and use it to do inference inside the encalve.

To keep the original interface of darknet, we replace the functionality of `fread` with reading the unsealed buffer inside the enclave. This makes sure no other process can read the weights of the model.

Because this project focuses on observing the performace of ML inference in enclave, the secure communication between enclaves are not implemented. Customer's inputs are read from the disk and results are printed out directly.

### To run the program: 
1. Install Intel SGX SDK and PSW
2. (Note: to simply run tiny model, you can directly go to step 4) Download weights files to `App/dnet-out/backup/` by running the script `App/dnet-out/download_weights.sh`
3. To seal a weights file, checkout to branch [seal-unseal](https://github.com/Luke20000429/Trusted-ML-SGX/tree/seal-unseal), change the path in provision.cpp and run `./provision`, which will generate a file `*.seal`.
4. To run the program, run the following command:
`./app <cfg_file> <data_file> <image_list_file> <sealed_weights_file> <num_of_images>` 
For example:
```
./app ./App/dnet-out/cfg/tiny.cfg ./App/dnet-out/data/imagenet.data ./App/dnet-out/data/imagenet/imagenet.image.list ./App/dnet-out/backup/tiny.seal 10
```
The program will read image from the path specified in `image_list_file` and unseal the weights file. Then it will do inference on the images and print the result. 


