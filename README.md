### To run the program: 
`./app <cfg_file> <data_file> <image_list_file> <sealed_weights_file> <num_of_images>` 

```
./app ./App/dnet-out/cfg/resnet18.cfg ./App/dnet-out/data/imagenet.data ./App/dnet-out/data/imagenet/imagenet.image.list ./App/dnet-out/backup/resnet18.seal 10
```

To seal a weights file, checkout to branch [seal-unseal](https://github.com/Luke20000429/Trusted-ML-SGX/tree/seal-unseal), change the path in provision.cpp and run it.
