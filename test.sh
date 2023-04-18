#!/bin/bash
## now loop through the above array
for i in "resnet18" "resnet34" "resnet50" "resnet101" "resnet152"
do
   echo "$i"
    ./app ./App/dnet-out/cfg/$i.cfg ./App/dnet-out/data/imagenet.data ./App/dnet-out/data/imagenet/imagenet.image.list ./App/dnet-out/backup/$i.weights 2> $i.out
done

# You can access them using echo "${arr[0]}", "${arr[1]}" also


