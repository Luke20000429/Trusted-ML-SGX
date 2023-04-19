#!/bin/bash
## now loop through the above array
for i in "resnet18" "resnet34" "resnet50" "resnet101" "resnet152" "darknet19"
do
   echo "$i"
   wget "https://pjreddie.com/media/files/$i.weights"
done

# You can access them using echo "${arr[0]}", "${arr[1]}" also


