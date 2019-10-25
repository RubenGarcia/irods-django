#!/bin/bash
#DATASET is the dataset name
#RDATASET is the related dataset name (optional)
#DPATH is the dataset path
export RD=$RANDOM

imkdir $DPATH/$DATASET

dd if=/dev/urandom bs=1k count=1k of=file
iput file $DPATH/$DATASET/$RD.dat

#metadata
R=$(( ( RANDOM % 100 ) + 1900 ))
imeta add -C $DPATH/$DATASET publicationYear $R
R=$(( ( RANDOM % 5 ) + 1 ))
imeta add -C $DPATH/$DATASET creator $R
R=$(( ( RANDOM % 5 ) + 1 ))
imeta add -C $DPATH/$DATASET publisher $R
R=$(( ( RANDOM % 5 ) + 1 ))
imeta add -C $DPATH/$DATASET owner $R
imeta add -C $DPATH/$DATASET identifier doi://lexis-datasets/$DATASET
imeta add -C $DPATH/$DATASET resourceType $RANDOM
imeta add -C $DPATH/$DATASET title $DATASET
if [ "$RDATASET" != "" ] ; then
		imeta add -C $DPATH/$DATASET relatedIdentifier doi://lexis-datasets/$RDATASET
fi
R=$(( ( RANDOM % 5 ) + 1 ))
imeta add -C $DPATH/$DATASET contributor $R

rm -f file
