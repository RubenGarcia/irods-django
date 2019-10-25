USER=ruben
CreateBasePaths=False
CreateProjects=False
CreateUser=False
CreateUserDatasets=False
CreatePublicDatasets=True

iinit
#create user, add aua
#create home
if [ $CreateBasePaths == "True" ] ; then
	imkdir /tempZone/user
	imkdir /tempZone/group
	imkdir /tempZone/public
	for i in 5 6 7; do
		imkdir /tempZone/user/wp$i
		imkdir /tempZone/group/wp$i
		imkdir /tempZone/public/wp$i
	done
fi

if [ $CreateProjects == "True" ] ; then
	for i in 1 2; do
          for j in 5 6; do
		imkdir /tempZone/user/wp$j/projectname$j$i
          done
	done
fi

if [ $CreateUser == "True" ] ; then
        for i in 1 2; do
           for j in 5 6; do
                imkdir /tempZone/user/wp$j/projectname$j$i/$USER
		ichmod -r own $USER /tempZone/user/wp$j/projectname$j$i/$USER
           done
        done
fi

if [ $CreateUserDatasets == "True" ] ; then
#private datasets for $USER
	for k in 1 2 3; do
	  for i in 1 2; do
           for j in 5 6; do
		imkdir /tempZone/user/wp$j/projectname$j$i/$USER/dataset$k
		export DATASET=dataset$k
		RK=`expr \( $k + 1 \) % 3`
		export RDATASET=dataset$RK
		export DPATH=/tempZone/user/wp$j/projectname$j$i/$USER
		./step2.sh
		ichmod -r own $USER /tempZone/user/wp$j/projectname$j$i/$USER/dataset$k
           done
          done
        done
fi

if [ $CreatePublicDatasets == "True" ] ; then

   for i in 1 2; do
      for j in 5 6 7; do
          imkdir /tempZone/public/wp$j/projectname$j$i
      done
   done

        for k in 1 2 3; do
          for i in 1 2; do
           for j in 5 6 7; do
                export DATASET=dataset$j$i$k
                RK=`expr \( $k + 1 \) % 3`
                export RDATASET=dataset$RK
                export DPATH=/tempZone/public/wp$j/projectname$j$i
                ./step2.sh
		#ichmod -r own public $DPATH/$DATASET
           done
          done
        done
fi     
	
