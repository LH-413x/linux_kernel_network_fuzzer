user=tester
scp -P 22055 cmake-build-debug/Bin/* ${user}@localhost:/home/${user}/workspace/
scp -P 22055 cmake-build-debug/Lib/* ${user}@localhost:/home/${user}/workspace/
scp -P 22055 /usr/local/lib/libnl-xfrm-3.so.200 ${user}@localhost:/home/${user}/workspace/
scp -P 22055 /usr/local/lib/libnl-3.so.200 ${user}@localhost:/home/${user}/workspace/
scp -P 22055 ./*.sh ${user}@localhost:/home/${user}/workspace/
ssh -p 22055 ${user}@localhost 'cd ${HOME}/workspace/ ; ./debug.sh ./xfrm_developer_example'
