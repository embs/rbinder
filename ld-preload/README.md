Compile

    $ gcc -fPIC -shared -o rbinder.so rbinder.c -ldl

Run

    $ LD_PRELOAD=/home/embs/git/embs/rbinder/ld-preload/rbinder.so <executable>
