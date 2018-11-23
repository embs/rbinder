from gfads/carts:ldpreload

ADD test.c test.c
ADD test-wrapper.c test-wrapper.c
USER root
ENV LD_PRELOAD ""
#RUN gcc -fPIC -shared -o test-wrapper.so test-wrapper.c -ldl
#RUN gcc -o test test.c
#ENV LD_PRELOAD /usr/src/app/test-wrapper.so

ENTRYPOINT ["./test"]
