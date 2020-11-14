# quic migration based on picoquic

Picoquic is a minimalist implementation of the QUIC protocol, as defined by the IETF.
The IETF spec started with the version of QUIC defined by Google and
implemented in Chrome, but the IETF spec is independent of Chrome, and
does not attempt to be backward compatible. The main developer is 
Christian Huitema.

This project is a Master thesis project which realize a quic connection migration based on picoquic.

# How to use
The main codes are on the branch called "pico_migration".

## Switch branch
You need to switch to the branch which is built for the picoquic connection migration test.

~~~
   git checkout pico_migration
~~~

## Building Picoquic

Picoquic is developed in C, and can be built under Windows or Linux. Building the
project requires first managing the dependencies, [Picotls](https://github.com/h2o/picotls)
and OpenSSL. Please note that you will need a recent version of Picotls --
the Picotls API has eveolved recently to support the latest version of QUIC. The
current code is tested against the Picotls version of Sat Sep 12 20:48:55 2020 +0900,
after commit `2464adadf28c1b924416831d24ca62380936a209`. The code uses OpenSSL
version 1.1.1.

To build Picoquic on Linux, you need to:

 * Install and build Openssl on your machine

 * Clone and compile Picotls, using cmake as explained in the Picotls documentation.

 * Clone and compile Picoquic:
~~~
   cmake .
   make
~~~
 * Run the test program `picoquic_ct` to verify the port.

## Run picoquic demo

For now the test codes are added on picoquicdemo.c file.

On the server side:
~~~
   ./picoquicdemo -p [port_number]
~~~

On the client side:
~~~
   ./picoquicdemo 127.0.0.1 [port_number]
~~~
