# RePeL

Prototype implementation of the Retrofittable Protection Library (RePeL), a protocol agnostic library to transparently retrofit integrity protection into industrial legacy protocols.
The library is adaptable to different protocols and message authentication code (MAC)
schemes. For that, RePeL separates code specific to protocols and MAC algorithms into exchangeable `parser` and `mac` modules. We provide a parser for the Modbus TCP protocol
and an integration of SHA26-HMAC as sample modules.

The `repel/` subdirectory contains the library core, while example programs for
the two supported platforms [Contiki-NG](https://github.com/contiki-ng/contiki-ng)
and Linux can be found in `examples-contiki/` and `examples-linux/` respectively.

## Prepare the Contiki-NG build environment
In order to build the example programs for Contiki-NG, set up its toolchain and repository as described [here](https://docs.contiki-ng.org/en/develop/doc/getting-started/Toolchain-installation-on-Linux.html).
Then, copy the library and example program folders into the source tree:

```
cp -R repel <contiki-ng>/os/lib/repel;
cp -R examples-contiki <contiki-ng>/examples/repel
```

Some example programs require a patched `rpl-border-router` service. In the Contiki-NG root directory, run:
```
git apply os/lib/repel/rpl-border-router.patch
```

To fix Contiki OS discarding TCP data that the applications wants to retain, apply the following patch in the Contiki-NG root directory:
```
git apply os/lib/repel/tcp_socket.patch
```

Hardware acceleration on the zoul platform can be enabled by setting `REPEL_USE_HW_ACCEL` to `true` in an example program's `project_conf.h` file. This requires patching TinyDTLS. Therefore, run in the Contiki-NG root directory:
```
git apply os/lib/repel/tinydtls.patch
```

For details on how to build the example programs, refer to the `README.md` files
the corresponding subdirectories.