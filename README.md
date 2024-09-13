# InvesTEE

InvesTEE is a framework for showcasing lawful TEE-supported remote forensic investigations. Please see our [IMF'24](https://www.uni-saarland.de/lehrstuhl/brodowski/veranstaltungen/imf-conference.html) paper for more details: [InvesTEE: A TEE-supported Framework for Lawful Remote Forensic Investigations](https://dl.acm.org/doi/pdf/10.1145/3680294).

## Requirements
We tested InvesTEE on Ubuntu 22.04. You require `git` to download the source code.

Install the [docker engine](https://docs.docker.com/engine/install/ubuntu/). We tested `Docker version 26.1.3, build b72abbb`. Additionally, we are using the `compose` plugin (`Docker Compose version v2.27.1`) to create and run the container.

## Building with Docker
We recommend building and running InvesTEE using our `Dockerfile`. For easy usage, we provide a `Makefile` that runs the most relevant commands. Execute the following commands to build a docker container named `investee`.
```
# clone repository
git clone https://github.com/investee/investee.git

# build docker container
cd investee
make build
```

This process will build the container and compile relevant software running inside, including `QEMU` and [OP-TEE](https://optee.readthedocs.io/en/latest/general/about.html)
If successful, you will drop into a shell inside the running container. You may exit the container.

## Directory Structure

| Path | Description |
| :--- | :--- |
| `/docker` | InvesTEE's Dockerfile and docker entrypoints |
| `/src` | InvesTEE's source code. This involves multiple forks of repositories to emulate an ARM64 system as found on modern smartphones. We refer to the [build](https://optee.readthedocs.io/en/latest/building/gits/build.html#build) process provided by [OP-TEE](https://optee.readthedocs.io/en/latest/general/about.html). |
| `/src/optee_examples/investee/host/main.c` | Source code of our Forensic Software running as a Client Application. |
| `/src/optee_os/core/pta/investee.c` | Source code of our Control Software running as a Trusted Application. |
| `src/svc-gdb.log` | Output of SVC logging using a breakpoint in the Linux kernel. This is our ground truth. |
| `src/sw-serial.log` | Output of OP-TEE including the Control Software's SVC logging. You may compare it to `src/svc-gdb.log`. |

## Usage

### Set-up

Interacting with InvesTEE is done using make commands specified in `Makefile`. Have a look into this file for more details.
You may execute `make run-machine` to start the docker container that runs a QEMU machine with OP-TEE and InvesTEE.
Two terminal will pop up: One for the NW (Linux) and one for the SW (OP-TEE) output.
In the NW terminal you can log in as `root` without password. 
To setup the SVC logging for our ground truth that uses gdb breakpoints you may execute `make run-svc-log SVC_HANDLER_ADDR=???` in a new host terminal.
Since we have KASLR active, run `cat /proc/kallsyms | grep el0t_64_sync_handler` in the NW terminal to get the address to hook, i.e., `SVC_HANDLER_ADDR`.
As soon as you run the command you will see logging output when using the NW terminal. The output is also saved to `src/svc-gdb.log`.

### Proof-of-Concept

Next, we run our Proof-of-Concept as explained in the evaluation section in the paper.
To this end, we execute our Forensic Software found at `/usr/bin/optee_example_investee` in the NW terminal.
The binary is a Client Application that will communicate with the Control Software (already loaded into the TEE as a Pseudo Trusted Application) when started.
It will (1) build up a connection to the TEE, (2) request root privileges (starting here the Control Software will place the exception vector table hooking), and (3) open and read `/etc/shadow` and finally run a loop of `sleep` and `printf` calls to keep the connection to the TEE alive (this is optional). 
To run the experiment, go to `/usr/bin` in the NW terminal and execute `./optee_example_investee 2`. If successfull you will see the content of `/etc/shadow`.
You may compare the logging output in `src/svc-gdb.log` and `src/sw-serial.log` to reason about the logged SVCs.


