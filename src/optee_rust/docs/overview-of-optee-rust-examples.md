---
permalink: /trustzone-sdk-docs/overview-of-optee-rust-examples
---

# Overview of OP-TEE Rust Examples

All OP-TEE Rust examples are suffixed with `-rs`, which work as standalone host
application and corresponding TA (Trusted Application) and can be found in
separate directories.

To install all examples in `SDK_ROOT_DIR/out/`, run `make examples-install`
after `make examples`.

To compile one of the examples, run `make -C examples/EXAMPLE_DIR`.

| Host application name        | TA UUID                                | Description                                                  |
| ---------------------------- | -------------------------------------- | ------------------------------------------------------------ |
| acipher-rs                   | `057f4b66-bdab-11eb-96cf-33d6e41cc849` | Generate an RSA key pair,  encrypt a supplied string and decrypt it. |
| aes-rs                       | `0864c8ec-bdab-11eb-8926-c7fa47a8c92d` | Run an AES encryption and decryption.                        |
| authentication-rs            | `0a5a06b2-bdab-11eb-add0-77f29de31296` | Run AES-CCM authenticated encryption / decryption.           |
| big_int-rs                   | `0bef16a2-bdab-11eb-94be-6f9815f37c21` | Do mathematical operations of big integers, such as addition, subtraction, multiplication, division, etc. |
| diffie_hellman-rs            | `0e6bf4fe-bdab-11eb-9bc5-3f4ecb50aee7` | Run Diffie-Hellman key exchange to derive shared secrets.    |
| digest-rs                    | `10de87e2-bdab-11eb-b73c-63fec73e597c` | Calculate the hash of the message using SHA256 digest algorithm. |
| hello_world-rs               | `133af0ca-bdab-11eb-9130-43bf7873bf67` | Increment and decrement an integer value.                    |
| hotp-rs                      | `1585d412-bdab-11eb-ba91-3b085fd2601f` | Generate HMAC based One Time Password which is  described in [RFC4226](https://www.ietf.org/rfc/rfc4226.txt). |
| message_passing_interface-rs | `17556a46-bdab-11eb-b325-d38c9a9af725` | Passing serde json message between host application and TA, which is more convenient to send structured data. |
| random-rs                    | `197c710c-bdab-11eb-8f3f-17a5f698d23b` | Generate a random UUID.                                      |
| secure_storage-rs            | `1cd6d392-bdab-11eb-9082-abc902ac5cd4` | Read / write / delete raw data from / into the OP-TEE secure storage. |
| serde-rs                     | `1ed47816-bdab-11eb-9ebd-3ffe0648da93` | Invoke third party crate `serde` for serialization and deserialization. |
| supp_plugin-rs               | `255fc838-de89-42d3-9a8e-d044c50fa57c` | TA actively invokes a command defined in normal world plugins. Do interaction between host <-> TA <-> plugin. The plugin is identified by UUID: ef620757-fa2b-4f19-a1c4-6e51cfe4c0f9. |
| tcp_client-rs                | `59db8536-e5e6-11eb-8e9b-a316ce7a6568` | Do HTTP connection from Trusted Application.                 |
| time-rs                      | `21b1a1da-bdab-11eb-b614-275a7098826f` | Set / get TEE time.                                          |
| udp_socket-rs                | `87c2d78e-eb7b-11eb-8d25-df4d5338f285` | Do UDP socket connection from Trusted Application.           |
| signature_verification-rs    | `c7e478c2-89b3-46eb-ac19-571e66c3830d` | Sign a message and verify the signature using the third party crate [ring](https://github.com/veracruz-project/ring). |
| tls_client-rs                | `ec55bfe2-d9c7-11eb-8b0e-f3f8fad927f7` | Do TLS connection from Trusted Application.                  |
| tls_server-rs                | `69547de6-f47e-11eb-994e-f34e88d5c2b4` | Set up the TLS server in Trusted Application.                |
