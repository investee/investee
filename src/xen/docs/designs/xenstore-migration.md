# Xenstore Migration

## Background

The design for *Non-Cooperative Migration of Guests*[1] explains that extra
save records are required in the migrations stream to allow a guest running PV
drivers to be migrated without its co-operation. Moreover the save records must
include details of registered xenstore watches as well as content; information
that cannot currently be recovered from `xenstored`, and hence some extension
to the xenstored implementations will also be required.

As a similar set of data is needed for transferring xenstore data from one
instance to another when live updating xenstored this document proposes an
image format for a 'migration stream' suitable for both purposes.

## Proposal

The image format consists of a _header_ followed by 1 or more _records_. Each
record consists of a type and length field, followed by any data mandated by
the record type. At minimum there will be a single record of type `END`
(defined below).

### Header

The header identifies the stream as a `xenstore` stream, including the version
of the specification that it complies with.

All fields in this header must be in _big-endian_ byte order, regardless of
the setting of the endianness bit.


```
    0       1       2       3       4       5       6       7    octet
+-------+-------+-------+-------+-------+-------+-------+-------+
| ident                                                         |
+-------------------------------+-------------------------------|
| version                       | flags                         |
+-------------------------------+-------------------------------+
```


| Field     | Description                                       |
|-----------|---------------------------------------------------|
| `ident`   | 0x78656e73746f7265 ('xenstore' in ASCII)          |
|           |                                                   |
| `version` | The version of the specification, defined values: |
|           | 0x00000001: all fields and records without any    |
|           |             explicitly mentioned version          |
|           |             dependency are valid.                 |
|           | 0x00000002: all fields and records valid for      |
|           |             version 1 plus fields and records     |
|           |             explicitly stated to be supported in  |
|           |             version 2 are valid.                  |
|           |                                                   |
| `flags`   | 0 (LSB): Endianness: 0 = little, 1 = big          |
|           |                                                   |
|           | 1-31: Reserved (must be zero)                     |

### Records

Records immediately follow the header and have the following format:


```
    0       1       2       3       4       5       6       7    octet
+-------+-------+-------+-------+-------+-------+-------+-------+
| type                          | len                           |
+-------------------------------+-------------------------------+
| body
...
|       | padding (0 to 7 octets)                               |
+-------+-------------------------------------------------------+
```

NOTE: padding octets or fields not valid in the used version here and in all
      subsequent format specifications must be written as zero and should be
      ignored when the stream is read.


| Field  | Description                                          |
|--------|------------------------------------------------------|
| `type` | 0x00000000: END                                      |
|        | 0x00000001: GLOBAL_DATA                              |
|        | 0x00000002: CONNECTION_DATA                          |
|        | 0x00000003: WATCH_DATA                               |
|        | 0x00000004: TRANSACTION_DATA                         |
|        | 0x00000005: NODE_DATA                                |
|        | 0x00000006: GLOBAL_QUOTA_DATA                        |
|        | 0x00000007: DOMAIN_DATA                              |
|        | 0x00000008: WATCH_DATA_EXTENDED (version 2 and up)   |
|        | 0x00000009 - 0xFFFFFFFF: reserved for future use     |
|        |                                                      |
| `len`  | The length (in octets) of `body`                     |
|        |                                                      |
| `body` | The type-specific record data                        |

Some records will depend on other records in the migration stream. Records
upon which other records depend must always appear earlier in the stream.

The various formats of the type-specific data are described in the following
sections:

\pagebreak

### END

The end record marks the end of the image, and is the final record
in the stream.

```
    0       1       2       3       4       5       6       7    octet
+-------+-------+-------+-------+-------+-------+-------+-------+
```


The end record contains no fields; its body length is 0.

\pagebreak

### GLOBAL_DATA

This record is only relevant for live update. It contains details of global
xenstored state that needs to be restored.

```
    0       1       2       3    octet
+-------+-------+-------+-------+
| rw-socket-fd                  |
+-------------------------------+
| evtchn-fd                     |
+-------------------------------+
```


| Field          | Description                                  |
|----------------|----------------------------------------------|
| `rw-socket-fd` | The file descriptor of the socket accepting  |
|                | read-write connections                       |
|                |                                              |
| `evtchn-fd`    | The file descriptor used to communicate with |
|                | the event channel driver                     |

xenstored will resume in the original process context. Hence `rw-socket-fd`
simply specifies the file descriptor of the socket. Sockets are not always
used, however, and so -1 will be used to denote an unused socket.

\pagebreak

### CONNECTION_DATA

For live update the image format will contain a `CONNECTION_DATA` record for
each connection to xenstore. For migration it will only contain a record for
the domain being migrated.


```
    0       1       2       3       4       5       6       7    octet
+-------+-------+-------+-------+-------+-------+-------+-------+
| conn-id                       | conn-type     |               |
+-------------------------------+---------------+---------------+
| conn-spec
...
+---------------+---------------+-------------------------------+
| in-data-len   | out-resp-len  | out-data-len                  |
+---------------+---------------+-------------------------------+
| data
...
```


| Field          | Description                                  |
|----------------|----------------------------------------------|
| `conn-id`      | A non-zero number used to identify this      |
|                | connection in subsequent connection-specific |
|                | records                                      |
|                |                                              |
| `conn-type`    | 0x0000: shared ring                          |
|                | 0x0001: socket                               |
|                | 0x0002 - 0xFFFF: reserved for future use     |
|                |                                              |
| `conn-spec`    | See below                                    |
|                |                                              |
| `in-data-len`  | The length (in octets) of any data read      |
|                | from the connection not yet processed        |
|                |                                              |
| `out-resp-len` | The length (in octets) of a partial response |
|                | not yet written to the connection            |
|                |                                              |
| `out-data-len` | The length (in octets) of any pending data   |
|                | not yet written to the connection, including |
|                | a partial response (see `out-resp-len`)      |
|                |                                              |
| `data`         | Pending data: first in-data-len octets of    |
|                | read data, then out-data-len octets of       |
|                | written data (any of both may be empty)      |

In case of live update the connection record for the connection via which
the live update command was issued will contain the response for the live
update command in the pending not yet written data.

\pagebreak

The format of `conn-spec` is dependent upon `conn-type`.

For `shared ring` connections it is as follows:


```
    0       1       2       3       4       5       6       7    octet
+---------------+---------------+---------------+---------------+
| domid         | tdomid        | evtchn                        |
+-------------------------------+-------------------------------+
```


| Field     | Description                                       |
|-----------|---------------------------------------------------|
| `domid`   | The domain-id that owns the shared page           |
|           |                                                   |
| `tdomid`  | The domain-id that `domid` acts on behalf of if   |
|           | it has been subject to an SET_TARGET              |
|           | operation [2] or DOMID_INVALID [3] otherwise      |
|           |                                                   |
| `evtchn`  | The port number of the interdomain channel used   |
|           | by xenstored to communicate with `domid`          |
|           |                                                   |

The GFN of the shared page is not preserved because the ABI reserves
entry 1 in `domid`'s grant table to point to the xenstore shared page.
Note there is no guarantee the page will still be valid at the time of
the restore because a domain can revoke the permission.

For `socket` connections it is as follows:


```
+---------------+---------------+---------------+---------------+
| socket-fd                     | pad                           |
+-------------------------------+-------------------------------+
```


| Field       | Description                                     |
|-------------|-------------------------------------------------|
| `socket-fd` | The file descriptor of the connected socket     |

This type of connection is only relevant for live update, where the xenstored
resumes in the original process context. Hence `socket-fd` simply specify
the file descriptor of the socket connection.

\pagebreak

### WATCH_DATA

The image format will contain either a `WATCH_DATA` or a `WATCH_DATA_EXTENDED`
record for each watch registered by a connection for which there is
`CONNECTION_DATA` record previously present.

```
    0       1       2       3    octet
+-------+-------+-------+-------+
| conn-id                       |
+---------------+---------------+
| wpath-len     | token-len     |
+---------------+---------------+
| wpath
...
| token
...
```


| Field       | Description                                     |
|-------------|-------------------------------------------------|
| `conn-id`   | The connection that issued the `WATCH`          |
|             | operation [2]                                   |
|             |                                                 |
| `wpath-len` | The length (in octets) of `wpath` including the |
|             | NUL terminator                                  |
|             |                                                 |
| `token-len` | The length (in octets) of `token` including the |
|             | NUL terminator                                  |
|             |                                                 |
| `wpath`     | The watch path, as specified in the `WATCH`     |
|             | operation                                       |
|             |                                                 |
| `token`     | The watch identifier token, as specified in the |
|             | `WATCH` operation                               |

\pagebreak

### WATCH_DATA_EXTENDED

The image format will contain either a `WATCH_DATA` or a `WATCH_DATA_EXTENDED`
record for each watch registered by a connection for which there is
`CONNECTION_DATA` record previously present. The `WATCH_DATA_EXTENDED` record
type is valid only in version 2 and later.

```
    0       1       2       3    octet
+-------+-------+-------+-------+
| conn-id                       |
+---------------+---------------+
| wpath-len     | token-len     |
+---------------+---------------+
| depth         | pad           |
+---------------+---------------+
| wpath
...
| token
...
```


| Field       | Description                                     |
|-------------|-------------------------------------------------|
| `conn-id`   | The connection that issued the `WATCH`          |
|             | operation [2]                                   |
|             |                                                 |
| `wpath-len` | The length (in octets) of `wpath` including the |
|             | NUL terminator                                  |
|             |                                                 |
| `token-len` | The length (in octets) of `token` including the |
|             | NUL terminator                                  |
|             |                                                 |
| `depth`     | The number of directory levels below the        |
|             | watched path to consider for a match.           |
|             | A value of 0xffff is used for unlimited depth.  |
|             |                                                 |
| `wpath`     | The watch path, as specified in the `WATCH`     |
|             | operation                                       |
|             |                                                 |
| `token`     | The watch identifier token, as specified in the |
|             | `WATCH` operation                               |

\pagebreak

### TRANSACTION_DATA

The image format will contain a `TRANSACTION_DATA` record for each transaction
that is pending on a connection for which there is `CONNECTION_DATA` record
previously present.


```
    0       1       2       3    octet
+-------+-------+-------+-------+
| conn-id                       |
+-------------------------------+
| tx-id                         |
+-------------------------------+
```


| Field          | Description                                  |
|----------------|----------------------------------------------|
| `conn-id`      | The connection that issued the               |
|                | `TRANSACTION_START` operation [2]            |
|                |                                              |
| `tx-id`        | The transaction id passed back to the domain |
|                | by the `TRANSACTION_START` operation         |

\pagebreak

### NODE_DATA

For live update the image format will contain a `NODE_DATA` record for each
node in xenstore. For migration it will only contain a record for the nodes
relating to the domain being migrated. The `NODE_DATA` may be related to
a _committed_ node (globally visible in xenstored) or a _pending_ node (created
or modified by a transaction for which there is also a `TRANSACTION_DATA`
record previously present).

Each _committed_ node in the stream is required to have an already known parent
node. A parent node is known if it was either in the node data base before the
stream was started to be processed, or if a `NODE_DATA` record for that parent
node has already been processed in the stream.


```
    0       1       2       3    octet
+-------+-------+-------+-------+
| conn-id                       |
+-------------------------------+
| tx-id                         |
+---------------+---------------+
| path-len      | value-len     |
+---------------+---------------+
| access        | perm-count    |
+---------------+---------------+
| perm1                         |
+-------------------------------+
...
+-------------------------------+
| permN                         |
+---------------+---------------+
| path
...
| value
...
```


| Field        | Description                                    |
|--------------|------------------------------------------------|
| `conn-id`    | If this value is non-zero then this record     |
|              | related to a pending transaction               |
|              |                                                |
| `tx-id`      | This value should be ignored if `conn-id` is   |
|              | zero. Otherwise it specifies the id of the     |
|              | pending transaction                            |
|              |                                                |
| `path-len`   | The length (in octets) of `path` including the |
|              | NUL terminator                                 |
|              |                                                |
| `value-len`  | The length (in octets) of `value` (which will  |
|              | be zero for a deleted node)                    |
|              |                                                |
| `access`     | This value should be ignored if this record    |
|              | does not relate to a pending transaction,      |
|              | otherwise it specifies the accesses made to    |
|              | the node and hence is a bitwise OR of:         |
|              |                                                |
|              | 0x0001: read                                   |
|              | 0x0002: written                                |
|              |                                                |
|              | The value will be zero for a deleted node      |
|              |                                                |
| `perm-count` | The number (N) of node permission specifiers   |
|              | (which will be 0 for a node deleted in a       |
|              | pending transaction)                           |
|              |                                                |
| `perm1..N`   | A list of zero or more node permission         |
|              | specifiers (see below)                         |
|              |                                                |
| `path`       | The absolute path of the node                  |
|              |                                                |
| `value`      | The node value (which may be empty or contain  |
|              | NUL octets)                                    |


A node permission specifier has the following format:


```
    0       1       2       3    octet
+-------+-------+-------+-------+
| perm  | flags | domid         |
+-------+-------+---------------+
```

| Field   | Description                                         |
|---------|-----------------------------------------------------|
| `perm`  | One of the ASCII values `w`, `r`, `b` or `n` as     |
|         | specified for the `SET_PERMS` operation [2]         |
|         |                                                     |
| `flags` | A bit-wise OR of:                                   |
|         | 0x01: stale permission, ignore when checking        |
|         |       permissions                                   |
|         |                                                     |
| `domid` | The domain-id to which the permission relates       |

Note that perm1 defines the domain owning the node. See [4] for more
explanation of node permissions.

\pagebreak

### GLOBAL_QUOTA_DATA

This record is only relevant for live update. It contains the global settings
of xenstored quota.

```
    0       1       2       3    octet
+-------+-------+-------+-------+
| n-dom-quota   | n-glob-quota  |
+---------------+---------------+
| quota-val 1                   |
+-------------------------------+
...
+-------------------------------+
| quota-val N                   |
+-------------------------------+
| quota-names
...
```


| Field          | Description                                  |
|----------------|----------------------------------------------|
| `n-dom-quota`  | Number of quota values which apply per       |
|                | domain by default.                                      |
|                |                                              |
| `n-glob-quota` | Number of quota values which apply globally  |
|                | only.                                        |
|                |                                              |
| `quota-val`    | Quota values, first the ones applying per    |
|                | domain, then the ones applying globally. A   |
|                | value of 0 has the semantics of "unlimited". |
|                |                                              |
| `quota-names`  | 0 delimited strings of the quota names in    |
|                | the same sequence as the `quota-val` values. |


Allowed quota names are those explicitly named in [2] for the `GET_QUOTA`
and `SET_QUOTA` commands, plus implementation specific ones. Quota names not
recognized by the receiving side should not have any effect on behavior for
the receiving side (they can be ignored or preserved for inclusion in
future live migration/update streams).

\pagebreak

### DOMAIN_DATA

This record is optional and can be present once for each domain.


```
    0       1       2       3     octet
+-------+-------+-------+-------+
| domain-id     | n-quota       |
+---------------+---------------+
| features                      |
+-------------------------------+
| quota-val 1                   |
+-------------------------------+
...
+-------------------------------+
| quota-val N                   |
+-------------------------------+
| quota-names
...
```


| Field          | Description                                  |
|----------------|----------------------------------------------|
| `domain-id`    | The domain-id of the domain this record      |
|                | belongs to.                                  |
|                |                                              |
| `n-quota`      | Number of quota values.                      |
|                |                                              |
| `features`     | Value of the feature field visible by the    |
|                | guest at offset 2064 of the ring page.       |
|                | Only valid for version 2 and later.          |
|                |                                              |
| `quota-val`    | Quota values, a value of 0 has the semantics |
|                | "unlimited".                                 |
|                |                                              |
| `quota-names`  | 0 delimited strings of the quota names in    |
|                | the same sequence as the `quota-val` values. |

Allowed quota names are those explicitly named in [2] for the `GET_QUOTA`
and `SET_QUOTA` commands, plus implementation specific ones. Quota names not
recognized by the receiving side should not have any effect on behavior for
the receiving side (they can be ignored or preserved for inclusion in
future live migration/update streams).

\pagebreak


* * *

[1] See https://xenbits.xen.org/gitweb/?p=xen.git;a=blob;f=docs/designs/non-cooperative-migration.md

[2] See https://xenbits.xen.org/gitweb/?p=xen.git;a=blob;f=docs/misc/xenstore.txt

[3] See https://xenbits.xen.org/gitweb/?p=xen.git;a=blob;f=xen/include/public/xen.h;hb=HEAD#l612

[4] https://wiki.xen.org/wiki/XenBus
