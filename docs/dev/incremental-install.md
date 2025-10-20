# How ADB incremental-install works

The regular way an app is installed on an Android devices is for ADB to open a
connection to the package manager (`pm`) and write all the bytes. Once received
by `pm`, the app is verified via v2 signature checking, adb gets an
installation reply (SUCCESS or FAILURE [..]), and the operation is considered
over.

Incremental-install is a departure from the idea that all bytes needs to be
pushed for the installation to be considered over. It even allows an app to
start before `pm` has received all the bytes.

## The big picture

The big picture of incremental-install revolves around four concepts.

- Blocks
- Block requests
- Incremental Server (`IS`)
- V4 signature

Each file of an app (apk, splits, obb) are viewed as a series of blocks.

In incremental-install mode, `pm` only need to receive a few blocks to validate
the app and declare installation over (with SUCCESS/FAILURE) which increase
installation speed tremendously.

In the background, ADB will keep on steaming blocks linearly, even after `pm`
reported being "done". The background streaming is done in ADB's embedded
`IS`.

The `IS` sends blocks to the device in order it assumes will be accessed by `pm`.
And then it sends the remaining block from start to end of file.

`pm` will inevitably need blocks it has not received yet. For example, when the
app's Central Directory (located at the end of a zip file) must be read to know
what files are in the apk. This is where block requests enter the picture. The
Android device can issue requests which will make the `IS` bump the priority of
a block so it is sent to the device as soon as possible.

### Incremental-install filesystem

The block requests are not issued by Android Frameworks. Framework is completely
oblivious of the background streaming. Everything is done at the Android kernel
level where file access is detected. If a read lands on a block that has not been
received yet, the kernel issues a block request to get it from the streaming
server immediately.

### App verification

In incremental-install mode, `pm` does minimal verification of app integrity.
- Checks that there is a v4 signature
- Check there is a v2 or v3 signature
- Check that v4 is linked to either v2 or v3
- Check the v4 header is signed with same certificate as v2/v3

The rest of the app verification is done by the Android kernel for each block level
when they are received.

With v2 signing, an apps is signed by building a merkle tree, keeping only the
top node hash, signing it, and embedding it in the apk. On `pm` side, to verify
the app, the merkle tree is rebuilt, and the top hash is compared against the
signed hash. V2 can only work if `pm` has all the bytes of an app which is not
the case here.

#### v4 signing
This problem is solved with V4 signing which does not discard the merkle tree
but embed it in the signed file and also outputs the top merkle node hash in
a .idsig file.

Upon installation the whole merkle tree from V4 is given to `pm` which forwards
it to the Android kernel. The kernel is in charge of verifying the integrity
of each block when they are received from the `IS` via the merkle tree.

For more details about v4 signing, refer to [APK signature scheme v4](https://source.android.com/docs/security/features/apksigning/v4) page.

## How ADB performs incremental-install

To perform incremental-install, ADB needs to do two things.

- Define the block database to `pm`.
- Start a `IS`.

```
  ┌───┐                              ┌────┐
  │adb│                              │ppm │
  └─┬─┘                              └─┬──┘
    │       pm install-incremental     │
    ├─────────────────────────────────►│
    │    ┌────┐                        │
    ├───►│ IS │                        │
    │    └─┬──┘                        │
    X      │                           │
           ├──────────────────────────►│
           ├──────────────────────────►│
           │◄──────────────────────────┤
           ├──────────────────────────►│
           │                           │
```

### Local database

The call to `pm incremental-install` has arguments describing the `IS` database.
It allows the kernel to issue block requests. The arg format to describe the `IS`
database is as follows.

```
filename:file_size:file_id:signature[:protocol_version]
```

where

- `file_id` is the identified that will be used by the kernel for block
requests. There is one arg for each file to be streamed.
- `signature` is the top merkle hash.
- `[:protocol_version]` is optional. (default: 0)

#### Protocol version

If `protocol_version` is 0, the merkle tree of the file is not sent via the `IS`
but instead sent on stdin, before the `IS` is started.

If `protocol_version` is 1, the merkle tree of the file is sent via the `IS`.

The current implementation of ADB only uses version 1.

### Unsigned files

There could be unsigned files to be installed. In this case, `pm` has to be made
aware of them via a special arg format.

```
filename:file_size:file_id
```

These files are not sent via the `IS` but instead sent on stdin, before
the `IS` is started.

```
  ┌───┐                              ┌────┐
  │adb│                              │ppm │
  └─┬─┘                              └─┬──┘
    │       pm install-incremental     │
    ├─────────────────────────────────►│
    │                                  │
    │       (stdin) write(unsigned)    │
    ├─────────────────────────────────►│
    │    ┌────┐                        │
    ├───►│ IS │                        │
    │    └─┬──┘                        │
    X      │                           │
           ├──────────────────────────►│
           ├──────────────────────────►│
           │◄──────────────────────────┤
           ├──────────────────────────►│
           │                           │
```

## ADB Installation Strategy

If the `--incremental` flag is specified, ADB will always use incremental
install, even if some apk files are not v4-signed.

If any other installation mode flag (`--streaming`, `--no-streaming`,
`--no-incremental`) is specified, ADB will never use incremental install, even
if some apk files are v4-signed.

If none of the installation mode flags above is specified, and all apk files are
v4-signed, ADB will use incremental install by default and fall back to regular
install when incremental install fails or the device doesn't support incremental
installations.

## Learn more

There is more documentation about this topic which is unfortunately internal only.

- [go/incremental-adb](go/incremental-adb)
- [go/apk-v4-signature-format](go/apk-v4-signature-format)
- [go/instamatic-design-signature](go/instamatic-design-signature)
