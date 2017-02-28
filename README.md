# QJWT

## Introduction

This class implements a subset of the [JSON Web Token](https://en.wikipedia.org/wiki/JSON_Web_Token)
open standard [RFC 7519](https://tools.ietf.org/html/rfc7519) and is heavily inspired by the following projects:
- NodeJS (https://github.com/nodejs/node/blob/master/src/node_crypto.cc)
- ecdsa-sig-formatter (https://github.com/Brightspace/node-ecdsa-sig-formatter)
- QJsonWebToken (https://github.com/juangburgos/QJsonWebToken)

Currently this implementation only supports the following algorithms:

Alg   | Parameter Value  Algorithm
----- | ---------------------------------------------------
HS256 | HMAC using SHA-256 hash algorithm
HS384 | HMAC using SHA-384 hash algorithm
HS512 | HMAC using SHA-512 hash algorithm
RS256 | RSASSA-PKCS1-v1_5 using SHA-256 hash algorithm
RS384 | RSASSA-PKCS1-v1_5 using SHA-384 hash algorithm
RS512 | RSASSA-PKCS1-v1_5 using SHA-512 hash algorithm
ES256 | ECDSA using P-256 curve and SHA-256 hash algorithm
ES384 | ECDSA using P-384 curve and SHA-384 hash algorithm
ES512 | ECDSA using P-521 curve and SHA-512 hash algorithm

## Include

In order to include this class in your project, in the qt project **.pro** file add the lines:

```
include(qjwt.pri)
```

## Usage

The repository of this project includes an example that demonstrate the use of this class:

* ./example/  : Example that shows how to first sign and then verify the created token.
