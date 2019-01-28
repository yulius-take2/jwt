

# Module jwt_ecdsa #
* [Description](#description)
* [Function Index](#index)
* [Function Details](#functions)

Eliptic curve digital signature algorithm.

<a name="description"></a>

## Description ##
Helper functions for encoding/decoding ECDSA signature
<a name="index"></a>

## Function Index ##


<table width="100%" border="1" cellspacing="0" cellpadding="2" summary="function index"><tr><td valign="top"><a href="#signature-1">signature/1</a></td><td><p></p>Transcode the ECDSA Base64-encoded signature into ASN.1/DER format.</td></tr><tr><td valign="top"><a href="#signature-3">signature/3</a></td><td><p></p>Transcodes the JCA ASN.1/DER-encoded signature into the concatenated R + S format
a.k.a <em>raw</em> format.</td></tr></table>


<a name="functions"></a>

## Function Details ##

<a name="signature-1"></a>

### signature/1 ###

`signature(Base64Sig) -> any()`

Transcode the ECDSA Base64-encoded signature into ASN.1/DER format

<a name="signature-3"></a>

### signature/3 ###

`signature(Payload, Crypto, Key) -> any()`

Transcodes the JCA ASN.1/DER-encoded signature into the concatenated R + S format
a.k.a _raw_ format

