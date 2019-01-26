%% @doc Eliptic curve digital signature algorithm
%%
%% Helper functions for encoding/decoding ECDSA signature
%%
%% @end
-module(jwt_ecdsa).

-include_lib("public_key/include/public_key.hrl").

-export([
    signature/1,
    signature/3
]).

%% @doc
%%
%% Transcode the ECDSA Base64-encoded signature into ASN.1/DER format
%%
%% @end
signature(Base64Sig) ->
    Signature = base64url:decode(Base64Sig),
    SignatureLen = byte_size(Signature),
    {RBin, SBin} = split_binary(Signature, (SignatureLen div 2)),
    R = crypto:bytes_to_integer(RBin),
    S = crypto:bytes_to_integer(SBin),
    public_key:der_encode('ECDSA-Sig-Value', #'ECDSA-Sig-Value'{ r = R, s = S }).

%% @doc
%%
%% Transcodes the JCA ASN.1/DER-encoded signature into the concatenated R + S format
%% a.k.a <em>raw</em> format
%%
%% @end
signature(Payload, Crypto, Key) ->
    Der = public_key:sign(Payload, Crypto, Key),
    raw(Der, Key).

raw(Der, #'ECPrivateKey'{parameters = {namedCurve, NamedCurve}}) ->
    #'ECDSA-Sig-Value'{ r = R, s = S } = public_key:der_decode('ECDSA-Sig-Value', Der),
    GroupDegree = group_degree(pubkey_cert_records:namedCurves(NamedCurve)),
    Size = (GroupDegree + 7) div 8,
    RBin = int_to_bin(R),
    SBin = int_to_bin(S),
    RPad = pad(RBin, Size),
    SPad = pad(SBin, Size),
    <<RPad/binary, SPad/binary>>.

%% @private
int_to_bin(X) when X < 0 ->
    int_to_bin_neg(X, []);
int_to_bin(X) ->
    int_to_bin_pos(X, []).

%% @private
int_to_bin_pos(0, Ds = [_|_]) ->
    list_to_binary(Ds);
int_to_bin_pos(X, Ds) ->
    int_to_bin_pos(X bsr 8, [(X band 255)|Ds]).

%% @private
int_to_bin_neg(-1, Ds = [MSB|_]) when MSB >= 16#80 ->
    list_to_binary(Ds);
int_to_bin_neg(X,Ds) ->
    int_to_bin_neg(X bsr 8, [(X band 255)|Ds]).

%% @private
pad(Bin, Size) when byte_size(Bin) =:= Size ->
    Bin;
pad(Bin, Size) when byte_size(Bin) < Size ->
    pad(<<0, Bin/binary>>, Size).

%% See the OpenSSL documentation for EC_GROUP_get_degree()
group_degree(sect571r1) -> 571;
group_degree(sect571k1) -> 571;
group_degree(sect409r1) -> 409;
group_degree(sect409k1) -> 409;
group_degree(secp521r1) -> 521;
group_degree(secp384r1) -> 384;
group_degree(secp224r1) -> 224;
group_degree(secp224k1) -> 224;
group_degree(secp192k1) -> 192;
group_degree(secp160r2) -> 160;
group_degree(secp128r2) -> 128;
group_degree(secp128r1) -> 128;
group_degree(sect233r1) -> 233;
group_degree(sect233k1) -> 233;
group_degree(sect193r2) -> 193;
group_degree(sect193r1) -> 193;
group_degree(sect131r2) -> 131;
group_degree(sect131r1) -> 131;
group_degree(sect283r1) -> 283;
group_degree(sect283k1) -> 283;
group_degree(sect163r2) -> 163;
group_degree(secp256k1) -> 256;
group_degree(secp160k1) -> 160;
group_degree(secp160r1) -> 160;
group_degree(secp112r2) -> 112;
group_degree(secp112r1) -> 112;
group_degree(sect113r2) -> 113;
group_degree(sect113r1) -> 113;
group_degree(sect239k1) -> 239;
group_degree(sect163r1) -> 163;
group_degree(sect163k1) -> 163;
group_degree(secp256r1) -> 256;
group_degree(secp192r1) -> 192;
group_degree(brainpoolP160r1) -> 160;
group_degree(brainpoolP160t1) -> 160;
group_degree(brainpoolP192r1) -> 192;
group_degree(brainpoolP192t1) -> 192;
group_degree(brainpoolP224r1) -> 224;
group_degree(brainpoolP224t1) -> 224;
group_degree(brainpoolP256r1) -> 256;
group_degree(brainpoolP256t1) -> 256;
group_degree(brainpoolP320r1) -> 320;
group_degree(brainpoolP320t1) -> 320;
group_degree(brainpoolP384r1) -> 384;
group_degree(brainpoolP384t1) -> 384;
group_degree(brainpoolP512r1) -> 512;
group_degree(brainpoolP512t1) -> 512.
