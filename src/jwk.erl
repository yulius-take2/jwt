%%
%% RFC 7517: JSON Web Key (JWK) 
%% 

-module(jwk).
-include_lib("public_key/include/OTP-PUB-KEY.hrl").

-export([encode/2, decode/2]).

%%
%%
-type id()         :: binary().
-type public_key() :: #'RSAPublicKey'{} | pem().
-type pem()        :: binary().
-type json()       :: binary().

%%
%% encode Erlang/OTP Key to JWK
-spec encode(id(), public_key()) -> {ok, json()} | {error, _}.

encode(Id, #'RSAPublicKey'{modulus = N, publicExponent = E}) ->
    {ok, jsx:encode(
        #{
            keys => 
            [
                #{
                    kid => Id,
                    kty => <<"RSA">>, 
                    n   => encode_int(N), 
                    e   => encode_int(E)
                }
            ]
        }
    )};

encode(Id, PEM)
 when is_binary(PEM) ->
    [RSAEntry] = public_key:pem_decode(PEM),
    encode(Id, public_key:pem_entry_decode(RSAEntry));

encode(_, _) ->
    {error, not_supported}.

encode_int(X) ->
    base64url:encode(binary:encode_unsigned(X)).

%%
%% decode JWK to Erlang/OTP Key
-spec decode(id(), json()) -> {ok, public_key()} | {error, _}.

decode(Id, Json) ->
    #{<<"keys">> := JWTs} = jsx:decode(Json, [return_maps]),
    decode(
        lists:dropwhile(
            fun(X) -> 
                maps:get(<<"kid">>, X, undefined) /= Id 
            end,
            JWTs
        )
    ).

decode([]) ->
    {error, not_found};

decode([#{<<"kty">> := <<"RSA">>, <<"n">> := N, <<"e">> := E} | _]) ->
    {ok, 
        #'RSAPublicKey'{
            modulus        = decode_int(N), 
            publicExponent = decode_int(E)
        }
    };

decode(_) ->
    {error, not_supported}.

decode_int(X) ->
    binary:decode_unsigned(base64url:decode(X)).


