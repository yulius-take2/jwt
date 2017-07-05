-module(jwt_tests).
-include_lib("eunit/include/eunit.hrl").
-compile([export_all]).

-define(SECRET, <<"supas3cri7">>).

jwt_test_() -> {setup,
    fun start/0, fun stop/1,
    [ fun test_encoding/0
    , fun test_encoding_with_exp/0
    , fun test_encoding_map_claimset_with_exp/0
    , fun test_encoding_with_undefined_algorithm/0
    , fun test_encoding_with_all_algorithms/0
    , fun test_decoding_simple/0
    , fun test_decoding_header_error/0
    , fun test_decoding_payload_error/0
    , fun test_decoding_signature_error/0
    , fun test_decoding_very_bad_token/0

    , fun test_encoding_with_none/0
    , fun test_decoding_with_none/0

    , fun test_encoding_with_rs256/0
    , fun test_decoding_with_rs256/0
    , fun test_decoding_with_rs256_invalid_signature/0
    ]}.

start() -> ok.
stop(_) -> ok.

%%
%% Tests
%%

test_encoding() ->
    Claims = [{user_id, 42}, {user_name, <<"John Doe">>}],
    {ok, Token} = jwt:encode(<<"HS256">>, Claims, ?SECRET),

    ExpHeader = <<"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9">>,
    ExpPayload = <<"eyJ1c2VyX2lkIjo0MiwidXNlcl9uYW1lIjoiSm9obiBEb2UifQ">>,
    ExpSignature = <<"cDMB--ajYo0DWsX14wTkWmM385X9OAOPgIPSsJzKZ8E">>,

    ?assertEqual(makeToken(ExpHeader, ExpPayload, ExpSignature), Token).

test_encoding_with_exp() ->
    ExpirationSeconds = 86400,
    Result = jwt:encode(<<"HS256">>, [], ExpirationSeconds, ?SECRET),

    ?assertMatch({ok, _Token}, Result).

test_encoding_map_claimset_with_exp() ->
    ExpirationSeconds = 86400,
    Result = jwt:encode(<<"HS256">>, #{}, ExpirationSeconds, ?SECRET),

    ?assertMatch({ok, _Token}, Result).

test_encoding_with_undefined_algorithm() ->
    Error = jwt:encode(<<"HS128">>, [], ?SECRET),

    ?assertEqual({error, algorithm_not_supported}, Error).

test_encoding_with_all_algorithms() ->
    ?assertMatch({ok, _Token}, jwt:encode(<<"HS256">>, [], ?SECRET)),
    ?assertMatch({ok, _Token}, jwt:encode(<<"HS384">>, [], ?SECRET)),
    ?assertMatch({ok, _Token}, jwt:encode(<<"HS512">>, [], ?SECRET)).

test_decoding_simple() ->
    Header = <<"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9">>,
    Payload = <<"eyJ1c2VyX2lkIjo0MiwidXNlcl9uYW1lIjoiSm9obiBTbm93In0">>,
    Signature = <<"RzveVJs7YQbgVVgtmPRx7lOQOs89pCFxjLIEyzgnFaA">>,

    Claims = jwt:decode(makeToken(Header, Payload, Signature), ?SECRET),

    ?assertMatch({ok, #{ <<"user_id">> := 42
                       , <<"user_name">> := <<"John Snow">>
                       }}, Claims).

test_decoding_header_error() ->
    Header = <<"...">>,
    Payload = <<"eyJ1c2VyX2lkIjo0MiwidXNlcl9uYW1lIjoiSm9obiBTbm93In0">>,
    Signature = <<"RzveVJs7YQbgVVgtmPRx7lOQOs89pCFxjLIEyzgnFaA">>,

    Claims = jwt:decode(makeToken(Header, Payload, Signature), ?SECRET),

    ?assertMatch({error, invalid_token}, Claims).

test_decoding_payload_error() ->
    Header = <<"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9">>,
    Payload = <<"...">>,
    Signature = <<"RzveVJs7YQbgVVgtmPRx7lOQOs89pCFxjLIEyzgnFaA">>,

    Claims = jwt:decode(makeToken(Header, Payload, Signature), ?SECRET),

    ?assertMatch({error, invalid_token}, Claims).

test_decoding_signature_error() ->
    Header = <<"eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9">>,
    Payload = <<"eyJ1c2VyX2lkIjo0MiwidXNlcl9uYW1lIjoiSm9obiBTbm93In0">>,
    Signature = <<"RzveVJs7YQbgVVgtmPRx7lOQOs89pCFxjLIEyzgnFa">>,

    Claims = jwt:decode(makeToken(Header, Payload, Signature), ?SECRET),

    ?assertMatch({error, invalid_signature}, Claims).

test_decoding_very_bad_token() ->
    Claims = jwt:decode(<<"very_bad">>, ?SECRET),

    ?assertMatch({error, invalid_token}, Claims).

%%
%% both encoding / decoding with none MUST not be supported
%% due to change the signature attack
test_encoding_with_none() ->
    Claims = #{sub => 1234567890, name => <<"John Doe">>, admin => true},
    Result = jwt:encode(<<"none">>, Claims, ?SECRET),

    ?assertMatch({error, algorithm_not_supported}, Result).


test_decoding_with_none() ->
    Header = <<"eyJhbGciOiJub25lIiwidHlwIjoiSldUIn0">>,
    Payload = <<"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9">>,
    Signature = <<"2XijNOVI9LXP9nWf-oj2SEWWNlcwmxzlQNGK1WdaWcQ">>,

    Result = jwt:decode(makeToken(Header, Payload, Signature), rsa_public()),

    ?assertMatch({error, invalid_signature}, Result).


%%
%% 
test_encoding_with_rs256() ->
    Claims = #{sub => 1234567890, name => <<"John Doe">>, admin => true},
    {ok, Token} = jwt:encode(<<"RS256">>, Claims, rsa_secret()),

    ExpHeader = <<"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9">>,
    ExpPayload = <<"eyJhZG1pbiI6dHJ1ZSwibmFtZSI6IkpvaG4gRG9lIiwic3ViIjoxMjM0NTY3ODkwfQ">>,
    ExpSignature = <<"W4utVJa53XlPrfyd34NsTY16ONtUp0SG840enCKErSbMw5HPRW-4dO1OOAwSlNZy0L__5kH3733D7ooxEd_wLDRSNRhtq3CiVx6j5vOCW84xLL9U7ytQPubSruirt1L1eVnnxKmzMLM0d2wnog6wTeaNYUDsiLXUt2DRpT6XlWQ">>,

    ?assertEqual(makeToken(ExpHeader, ExpPayload, ExpSignature), Token).

test_decoding_with_rs256() ->
    Header = <<"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9">>,
    Payload = <<"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9">>,
    Signature = <<"EkN-DOsnsuRjRO6BxXemmJDm3HbxrbRzXglbN2S4sOkopdU4IsDxTI8jO19W_A4K8ZPJijNLis4EZsHeY559a4DFOd50_OqgHGuERTqYZyuhtF39yxJPAjUESwxk2J5k_4zM3O-vtd1Ghyo4IbqKKSy6J9mTniYJPenn5-HIirE">>,

    Claims = jwt:decode(makeToken(Header, Payload, Signature), rsa_public()),

    ?assertMatch({ok, #{<<"sub">>   := <<"1234567890">>, 
                        <<"name">>  := <<"John Doe">>, 
                        <<"admin">> := true}}, Claims).

test_decoding_with_rs256_invalid_signature() ->
    Header = <<"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9">>,
    Payload = <<"eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9">>,
    Signature = <<"eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9">>,

    Claims = jwt:decode(makeToken(Header, Payload, Signature), rsa_public()),

    ?assertMatch({error, invalid_signature}, Claims).

%%
%% Helpers
%%

makeToken(Header, Payload, Sign) ->
    <<Header/binary, ".", Payload/binary, ".", Sign/binary>>.

rsa_public() ->
    {ok, PEM} = file:read_file("./test/public.pem"),
    [ RSAEntry ] = public_key:pem_decode(PEM),
    public_key:pem_entry_decode(RSAEntry).


rsa_secret() ->
    {ok, PEM} = file:read_file("./test/secret.pem"),
    [ RSAEntry ] = public_key:pem_decode(PEM),
    public_key:pem_entry_decode(RSAEntry, "").
