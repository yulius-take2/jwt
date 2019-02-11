-module(jwk_tests).
-include_lib("eunit/include/eunit.hrl").

-define(ID, <<"test">>).

encoding_test_() ->
    {ok, JWTs} = jwk:encode(?ID, public()),
    {ok, JWTs2} = jwk:encode(?ID, public_binary()),
    {error, Error} = jwk:encode(?ID, garbage),
    Expected = json(),
    [?_assertMatch(Expected, jsx:decode(JWTs, [return_maps])),
    ?_assertMatch(Expected, jsx:decode(JWTs2, [return_maps])),
    ?_assertEqual(not_supported, Error)].


decoding_test() ->
    {ok, Json} = file:read_file("./test/jwks.json"),
    {ok, PKey} = jwk:decode(?ID, Json),
    Expected   = public(),
    ?assertMatch(Expected, PKey).


decoding_parsed_json_test() ->
    {ok, PKey} = jwk:decode(?ID, json()),
    Expected   = public(),
    ?assertMatch(Expected, PKey).



%%
%% Helpers
%%

public() ->
    {'RSAPublicKey',
        26634547600177008912365441464036882611104634136430581696102639463075266436216946316053845642300166320042915031924501272705275043130211783228252369194856949397782880847235143381529207382262647906987655738647387007320361149854766523417293323739185308113373529512728932838100141612048712597178695720651344295450174895369923383396704334331627261565907266749863744707920606364678231639106403854977302183719246256958550651555767664134467706614553219592981545363271425781391262006405169505726523023628770285432062044391310047445749287563161668548354322560223509946990827691654627968182167826397015368836435965354956581554819, 65537}.

public_binary() ->
    <<
        "-----BEGIN RSA PUBLIC KEY-----\n",
        "MIIBCgKCAQEA0vx7agoebGcQSuuPiLJXZptN9nndrQmbXEps2aiAFbWhM78LhWx4\n",
        "cbbfAAtVT86zwu1RK7aPFFxuhDR1L6tSoc/BJECPebWKRXjBZCiFV4n3oknjhMst\n",
        "n64tZ/2W+5JsGY4Hc5n9yBXArwl93lqt7/RN5w6Cf0h4QyQ5v+65YGjQR0/FDW2Q\n",
        "vzqY368QQMicAtaSqzs8KJZgnYb9c7d0zgdAZHzu6qMQvRL5hajrn1n91CbOpbIS\n",
        "D08qNLyrdkt+bFTWhAI4vMQFh6WeZu0fM4lFd2NcRwr3XPksINHaQ+G/xBniIqbw\n",
        "0Ls1jF44+csFCur+kEgU8awapJzKnqDKgwIDAQAB\n",
        "-----END RSA PUBLIC KEY-----\n"
    >>.

json() ->
    {ok, Json} = file:read_file("./test/jwks.json"),
    jsx:decode(Json, [return_maps]).
