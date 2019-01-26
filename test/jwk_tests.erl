-module(jwk_tests).
-include_lib("eunit/include/eunit.hrl").

jwk_test_() ->
    {setup,
        fun start/0, fun stop/1,
        [
          fun test_encoding/0
        , fun test_decoding/0
        , fun test_decoding_parsed_json/0
        ]
    }.

start() -> ok.
stop(_) -> ok.

%%
%% Tests
%%
-define(ID, <<"test">>).

test_encoding() ->
    {ok, JWTs} = jwk:encode(?ID, public()),
    Expected   = json(),
    
    ?assertMatch(Expected,  jsx:decode(JWTs, [return_maps])).


test_decoding() ->
    {ok, Json} = file:read_file("./test/jwks.json"),
    {ok, PKey} = jwk:decode(?ID, Json),
    Expected   = public(),
    ?assertMatch(Expected, PKey).


test_decoding_parsed_json() ->
    {ok, PKey} = jwk:decode(?ID, json()),
    Expected   = public(),
    ?assertMatch(Expected, PKey).



%%
%% Helpers
%%

public() ->
    {'RSAPublicKey',
        26634547600177008912365441464036882611104634136430581696102639463075266436216946316053845642300166320042915031924501272705275043130211783228252369194856949397782880847235143381529207382262647906987655738647387007320361149854766523417293323739185308113373529512728932838100141612048712597178695720651344295450174895369923383396704334331627261565907266749863744707920606364678231639106403854977302183719246256958550651555767664134467706614553219592981545363271425781391262006405169505726523023628770285432062044391310047445749287563161668548354322560223509946990827691654627968182167826397015368836435965354956581554819, 65537}.

json() ->
    {ok, Json} = file:read_file("./test/jwks.json"),
    jsx:decode(Json, [return_maps]).
