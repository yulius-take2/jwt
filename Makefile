.PHONY: all compile test lint doc edown clean

all: compile

compile:
	@./rebar3 compile

test:
	@./rebar3 eunit

lint:
	elvis rock --verbose

doc: edown
	@./rebar3 edoc

edown:
	@./rebar3 as edown edoc

clean:
	@./rebar3 clean
	@rm -rf _build

run:
	@erl -name jwt@127.0.0.1 \
		-pa ./_build/default/lib/*/ebin \
		+P 1000000 +K true +A 160 -sbt ts

