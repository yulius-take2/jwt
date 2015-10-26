.PHONY: all compile test clean

all: compile

compile:
	@./rebar3 compile

test:
	@./rebar3 eunit

clean:
	@./rebar clean
	@rm -rf _build
