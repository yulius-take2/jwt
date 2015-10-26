### jwt &mdash; Erlang JWT Library

---

JWT is a simple authorization token [format](http://jwt.io/) based on JSON.

## Usage example

```erlang
%% Create JWT token
> application:ensure_all_started(jwt).
> Key = <<"supas3cri7">>.
> Claims = [
    {user_id, 42},
    {user_name, <<"Bob">>}
  ].
> {ok, Token} = jwt:encode(<<"HS256">>, Claims, Key).
%% or with expiration
> ExpirationSeconds = 86400.
> {ok, Token} = jwt:encode(<<"HS256">>, Claims, ExpirationSeconds, Key).

%% Parse JWT token
> {ok, Claims} = jwt:decode(Token, Key).
```

---

### Contributing

1. Fork it
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create new Pull Request
