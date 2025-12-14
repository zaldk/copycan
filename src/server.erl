-module(server).
-export([start/2]).

-define(SECRET, <<"SuperSecretKey">>).

start(Port, ChallengerPorts) ->
    io:format("[Server] Listening on ~p~n", [Port]),
    {ok, ListenSocket} = gen_tcp:listen(Port, [binary, {packet, 0}, {active, false}, {reuseaddr, true}]),
    accept_loop(ListenSocket, ChallengerPorts).

accept_loop(Socket, ChallengerPorts) ->
    {ok, Conn} = gen_tcp:accept(Socket),
    Pid = spawn(fun() -> handle(Conn, ChallengerPorts) end),
    gen_tcp:controlling_process(Conn, Pid),
    accept_loop(Socket, ChallengerPorts).

handle(Socket, ChallengerPorts) ->
    case gen_tcp:recv(Socket, 0, 5000) of
        {ok, Data} when is_binary(Data) ->
            case parse_request(Data) of
                {Method, Path, Headers, Body} ->
                    Response = route(Method, Path, Headers, Body, ChallengerPorts),
                    gen_tcp:send(Socket, Response);
                error ->
                    gen_tcp:send(Socket, response(400, <<"Bad Request">>))
            end;
        _ -> ok
    end,
    gen_tcp:close(Socket).

%% --- Routes ---

route(<<"POST">>, <<"/api/register">>, _H, Body, _CP) ->
    try json:decode(Body) of
        #{<<"username">> := User, <<"password">> := Pass} ->
            case db:create_user(binary_to_list(User), binary_to_list(Pass)) of
                ok -> response(201, <<"User created">>);
                {error, exists} -> response(409, <<"Username taken">>);
                {error, invalid_username} -> response(400, <<"Invalid username">>)
            end;
        _ -> response(400, <<"Invalid JSON">>)
    catch _:_ -> response(400, <<"JSON Error">>) end;

route(<<"POST">>, <<"/login">>, _H, Body, _CP) ->
    try json:decode(Body) of
        #{<<"username">> := User, <<"password">> := Pass} ->
            case db:check_user(binary_to_list(User), binary_to_list(Pass)) of
                true ->
                    Token = generate_jwt(User),
                    Json = iolist_to_binary(io_lib:format("{\"token\": \"~s\", \"username\": \"~s\"}", [Token, User])),
                    response(200, [{"Content-Type", "application/json"}], Json);
                false ->
                    response(401, <<"Invalid credentials">>)
            end;
        _ -> response(400, <<"Invalid JSON">>)
    catch _:_ -> response(400, <<"JSON Error">>) end;

route(<<"GET">>, <<"/">>, _H, _B, _CP) ->
    {ok, Html} = file:read_file("index.html"),
    response(200, [{"Content-Type", "text/html; charset=utf-8"}], Html);

route(<<"GET">>, <<"/api/pastes">>, _H, _B, _CP) ->
    {ok, Json} = db:get_recent_pastes(),
    response(200, [{"Content-Type", "application/json"}], list_to_binary(Json));

route(<<"GET">>, <<"/api/pastes/", ID/binary>>, _H, _B, _CP) ->
    case db:get_paste(binary_to_list(ID)) of
        {ok, Content} ->
            % Content is now a UTF-8 binary
            response(200, [{"Content-Type", "text/plain; charset=utf-8"}], Content);
        {error, not_found} ->
            response(404, <<"Not Found or Expired">>)
    end;

route(<<"POST">>, <<"/api/pastes">>, Headers, Body, ChallengerPorts) ->
    case validate_jwt(Headers) of
        false -> response(401, <<"Unauthorized">>);
        true ->
            try json:decode(Body) of
                Map when is_map(Map) ->
                    process_paste(Map, Body, ChallengerPorts);
                _ -> response(400, <<"Invalid JSON">>)
            catch _:_ -> response(400, <<"JSON Error">>) end
    end;

route(_, _, _, _, _) -> response(404, <<"Not Found">>).

%% --- Logic ---

process_paste(Map, RawBody, ChallengerPorts) ->
    Content = maps:get(<<"content">>, Map, undefined),
    Prefix = maps:get(<<"prefix">>, Map, undefined),
    Expiration = try
        case maps:get(<<"expiration">>, Map, 3600) of
            Exp when is_integer(Exp), Exp > 0 -> Exp;
            _ -> 3600
        end
    catch _:_ -> 3600 end,

    if
        Content =/= undefined, Prefix =/= undefined ->
            case verify_challenge(RawBody, ChallengerPorts) of
                true ->
                    % FIX: Pass Content (binary) directly, db:create_paste now expects it
                    {ok, ID} = db:create_paste(Content, Expiration),
                    Reply = iolist_to_binary(io_lib:format("{\"id\": \"~s\"}", [ID])),
                    response(201, [{"Content-Type", "application/json"}], Reply);
                false ->
                    response(403, <<"PoW Failed">>)
            end;
        true ->
            response(400, <<"Missing content or prefix">>)
    end.

verify_challenge(Body, Ports) ->
    Port = lists:nth(rand:uniform(length(Ports)), Ports),
    case gen_tcp:connect("localhost", Port, [binary, {active, false}, {packet, 0}]) of
        {ok, Sock} ->
            Req = [
                "POST /verify HTTP/1.1\r\n",
                "Content-Length: ", integer_to_list(byte_size(Body)), "\r\n",
                "\r\n",
                Body
            ],
            gen_tcp:send(Sock, Req),
            case gen_tcp:recv(Sock, 0, 2000) of
                {ok, Resp} when is_binary(Resp) ->
                    gen_tcp:close(Sock),
                    case binary:match(Resp, <<"\"valid\": true">>) of
                        nomatch -> false;
                        _ -> true
                    end;
                _ -> false
            end;
        _ -> false
    end.

generate_jwt(User) ->
    Header = base64url(<<"{\"alg\":\"HS256\",\"typ\":\"JWT\"}">>),
    Payload = base64url(iolist_to_binary(io_lib:format("{\"sub\":\"~s\"}", [User]))),
    Sig = sign(Header, Payload),
    <<Header/binary, ".", Payload/binary, ".", Sig/binary>>.

validate_jwt(Headers) ->
    case lists:keyfind(<<"Authorization">>, 1, Headers) of
        false -> false;
        {_, Val} ->
            case binary:split(Val, <<" ">>) of
                [<<"Bearer">>, Token] ->
                    case binary:split(Token, <<".">>, [global]) of
                        [H, P, S] -> S == sign(H, P);
                        _ -> false
                    end;
                _ -> false
            end
    end.

sign(H, P) ->
    Data = <<H/binary, ".", P/binary>>,
    base64url(crypto:mac(hmac, sha256, ?SECRET, Data)).

base64url(Data) ->
    B64 = base64:encode(Data),
    B1 = binary:replace(B64, <<"+">>, <<"-">>, [global]),
    B2 = binary:replace(B1, <<"/">>, <<"_">>, [global]),
    binary:replace(B2, <<"=">>, <<>>, [global]).

parse_request(Data) ->
    case binary:split(Data, <<"\r\n\r\n">>) of
        [Head, Body] ->
            [ReqLine | HLines] = binary:split(Head, <<"\r\n">>, [global]),
            [Method, Path, _] = binary:split(ReqLine, <<" ">>, [global]),
            Headers = [ split_header(H) || H <- HLines, H =/= <<>> ],
            {Method, Path, Headers, Body};
        _ -> error
    end.

split_header(Line) ->
    [K, V] = binary:split(Line, <<": ">>),
    {K, V}.

response(Code, Headers, Body) ->
    [io_lib:format("HTTP/1.1 ~p OK\r\nContent-Length: ~p\r\n", [Code, byte_size(Body)]),
     [[K, ": ", V, "\r\n"] || {K, V} <- Headers],
     "\r\n", Body].

response(Code, Body) -> response(Code, [], Body).
