-module(load_balancer).
-export([start/0]).

-define(LB_PORT, 8080).
-define(SERVER_PORTS, [8081, 8082, 8083]).
-define(CHALLENGE_PORTS, [9001, 9002, 9003]).

start() ->
    io:format("[LB] Setup DB & Cleanup...~n"),
    db:setup(),

    io:format("[LB] Spawning Challengers...~n"),
    lists:foreach(fun(P) ->
        Cmd = "./challenger " ++ integer_to_list(P) ++ " > /dev/null 2>&1 &",
        io:format("Spawned ~p: ~p\n", [Cmd, os:cmd(Cmd)])
    end, ?CHALLENGE_PORTS),

    io:format("[LB] Spawning Servers...~n"),
    lists:foreach(fun(P) ->
        spawn(fun() -> server:start(P, ?CHALLENGE_PORTS) end)
    end, ?SERVER_PORTS),

    {ok, Listen} = gen_tcp:listen(?LB_PORT, [binary, {packet, 0}, {active, false}, {reuseaddr, true}]),
    io:format("[LB] Ready on port ~p~n", [?LB_PORT]),
    loop(Listen, ?SERVER_PORTS).

loop(Listen, Servers) ->
    {ok, ClientSock} = gen_tcp:accept(Listen),
    [Target | Rest] = Servers,
    spawn(fun() -> proxy_start(ClientSock, Target) end),
    loop(Listen, Rest ++ [Target]).

proxy_start(Client, Port) ->
    case gen_tcp:connect("localhost", Port, [binary, {packet, 0}, {active, false}]) of
        {ok, Server} ->
            Pid = self(),
            spawn(fun() -> pipe(Client, Server, Pid) end),
            pipe(Server, Client, Pid);
        _ -> gen_tcp:close(Client)
    end.

pipe(A, B, _) ->
    case gen_tcp:recv(A, 0, 5000) of
        {ok, Data} when is_binary(Data) ->
            gen_tcp:send(B, Data),
            pipe(A, B, unused);
        _ ->
            gen_tcp:close(B),
            gen_tcp:close(A)
    end.
