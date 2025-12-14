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
        os:cmd(Cmd)
    end, ?CHALLENGE_PORTS),

    io:format("[LB] Spawning Servers (SSL)...~n"),
    lists:foreach(fun(P) ->
        spawn(fun() -> server:start(P, ?CHALLENGE_PORTS) end)
    end, ?SERVER_PORTS),

    {ok, Listen} = gen_tcp:listen(?LB_PORT, [binary, {packet, 0}, {active, false}, {reuseaddr, true}]),
    io:format("[LB] Ready on port ~p (Smart SSL/HTTP Proxy)~n", [?LB_PORT]),
    io:format("[LB] Logs available in: .build/challenger.log~n"),
    loop(Listen, ?SERVER_PORTS).

loop(Listen, Servers) ->
    {ok, ClientSock} = gen_tcp:accept(Listen),
    % Round Robin
    [Target | Rest] = Servers,
    spawn(fun() -> sniff_and_proxy(ClientSock, Target) end),
    loop(Listen, Rest ++ [Target]).

%% --- Protocol Sniffer ---

sniff_and_proxy(ClientSock, TargetPort) ->
    % Read the first packet from the client
    case gen_tcp:recv(ClientSock, 0, 5000) of
        {ok, <<22, _/binary>> = Data} ->
            % Byte 22 (0x16) is the TLS Handshake Content Type.
            % This is an HTTPS connection. Forward to backend.
            case gen_tcp:connect("localhost", TargetPort, [binary, {packet, 0}, {active, false}]) of
                {ok, ServerSock} ->
                    % Forward the initial handshake packet we just read
                    gen_tcp:send(ServerSock, Data),
                    Pid = self(),
                    spawn(fun() -> pipe(ClientSock, ServerSock, Pid) end),
                    pipe(ServerSock, ClientSock, Pid);
                _ ->
                    gen_tcp:close(ClientSock)
            end;

        {ok, Data} ->
            % Not TLS. Likely Plain HTTP (e.g. "GET / ...")
            % We will extract the 'Host' header and redirect to HTTPS.
            redirect_to_https(ClientSock, Data);

        _ ->
            gen_tcp:close(ClientSock)
    end.

%% --- HTTP Redirector Logic ---

redirect_to_https(Sock, Data) ->
    Host = parse_host(Data),
    % Create HTTP 301 Response
    % We keep the port 8080 because that is where we are listening, but change scheme to https
    RedirectURL = iolist_to_binary(["https://", Host, "/"]),
    Response = [
        "HTTP/1.1 301 Moved Permanently\r\n",
        "Location: ", RedirectURL, "\r\n",
        "Connection: close\r\n",
        "Content-Length: 0\r\n\r\n"
    ],
    gen_tcp:send(Sock, Response),
    gen_tcp:close(Sock).

parse_host(Data) ->
    % Simple parser to find "Host: <value>\r\n"
    % Case insensitive search for "host:"
    case binary:match(string:lowercase(Data), <<"host: ">>) of
        {Start, Len} ->
            % Extract everything after "Host: "
            Rest = binary:part(Data, Start + Len, byte_size(Data) - (Start + Len)),
            % Find the end of the line (\r\n)
            case binary:split(Rest, <<"\r">>) of
                [HostValue | _] -> string:trim(HostValue);
                _ -> <<"localhost:8080">> % Fallback
            end;
        nomatch ->
            <<"localhost:8080">> % Fallback
    end.

%% --- Pipe ---

pipe(A, B, _) ->
    case gen_tcp:recv(A, 0, 5000) of
        {ok, Data} when is_binary(Data) ->
            gen_tcp:send(B, Data),
            pipe(A, B, unused);
        _ ->
            gen_tcp:close(B),
            gen_tcp:close(A)
    end.
