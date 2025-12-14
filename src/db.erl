-module(db).
-export([setup/0, create_paste/2, get_paste/1, get_recent_pastes/0, create_user/2, check_user/2]).

setup() ->
    % Create tables
    os:cmd("sqlite3 pastebin.db 'CREATE TABLE IF NOT EXISTS pastes (id TEXT PRIMARY KEY, content TEXT, created_at DATETIME DEFAULT CURRENT_TIMESTAMP, expires_at DATETIME);'"),
    os:cmd("sqlite3 pastebin.db 'CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT);'"),
    spawn(fun() -> cleanup_loop() end),
    ok.

cleanup_loop() ->
    os:cmd("sqlite3 pastebin.db \"DELETE FROM pastes WHERE expires_at < datetime('now', 'localtime');\""),
    timer:sleep(60000),
    cleanup_loop().

%% --- Helpers for Hex Encoding (Fixes UTF-8 issues) ---

bin_to_hex(Bin) when is_binary(Bin) ->
    lists:flatten([io_lib:format("~2.16.0B", [X]) || X <- binary_to_list(Bin)]);
bin_to_hex(List) when is_list(List) ->
    lists:flatten([io_lib:format("~2.16.0B", [X]) || X <- List]).

hex_to_bin(HexStr) ->
    Clean = string:trim(HexStr),
    try
        << <<(list_to_integer([A,B], 16))>> || <<A,B>> <= list_to_binary(Clean) >>
    catch _:_ -> <<>> end.

%% --- Pastes ---

create_paste(Content, DurationSeconds) ->
    ID = base64:encode_to_string(crypto:strong_rand_bytes(8)),

    % FIX: Hex encode content to avoid shell/encoding issues completely
    HexContent = bin_to_hex(Content),

    % Use SQLite x'...' literal syntax cast to TEXT
    Cmd = io_lib:format(
        "sqlite3 pastebin.db \"INSERT INTO pastes (id, content, created_at, expires_at) VALUES ('~s', CAST(x'~s' AS TEXT), datetime('now', 'localtime'), datetime('now', 'localtime', '+~p seconds'));\"",
        [ID, HexContent, DurationSeconds]
    ),
    os:cmd(lists:flatten(Cmd)),
    {ok, ID}.

get_paste(ID) ->
    SanitizedID = re:replace(ID, "[^a-zA-Z0-9=/+]", "", [global, {return, list}]),

    % FIX: Request HEX(content) from SQLite to ensure we get raw bytes safely
    Cmd = io_lib:format(
        "sqlite3 pastebin.db \"SELECT hex(content) FROM pastes WHERE id = '~s' AND expires_at > datetime('now', 'localtime');\"",
        [SanitizedID]
    ),

    Result = os:cmd(lists:flatten(Cmd)),
    case string:trim(Result) of
        "" -> {error, not_found};
        Hex -> {ok, hex_to_bin(Hex)}
    end.

get_recent_pastes() ->
    Cmd = "sqlite3 pastebin.db -json \"SELECT id, created_at FROM pastes WHERE expires_at > datetime('now', 'localtime') ORDER BY created_at DESC LIMIT 10;\"",
    {ok, os:cmd(Cmd)}.

%% --- Users ---

create_user(Username, Password) ->
    % Username validation is strict (alphanumeric), so no injection risk there
    case re:run(Username, "^[a-zA-Z0-9]+$", [{capture, none}]) of
        match ->
            Hash = sha256_hex(Password),
            CheckCmd = io_lib:format("sqlite3 pastebin.db \"SELECT username FROM users WHERE username = '~s';\"", [Username]),
            case os:cmd(lists:flatten(CheckCmd)) of
                [] ->
                    InsertCmd = io_lib:format("sqlite3 pastebin.db \"INSERT INTO users (username, password_hash) VALUES ('~s', '~s');\"", [Username, Hash]),
                    os:cmd(lists:flatten(InsertCmd)),
                    ok;
                _ -> {error, exists}
            end;
        nomatch -> {error, invalid_username}
    end.

check_user(Username, Password) ->
    SanitizedUser = re:replace(Username, "[^a-zA-Z0-9]", "", [global, {return, list}]),
    Cmd = io_lib:format("sqlite3 pastebin.db \"SELECT password_hash FROM users WHERE username = '~s';\"", [SanitizedUser]),
    StoredHash = string:trim(os:cmd(lists:flatten(Cmd))),
    InputHash = sha256_hex(Password),
    if
        StoredHash =:= InputHash, StoredHash =/= [] -> true;
        true -> false
    end.

sha256_hex(Str) ->
    Bin = crypto:hash(sha256, Str),
    lists:flatten([io_lib:format("~2.16.0B", [X]) || X <- binary_to_list(Bin)]).
