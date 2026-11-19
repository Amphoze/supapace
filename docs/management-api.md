# Management API contract

The upstream `supabase` CLI manages hosted projects through an HTTP API (the Management API).
`supabase projects list` needs it; other commands were not checked. supapace does not serve
this API yet. This page records what the pinned CLI sends, observed against a stand-in, so that
an implementation is written to it and checked against the same CLI.

## The pinned CLI

| | |
|---|---|
| Version | 3.0.0 |
| Archive (amd64) | `supabase_3.0.0_linux_amd64.tar.gz`, SHA-256 `eeb61edcd59a4735fcb5e58596574f25d03d420efca779f43ddb307e1cc5c754` |
| Archive (arm64) | `supabase_3.0.0_linux_arm64.tar.gz`, SHA-256 `243474fb5b491a0df04682fc1941cc5519559a1178ae01c225c633eda2e8acb8` |
| Source | the project's GitHub release page for `v3.0.0` |

The pins are in `test/harness/experiments/pins-cli.env`. `test/harness/experiments/e45.sh`
fetches the archive, checks its SHA-256, and repeats every observation below, one PASS or FAIL
line each. The binary is a GNU/Linux executable (it needs the GNU C library). Another version is
a new pin: run `e45.sh` and the contract test against it before relying on it.

## Pointing the CLI at another API host

The CLI takes its API base URL from its *profile*. A profile is either a built-in name or the
path of a YAML file:

```yaml
name: example
api_url: https://api.example.test
dashboard_url: https://example.test
project_host: example.test
```

The CLI refuses, before sending anything, a profile file with a key it does not know
(`unknown keys: …`), an `api_url` that is not an `http` or `https` URL (`api_url must be an
http(s) URL`), or a missing member (`project_host is required`). It chooses the profile in this
order, the first one set winning:

1. the `--profile FILE` flag;
2. the `SUPABASE_PROFILE` environment variable;
3. the file `~/.supabase/profile`, which holds a profile file's path or a built-in profile's
   name;
4. the built-in profile `supabase` (`https://api.supabase.com`).

Each of the first three was seen to send the request to a host of our choosing; `--profile` was
seen to win over `SUPABASE_PROFILE`, and `SUPABASE_PROFILE` over `~/.supabase/profile`.
Two other ways do **not** work for API calls:

- `SUPABASE_API_URL` is ignored by `projects list`: with only that variable set, the CLI still
  called `https://api.supabase.com/v1/projects`; set beside a profile, the profile's host was
  called.
- The built-in profile `supabase-local` reaches `http://localhost:8080` only — a fixed address,
  not a way to choose a host.

A path in `api_url` was seen to prefix the call: `api_url` `http://HOST/prefix` gave
`GET /prefix/v1/projects`.

## The contract

- **URL shape:** `{api_url}/v1/…`; listing projects is `GET {api_url}/v1/projects`, without a
  query string.
- **Authorization:** every call carries `Authorization: Bearer TOKEN`, TOKEN being
  `SUPABASE_ACCESS_TOKEN`. Tokens of the forms `sbp_`, `sbp_oauth_` and `sbp_v0_` followed by 40
  lowercase hexadecimal digits were sent. **The CLI refuses, before sending anything,** a token
  of another form: upper-case hexadecimal digits, 39 or 41 digits, `sbp_v1_`, a trailing line
  end, or no `sbp_` prefix at all. A server's tokens must have one of the accepted forms.
- **Other request headers:** `Accept`, `Accept-Encoding`, `Connection` and `User-Agent`. No
  other header is sent with `projects list`.
- **Success:** `200` with a JSON array of project objects. With `--output-format json` the CLI
  prints `{"projects":[…],"message":""}`, the array holding the objects it received, each with
  a `linked` field added.
- **Error document:** a `401` or a `404` ends the command with exit status 1; the CLI quotes the
  response body in its error. The error document of this API is a JSON object with a `message`
  string:

  ```json
  {"message":"Unauthorized"}
  ```

  With `--output-format json` the CLI prints
  `{"_tag":"Error","error":{"code":"ProjectsListUnexpectedStatusError","message":"Unexpected error retrieving projects: {\"message\":\"Unauthorized\"}"}}`.
- **One request per call:** neither a `200`, a `401` nor a `404` was retried.

The observations as a table, which the contract test reads:

| Call | Answer of the API | Method | Path | Authorization | CLI exit status |
|---|---|---|---|---|---|
| `supabase projects list` | 200, a JSON array | `GET` | `/v1/projects` | `Bearer` | 0 |
| `supabase projects list` | 401, the error document | `GET` | `/v1/projects` | `Bearer` | 1 |

A token of a refused form ends `projects list` with exit status 1 and no request.

## Checking it

`sp-probe mgmt --listen ADDR --log FILE --token FILE` is a stand-in that serves
`GET /v1/projects` for one bearer token and logs every request line, every header name and the
`Authorization` scheme. Header values are never logged. The request target and header names are
logged as received: a client must not carry a secret in either. `TestMgmtContract_ProjectsList`
in `cmd/sp-probe` runs the pinned CLI, named by `SUPAPACE_CLI`, against it with a profile file
and a made-up token, in an empty home directory, and compares what arrives and the exit status
with the table above. Without `SUPAPACE_CLI` the test is skipped and says so. The CLI is
third-party code: run it on a disposable machine or inside a container without a network, as
`e45.sh` does.
