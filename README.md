![Experimental](https://img.shields.io/badge/experimental-red)
[![Apache
2.0](https://img.shields.io/badge/license-Apache%202.0-blue)](https://www.apache.org/licenses/LICENSE-2.0)
[![Discord](https://img.shields.io/discord/1296917489615110174?label=discord&logo=discord&logoColor=#5865F2)](https://discord.gg/9HFMDMt95z)
# factor

### The twelve-factor cli

## Rationale

While updating twelve-factor to clarify the contract between the application
and the platform, it became clear that introducing additional platform features
like workload identity would require a way to run those features locally. This
repository holds an experimental api for replicating the features of a
twelve-factor platform locally.

## Goals

This cli will evolve and change over time. The factor cli aims to:

* Provide an easy way to run twelve-factor apps locally
* Act as a "polyfill" mechanism to fill in gaps in features provided by the
  platform. This allows twelve-factor apps running on platforms that do not
  yet support all of the twelve-factor features to work.
* Be a place to experiment with new twelve-factor concepts to clarify
  recommendations for the manifesto.


## Current Features

The current iteration is focused primarily on workload identity generation and
validation. In the future we plan to experiment more with extensions to port
binding, constellations of twelve-factor apps, connections between apps and
backing services, and consistent local builds.

The cli supports:

* exposing app remotely via ngrok
* `.env` file loading and change detection
* workload identity managed with a local oidc provider, auth0, or k8s
* incoming identity validation via proxy

## Getting Started

To begin, copy the example.factor to your home directory:

    cp exmple.factor ~/.factor

Add a secret to your local identity provider:

    echo secret = "\"$(openssl rand -base64 32)\"" >> ~/.factor

Create an app:

    factor create --app local

Add an identity to your app:

    echo DEFAULT_AUDIENCE=default >> .env

Run an echo server:

    factor run ./echo.sh --incoming-identity example-clients.json

In another terminal window, load the file and make a request passing in the
token:

   TOKEN=$(cat DEFAULT.token)
   curl -v -H "Authorization: Bearer $TOKEN" http://localhost:5000

You should see `X-Factor-Client-Id: DEFAULT` in the response from the server.
Note that in this case we are generating an oidc token an validating it
locally.

## Governance and Code of Conduct

This project follows the main [twelve-factor
governance](https://github.com/twelve-factor/twelve-factor/blob/next/GOVERNANCE.md)
including the code of conduct defined there. Because it is experimental, it
does not use the same change management or major release guidelines. Please
treat it as alpha-quality software.

## Command Reference

`factor create`

This creates the config for a local app and stores it in `.factor-app` or the
specified config file via `--config`.

`factor run`

Loads an `.env` file if available, starts the given subcommand and proxies
requests to the subcommand. Validates incoming bearer tokens using the same
mechanism as `proxy` and syncs ids using the same mechanism as `id`. Audiences
can also be specified by setting `CLIENT_ID_AUDIENCE=<audience>` in environment
variables.

Additionally, if an ngrok key is specified in the app config, it will start an
ngrok tunnel and forward requests to the application. The ngrok url is
available to the application in the env var `NGROK_URL`.

`factor id`

Starts a background process to write and update one workload identity file for
each audience specified. The file will be stored in `./`. This can be updated
by specifying `--path` on the command line or changing the path value in
.factor-app.

`factor proxy`

Listens on `--port` and proxies requests to `--child_port`. Validates incoming
bearer tokens based on the flag `--incoming-identity` or `INCOMING_IDENTITY` in
the environment. Identity data looks like:

```
{
  "<client_id_a>": {
    "iss": "<issuer_regex>",
    "sub": "<subject_regex>",
    "aud": "<audience_regex>"
  },
  "<client_id_b>": {
    ...
  },
  ...
}
```

If a matching token is supplied, then the header `X-Factor-Client-Id` will be
set to the value of the matching client id. To reject, requests that don't
match, use the flag `--reject-unknown`
