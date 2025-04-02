![Experimental](https://img.shields.io/badge/experimental-red)
[![Apache
2.0](https://img.shields.io/badge/license-Apache%202.0-blue)](https://www.apache.org/licenses/LICENSE-2.0)
[![Discord](https://img.shields.io/discord/1296917489615110174?label=discord&logo=discord&logoColor=#5865F2)](https://discord.gg/9HFMDMt95z)

# Factor

### The Twelve-Factor CLI

Factor makes it easy to run twelve-factor apps locally and in CI.

`factor` aims to provide a local version of the facilities normally provided by a
twelve factor **platform**, such as routing, and explore proposals for new
twelve factor recommendations, such as workload identity.

> [!NOTE]
>
> It also serves as a place to experiment with new twelve-factor recommendations,
> because the ability to provide a local version of a proposed recommendation is
> a great way to verify that the recommendation is not overly coupled to the
> implementation details of specific platforms.

## Rationale

While updating twelve-factor to clarify the contract between the application
and the platform, it became clear that introducing additional platform features
like workload identity would require a way to run those features locally. This
repository holds an experimental api for replicating the features of a
twelve-factor platform locally.

## Goals

This cli will evolve and change over time. The `factor` cli aims to:

- Provide an easy way to run twelve-factor apps locally.
- Provide a way to run twelve factor apps in CI. Ideally, `factor` could use the
  app's `project.toml` configuration to run the CI suite in an environment as
  close as possible to the production environment.
- Act as a "polyfill" mechanism to fill in gaps in features provided by the
  platform. This allows twelve-factor apps running on platforms that do not
  yet support all of the twelve-factor features to work.
- Be a place to experiment with new twelve-factor concepts to clarify
  recommendations for the manifesto.

> Factor intends to explore whether [devcontainers] can work with Cloud Native
> Buildpacks to help create a local dev environment that is a close match to the
> production environment without configuration.

[devcontainers]: https://containers.dev/

### Non-Goals

Factor does not intend to be a general-purpose "Serverless" framework or a
general-purpose abstraction over multiple platforms.

Instead, it remains focused on providing the facilities expected by a twelve
factor platform outside of the platform: for local development, testing and CI.

## Current Features

The current iteration is focused primarily on workload identity generation and
validation. In the future we plan to experiment more with extensions to port
binding, constellations of twelve-factor apps, connections between apps and
backing services, and consistent local builds.

The CLI supports:

- exposing app remotely via ngrok
- `.env` file loading and change detection
- workload identity managed with a local oidc provider, auth0, or k8s
- incoming identity validation via proxy

## Getting Started

To begin, copy the example.factor to your home directory:

```shell
cp example.factor ~/.factor
```

Add a secret to your local identity provider:

```shell
$ echo secret = "\"$(openssl rand -base64 32)\"" >> ~/.factor
```

Create an app:

```shell
$ factor create --app local
```

Add an identity to your app:

```shell
$ echo DEFAULT_AUDIENCE=default >> .env
```

Run an echo server:

```shell
$ factor run ./echo.sh --incoming-identity example-clients.json
```

In another terminal window, load the file and make a request passing in the
token:

```shell
$ TOKEN=$(cat DEFAULT.token); \
  curl -v -H "Authorization: Bearer $TOKEN" http://localhost:5000
```

You should see `X-Client-Id: DEFAULT` in the response from the server.
Note that in this case we are generating an oidc token and validating it
locally.

## Architecture and Configuration

Factor CLI acts as a platform that provides services to your application in the same way a cloud platform would. This platform is configured through environment variables and provides services through environment variables and headers.

### Client-Side Identity

On the client side, Factor acts as an identity provider that generates tokens for your application to use when calling other services:

**Configuration (what your application provides to Factor):**

- `*_AUDIENCE` environment variables - Define the audiences for which Factor should generate tokens
  - Example: `DEFAULT_AUDIENCE=api.example.com` will generate a token for the audience "api.example.com"

**Services (what Factor provides to your application):**

- `*_CREDS` environment variables - Contain credentials that your application can use to authenticate to other services
  - Example: `DEFAULT_CREDS='{"type":"oidc","data":{"token":"file:///path/to/DEFAULT.token"}}'`
- Token files - Written to disk and referenced by the `*_CREDS` variables
  - These files are automatically updated by Factor (typically every 15 minutes)
  - Applications should monitor and reload these files when they change to maintain valid credentials

### Server-Side Identity

On the server side, Factor acts as an identity-aware proxy that validates incoming tokens and passes identity information to your application:

**Configuration (what your application provides to Factor):**

- `*_CLIENT_CREDS` environment variables - Define the client identities that are allowed to access your application
  - Example: `SERVICE_A_CLIENT_CREDS='{"type":"oidc","data":{"iss":"https://auth\\.example\\.com","sub":"service-.*","aud":"api"}}'`
- `REJECT_UNKNOWN` environment variable - When set to "true", rejects requests from unidentified clients
  - When not set or "false", requests without valid tokens will pass through without the `X-Client-Id` header

**Services (what Factor provides to your application):**

- `X-Client-Id` header - Contains the client ID of the authenticated caller, validated from their token
  - Example: When a request comes in with a valid token, your application receives `X-Client-Id: SERVICE_A`

This separation of concerns allows your application to focus on its business logic while Factor handles the complexities of identity management, token validation, and proxy configuration.

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
variables. Token files will be created in the current working directory.

The application will receive credentials through environment variables using the `*_CREDS` suffix format:

```json
{
  "type": "oidc",
  "data": {
    "token": "file:///path/to/token/file"
  }
}
```

For example:

```shell
# The environment variable name before _CREDS becomes the credential name
export SERVICE_CREDS='{"type":"oidc","data":{"token":"file:///tmp/service.token"}}'
```

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
the environment. Identity data can be provided in two ways:

1. As a JSON/TOML file specified by `--incoming-identity`:

```json
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

2. Through environment variables using the `*_CLIENT_CREDS` format:

```json
{
  "type": "oidc",
  "client_id": "optional_override",
  "data": {
    "iss": "<issuer_regex>",
    "sub": "<subject_regex>",
    "aud": "<audience_regex>"
  }
}
```

For example:

```shell
# The client_id field is optional - if omitted, the environment variable name without _CLIENT_CREDS is used
export SERVICE_A_CLIENT_CREDS='{"type":"oidc","data":{"iss":"https://auth\\.example\\.com","sub":"service-.*","aud":"api"}}'
```

If a matching token is supplied, then the header `X-Client-Id` will be
set to the value of the matching client id. To reject requests that don't
match, use the flag `--reject-unknown`

`factor info`

Prints out info for the current application. If factor is already running it
will dynamically print out the current data, otherwise loads the identity
provider to determine the values.

The output will be something like:

```
name=local
url=http://localhost:5000
iss=http://localhost:5000
sub=local
```
