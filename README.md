# Crystal Lang Digest Auth

[![Build Status](https://travis-ci.com/spider-gazelle/digest-auth.svg?branch=master)](https://travis-ci.com/github/spider-gazelle/digest-auth)

Communicate with servers that implement digest auth.

## Installation

1. Add the dependency to your `shard.yml`:

   ```yaml
   dependencies:
     digest-auth:
       github: spider-gazelle/digest-auth
   ```

2. Run `shards install`


## Usage

```crystal
require "http/client"
require "digest-auth"

# New client per-connection, this keeps track of nonce count
digest_auth = DigestAuth.new

uri = URI.parse "http://foo.com/posts?id=30&limit=5"

# if you expect digest auth use a head request to get the challenge header
client = HTTP::Client.new uri
response = client.head uri.full_path
response.status_code # => 401

challenge = response.headers["WWW-Authenticate"]
uri.user = "username"
uri.password = "password"

# Generate the auth header, need to indicate if talking to IIS
auth_header = digest_auth.auth_header(uri, challenge, "get", iis: false)

# Make the request
response = client.get uri.full_path, HTTP::Headers{ "Authorization" => auth_header }
response.status_code # => 200

# Make a second request while the connection is still open
uri.path = "/posts/30"
auth_header = digest_auth.auth_header(uri, challenge, "post", iis: false)
response = client.post uri.full_path, HTTP::Headers{ "Authorization" => auth_header }, body: "hello!"
response.status_code # => 201
```
