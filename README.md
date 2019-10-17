# Rack::JWT

[![Gem Version](https://badge.fury.io/rb/rack-jwt.svg)](http://badge.fury.io/rb/rack-jwt)
[![Build Status](https://travis-ci.org/eparreno/rack-jwt.svg)](https://travis-ci.org/eparreno/rack-jwt)
[![Code Climate](https://codeclimate.com/github/eparreno/rack-jwt/badges/gpa.svg)](https://codeclimate.com/github/eparreno/rack-jwt)

## About

This gem provides JSON Web Token (JWT) based authentication.

## Requirements

- Ruby 2.3.8 or greater

## Installation

Add this line to your application's `Gemfile`:

```ruby
gem 'rack-jwt'
```

And then execute:

```
$ bundle install
```

Or install it directly with:

```
$ gem install rack-jwt
```

## Usage

`Rack::JWT::Auth` accepts several configuration options. All options are passed in a single Ruby Hash:

* `secret` : required : `String` || `OpenSSL::PKey::RSA` || `OpenSSL::PKey::EC` : A cryptographically secure String (for HMAC algorithms) or a public key object of an appropriate type for public key algorithms. Set to `nil` if you are using the `'none'` algorithm.

* `verify` : optional : Boolean : Determines whether JWT will verify tokens keys for mismatch key types when decoded. Default is `true`. Set to `false` if you are using the `'none'` algorithm.

* `options` : optional : Hash : A hash of options that are passed through to JWT to configure supported claims and algorithms. See the ruby-jwt docs for [more information of the algorithms and their requirements](https://github.com/jwt/ruby-jwt#algorithms-and-usage) as well as [more information on the supported claims](https://github.com/progrium/ruby-jwt#support-for-reserved-claim-names). These options are passed through without change to the underlying `ruby-jwt` gem. By default only expiration (exp) and Not Before (nbf) claims are verified. Pass in an algorithm choice like `{ algorithm: 'HS256' }`.

* `exclude` : optional : Array : An Array of path strings representing paths that should not be checked for the presence of a valid JWT token. Excludes sub-paths as of specified paths as well (e.g. `%w(/docs)` excludes `/docs/some/thing.html` also). Each path should start with a `/`. If a path matches the current request path this entire middleware is skipped and no authentication or verification of tokens takes place.

* `on_error` : optional : Callable : An object which responds to `call` method with single `error` parameter. `error` parameter is one of `Rack::JWT::Auth::ERRORS_TO_RESCUE`. `on_error` callable object will be called if one of `Rack::JWT::Auth::ERRORS_TO_RESCUE` raised. For default handler check `Rack::JWT::Auth#default_on_error`.

## Example Server-Side Config

Where `my_args` is a `Hash` containing valid keys. See `spec/example_spec.rb`
for a more complete example of the valid arguments for creating and verifying
tokens.

### Sinatra

```ruby
use Rack::JWT::Auth, my_args
```

### Cuba

```ruby
Cuba.use Rack::JWT::Auth, my_args
```

### Rails

```ruby
Rails.application.config.middleware.use Rack::JWT::Auth, my_args
```

## Generating tokens
You can generate JSON Web Tokens for your users using the
`Rack::JWT::Token#encode` method which takes `payload`,
`secret`, and `algorithm` params.

The secret will be either a cryptographically strong random string, or the
secret key component of a public/private keypair of an accepted type depending on
the algorithm you choose. You can see examples of using the various key types at
the [ruby-jwt gem repo](https://github.com/jwt/ruby-jwt/blob/master/README.md)

The `algorithm` is an optional String and can be one of the following (default HMAC 'HS256'):

```ruby
%w(none HS256 HS384 HS512 RS256 RS384 RS512 ED25519 ES256 ES384 ES512)

HS256 is the default
```

Note that `ED25519` support depends on the `rbnacl` which is _not_ already included by the
`rack-jwt` gem. If you wish to use the `ED25519` algorith, you must also manually require
`rbnacl` gem in addition to `rack-jwt`.

Here is a sample payload with illustrative data. You don't have to use all,
or even most, of these.

```ruby
secret = 'your_secret_token_or_key'

my_payload = {
  data: 'data',
  exp: Time.now.to_i + 4 * 3600,
  nbf: Time.now.to_i - 3600,
  iss: 'https://my.awesome.website/',
  aud: 'audience',
  jti: Digest::MD5.hexdigest([hmac_secret, iat].join(':').to_s),
  iat: Time.now.to_i,
  sub: 'subject'
}

alg = 'HS256'

Rack::JWT::Token.encode(my_payload, secret, alg)
```

## Contributing

1. Fork it ( https://github.com/eparreno/rack-jwt/fork )
2. Create your feature branch (`git checkout -b my-new-feature`)
3. Commit your changes (`git commit -am 'Add some feature'`)
4. Push to the branch (`git push origin my-new-feature`)
5. Create a new Pull Request
