require 'spec_helper'

describe Rack::JWT::Auth do
  let(:issuer)  { Rack::JWT::Token }
  let(:secret)  { 'secret' } # use 'secret to match hardcoded 'secret' @ http://jwt.io'
  let(:verify)  { true }
  let(:payload) { { foo: 'bar' } }

  let(:inner_app) do
    ->(env) { [200, env, [payload.to_json]] }
  end

  let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret) }

  describe 'receiving valid Authorization headers' do
    describe 'with unsigned (none) valid header and token' do
      let(:app) { Rack::JWT::Auth.new(inner_app, secret: nil, verify: false, options: { algorithm: 'none' }) }

      it 'returns a 200' do
        header 'Authorization', "Bearer #{issuer.encode(payload, nil, 'none')}"
        get('/')
        expect(last_response.status).to eq 200
        expect(last_response.headers['jwt.header']).to eq({"typ"=>"JWT", "alg"=>"none"})
        expect(last_response.headers['jwt.payload']).to eq("foo" => "bar")
      end
    end

    describe 'with valid HMAC HS256 token (default)' do
      it 'returns a 200' do
        header 'Authorization', "Bearer #{issuer.encode(payload, secret, 'HS256')}"
        get('/')
        expect(last_response.status).to eq 200
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body).to eq(payload)
        expect(last_response.headers['jwt.header']).to eq({"typ"=>"JWT", "alg"=>"HS256"})
        expect(last_response.headers['jwt.payload']).to eq("foo" => "bar")
      end
    end

    describe 'with valid HMAC HS256 token (explicit)' do
      let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret, verify: verify, options: { algorithm: 'HS256' }) }

      it 'returns a 200' do
        header 'Authorization', "Bearer #{issuer.encode(payload, secret, 'HS256')}"
        get('/')
        expect(last_response.status).to eq 200
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body).to eq(payload)
        expect(last_response.headers['jwt.header']).to eq({"typ" => "JWT", "alg" => "HS256"})
        expect(last_response.headers['jwt.payload']).to eq({"foo" => "bar"})
      end
    end

    describe 'with valid HMAC HS256 token from http://jwt.io' do
      let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret, verify: verify, options: { algorithm: 'HS256' }) }

      it 'returns a 200' do
        # generate with HMAC secret of 'secret'
        header 'Authorization', "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiYWRtaW4iOnRydWV9.TJVA95OrM7E2cBab30RMHrHDcEfxjoYZgeFONFh7HgQ"
        get('/')
        expect(last_response.status).to eq 200
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body).to eq(payload)
        expect(last_response.headers['jwt.header']).to eq({"typ"=>"JWT", "alg"=>"HS256"})
        expect(last_response.headers['jwt.payload']).to eq({"sub"=>"1234567890", "name"=>"John Doe", "admin"=>true})
      end
    end

    describe 'with valid HMAC HS384 token' do
      let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret, verify: verify, options: { algorithm: 'HS384' }) }

      it 'returns a 200' do
        header 'Authorization', "Bearer #{issuer.encode(payload, secret, 'HS384')}"
        get('/')
        expect(last_response.status).to eq 200
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body).to eq(payload)
        expect(last_response.headers['jwt.header']).to eq({"typ"=>"JWT", "alg"=>"HS384"})
        expect(last_response.headers['jwt.payload']).to eq("foo" => "bar")
      end
    end

    describe 'with valid HMAC HS512 token' do
      let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret, verify: verify, options: { algorithm: 'HS512' }) }

      it 'returns a 200' do
        header 'Authorization', "Bearer #{issuer.encode(payload, secret, 'HS512')}"
        get('/')
        expect(last_response.status).to eq 200
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body).to eq(payload)
        expect(last_response.headers['jwt.header']).to eq({"typ"=>"JWT", "alg"=>"HS512"})
        expect(last_response.headers['jwt.payload']).to eq("foo" => "bar")
      end
    end

    describe 'with valid RSA RS256 key token' do
      let(:rsa_private) { OpenSSL::PKey::RSA.generate(2048) }
      let(:rsa_public)  { rsa_private.public_key }
      let(:app) { Rack::JWT::Auth.new(inner_app, secret: rsa_public, verify: verify, options: { algorithm: 'RS256' }) }

      it 'returns a 200' do
        header 'Authorization', "Bearer #{issuer.encode(payload, rsa_private, 'RS256')}"
        get('/')
        expect(last_response.status).to eq 200
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body).to eq(payload)
        expect(last_response.headers['jwt.header']).to eq({"typ"=>"JWT", "alg"=>"RS256"})
        expect(last_response.headers['jwt.payload']).to eq("foo" => "bar")
      end
    end

    describe 'with valid RSA RS384 key token' do
      let(:rsa_private) { OpenSSL::PKey::RSA.generate(2048) }
      let(:rsa_public)  { rsa_private.public_key }
      let(:app) { Rack::JWT::Auth.new(inner_app, secret: rsa_public, verify: verify, options: { algorithm: 'RS384' }) }

      it 'returns a 200' do
        header 'Authorization', "Bearer #{issuer.encode(payload, rsa_private, 'RS384')}"
        get('/')
        expect(last_response.status).to eq 200
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body).to eq(payload)
        expect(last_response.headers['jwt.header']).to eq({"typ"=>"JWT", "alg"=>"RS384"})
        expect(last_response.headers['jwt.payload']).to eq("foo" => "bar")
      end
    end

    describe 'with valid RSA RS512 key token' do
      let(:rsa_private) { OpenSSL::PKey::RSA.generate(2048) }
      let(:rsa_public)  { rsa_private.public_key }
      let(:app) { Rack::JWT::Auth.new(inner_app, secret: rsa_public, verify: verify, options: { algorithm: 'RS512' }) }

      it 'returns a 200' do
        header 'Authorization', "Bearer #{issuer.encode(payload, rsa_private, 'RS512')}"
        get('/')
        expect(last_response.status).to eq 200
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body).to eq(payload)
        expect(last_response.headers['jwt.header']).to eq({"typ"=>"JWT", "alg"=>"RS512"})
        expect(last_response.headers['jwt.payload']).to eq("foo" => "bar")
      end
    end

    describe 'with valid JWKS request' do
      let(:rsa_private) { OpenSSL::PKey::RSA.generate(2048) }
      let(:rsa_public)  { rsa_private.public_key }
      let(:jwk) { JWT::JWK.new(rsa_private) }
      let(:app) { Rack::JWT::Auth.new(inner_app, secret: nil, verify: verify, options: { algorithm: 'RS512', jwks: { keys: [jwk.export] }}) }

      it 'returns a 200' do
        header 'Authorization', "Bearer #{issuer.encode(payload, rsa_private, 'RS512', kid: jwk.kid)}"
        get('/')
        expect(last_response.status).to eq 200
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body).to eq(payload)
        expect(last_response.headers['jwt.header']).to eq({"typ"=>"JWT", "alg"=>"RS512", "kid" => jwk.kid})
        expect(last_response.headers['jwt.payload']).to eq("foo" => "bar")
      end
    end

    describe 'with valid EC ES256 key token' do
      let(:ecdsa) { OpenSSL::PKey::EC.generate('prime256v1') }
      let(:ecdsa_pub) { OpenSSL::PKey::EC.new(ecdsa) }
      let(:app) { Rack::JWT::Auth.new(inner_app, secret: ecdsa_pub, verify: verify, options: { algorithm: 'ES256' }) }

      it 'returns a 200' do
        header 'Authorization', "Bearer #{issuer.encode(payload, ecdsa, 'ES256')}"
        get('/')
        expect(last_response.status).to eq 200
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body).to eq(payload)
        expect(last_response.headers['jwt.header']).to eq({"typ"=>"JWT", "alg"=>"ES256"})
        expect(last_response.headers['jwt.payload']).to eq("foo" => "bar")
      end
    end

    describe 'with valid EC ES384 key token' do
      let(:ecdsa) { OpenSSL::PKey::EC.generate('secp384r1') }
      let(:ecdsa_pub) { OpenSSL::PKey::EC.new(ecdsa) }
      let(:app) { Rack::JWT::Auth.new(inner_app, secret: ecdsa_pub, verify: verify, options: { algorithm: 'ES384' }) }

      it 'returns a 200' do
        header 'Authorization', "Bearer #{issuer.encode(payload, ecdsa, 'ES384')}"
        get('/')
        expect(last_response.status).to eq 200
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body).to eq(payload)
        expect(last_response.headers['jwt.header']).to eq({"typ"=>"JWT", "alg"=>"ES384"})
        expect(last_response.headers['jwt.payload']).to eq("foo" => "bar")
      end
    end

    describe 'with valid EC ES512 key token' do
      let(:ecdsa) { OpenSSL::PKey::EC.generate('secp521r1') }
      let(:ecdsa_pub) { OpenSSL::PKey::EC.new(ecdsa) }
      let(:app) { Rack::JWT::Auth.new(inner_app, secret: ecdsa_pub, verify: verify, options: { algorithm: 'ES512' }) }

      it 'returns a 200' do
        header 'Authorization', "Bearer #{issuer.encode(payload, ecdsa, 'ES512')}"
        get('/')
        expect(last_response.status).to eq 200
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body).to eq(payload)
        expect(last_response.headers['jwt.header']).to eq({"typ"=>"JWT", "alg"=>"ES512"})
        expect(last_response.headers['jwt.payload']).to eq("foo" => "bar")
      end
    end

    describe 'with valid ED25519 key token' do
      private_key = RbNaCl::Signatures::Ed25519::SigningKey.generate
      public_key  = private_key.verify_key

      let(:app) { Rack::JWT::Auth.new(inner_app, secret: public_key, verify: verify, options: { algorithm: 'ED25519' }) }

      it 'returns a 200' do
        header 'Authorization', "Bearer #{issuer.encode(payload, private_key, 'ED25519')}"
        get('/')
        expect(last_response.status).to eq 200
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body).to eq(payload)
        expect(last_response.headers['jwt.header']).to eq({"typ"=>"JWT", "alg"=>"ED25519"})
        expect(last_response.headers['jwt.payload']).to eq("foo" => "bar")
      end
    end
  end

  describe 'receiving invalid Authorization headers' do

    # skip all verification!!!
    describe 'succeeds when verify: false even though secret in token is bad' do
      let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret, verify: false) }

      it 'returns a 200' do
        header 'Authorization', "Bearer #{issuer.encode(payload, 'badsecret', 'HS256')}"
        get('/')
        expect(last_response.status).to eq 200
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body).to eq(payload)
        expect(last_response.headers['jwt.header']).to eq({"typ"=>"JWT", "alg"=>"HS256"})
        expect(last_response.headers['jwt.payload']).to eq("foo" => "bar")
      end
    end

    describe 'with missing header' do
      it 'returns a 401' do
        get('/')
        expect(last_response.status).to eq 401
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body).to eq(error: 'Missing Authorization header')
        expect(last_response.headers['jwt.header']).to eq(nil)
        expect(last_response.headers['jwt.payload']).to eq(nil)
      end
    end

    describe 'with header, schema, but empty token' do
      it 'returns a 401' do
        header 'Authorization', 'Bearer '
        get('/')
        expect(last_response.status).to eq 401
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body).to eq(error: 'Invalid Authorization header format')
        expect(last_response.headers['jwt.header']).to eq(nil)
        expect(last_response.headers['jwt.payload']).to eq(nil)
      end
    end

    describe 'with header and token but missing schema' do
      it 'returns a 401' do
        header 'Authorization', issuer.encode(payload, secret, 'HS256')
        get('/')
        expect(last_response.status).to eq 401
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body).to eq(error: 'Invalid Authorization header format')
        expect(last_response.headers['jwt.header']).to eq(nil)
        expect(last_response.headers['jwt.payload']).to eq(nil)
      end
    end

    describe 'with header and valid token but incorrect schema' do
      it 'returns a 401' do
        header 'Authorization', "Badstuff #{issuer.encode(payload, secret, 'HS256')}"
        get('/')
        expect(last_response.status).to eq 401
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body).to eq(error: 'Invalid Authorization header format')
        expect(last_response.headers['jwt.header']).to eq(nil)
        expect(last_response.headers['jwt.payload']).to eq(nil)
      end
    end

    describe 'with header and malformed double period token' do
      it 'returns a 401' do
        header 'Authorization', 'Bearer abc123..abc123.abc123'
        get('/')
        expect(last_response.status).to eq 401
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body).to eq(error: 'Invalid Authorization header format')
        expect(last_response.headers['jwt.header']).to eq(nil)
        expect(last_response.headers['jwt.payload']).to eq(nil)
      end
    end

    describe 'with header and malformed trailing period token' do
      it 'returns a 401' do
        header 'Authorization', 'Bearer abc123.abc123.abc123.'
        get('/')
        expect(last_response.status).to eq 401
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body).to eq(error: 'Invalid Authorization header format')
        expect(last_response.headers['jwt.header']).to eq(nil)
        expect(last_response.headers['jwt.payload']).to eq(nil)
      end
    end

    describe 'with header and malformed leading period token' do
      it 'returns a 401' do
        header 'Authorization', 'Bearer .abc123.abc123.abc123'
        get('/')
        expect(last_response.status).to eq 401
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body).to eq(error: 'Invalid Authorization header format')
        expect(last_response.headers['jwt.header']).to eq(nil)
        expect(last_response.headers['jwt.payload']).to eq(nil)
      end
    end

    describe 'with header and malformed bad character token' do
      it 'returns a 401' do
        header 'Authorization', 'Bearer abc!123.abc123.abc123'
        get('/')
        expect(last_response.status).to eq 401
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body).to eq(error: 'Invalid Authorization header format')
        expect(last_response.headers['jwt.header']).to eq(nil)
        expect(last_response.headers['jwt.payload']).to eq(nil)
      end
    end

    describe 'with header and valid token but a different secret in the token than on server' do
      it 'returns a 401' do
        header 'Authorization', "Bearer #{issuer.encode(payload, 'badsecret', 'HS256')}"
        get('/')
        expect(last_response.status).to eq 401
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body).to eq(error: 'Invalid JWT token : Signature Verification Error')
        expect(last_response.headers['jwt.header']).to eq(nil)
        expect(last_response.headers['jwt.payload']).to eq(nil)
      end
    end
  end
end
