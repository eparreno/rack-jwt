require 'spec_helper'

describe Rack::JWT::Auth do
  let(:issuer)  { Rack::JWT::Token }
  let(:secret)  { 'secret' } # use 'secret to match hardcoded 'secret' @ http://jwt.io'
  let(:verify)  { true }
  let(:payload) { { foo: 'bar' } }

  let(:inner_app) do
    ->(env) { [200, env, [payload.to_json]] }
  end

  let(:app) do
    Rack::JWT::Auth.new(inner_app, secret: secret)
  end

  describe 'initialization of' do
    describe 'secret' do
      describe 'with only secret: arg provided' do
        let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret) }
        it 'succeeds' do
          expect(app.secret).to eq(secret)
        end
      end

      describe 'with no secret: arg provided' do
        it 'raises ArgumentError' do
          expect { Rack::JWT::Auth.new(inner_app, {}) }.to raise_error(ArgumentError)
        end
      end

      describe 'with secret: arg of invalid type' do
        it 'raises ArgumentError' do
          expect { Rack::JWT::Auth.new(inner_app, secret: []) }.to raise_error(ArgumentError)
        end
      end

      describe 'with nil secret: arg provided' do
        it 'raises ArgumentError' do
          expect { Rack::JWT::Auth.new(inner_app, secret: nil) }.to raise_error(ArgumentError)
        end
      end

      describe 'with empty secret: arg provided' do
        it 'raises ArgumentError' do
          expect { Rack::JWT::Auth.new(inner_app, secret: '') }.to raise_error(ArgumentError)
        end
      end

      describe 'with spaces secret: arg provided' do
        it 'raises ArgumentError' do
          expect { Rack::JWT::Auth.new(inner_app, secret: '     ') }.to raise_error(ArgumentError)
        end
      end
    end

    describe 'verify' do
      describe 'with true arg' do
        let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret, verify: true) }

        it 'succeeds' do
          header 'Authorization', "Bearer #{issuer.encode(payload, secret, 'HS256')}"
          get('/')
          expect(last_response.status).to eq 200
        end
      end

      describe 'with false arg' do
        let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret, verify: false) }

        it 'succeeds' do
          header 'Authorization', "Bearer #{issuer.encode(payload, secret, 'HS256')}"
          get('/')
          expect(last_response.status).to eq 200
        end
      end

      describe 'with a bad arg' do
        it 'raises ArgumentError' do
          expect { Rack::JWT::Auth.new(inner_app, secret: secret, verify: "badStringArg") }.to raise_error(ArgumentError)
        end
      end
    end

    describe 'options' do
      describe 'when algorithm "none" and secret is nil and verify is false' do
        let(:app) { Rack::JWT::Auth.new(inner_app, secret: nil, verify: false, options: { algorithm: 'none' }) }

        it 'succeeds' do
          header 'Authorization', "Bearer #{issuer.encode(payload, secret, 'HS256')}"
          get('/')
          expect(last_response.status).to eq 200
        end
      end

      describe 'when algorithm "none" and secret not nil but verify is false' do
        it 'raises an exception' do
          args = { secret: secret, verify: false, options: { algorithm: 'none' } }
          expect { Rack::JWT::Auth.new(inner_app, args) }.to raise_error(ArgumentError)
        end
      end

      describe 'when algorithm "none" and secret is nil but verify not false' do
        it 'raises an exception' do
          args = { secret: nil, verify: true, options: { algorithm: 'none' } }
          expect { Rack::JWT::Auth.new(inner_app, args) }.to raise_error(ArgumentError)
        end
      end

      describe 'when invalid algorithm provided' do
        it 'raises an exception' do
          args = { secret: secret, verify: true, options: { algorithm: 'badalg' } }
          expect { Rack::JWT::Auth.new(inner_app, args) }.to raise_error(ArgumentError)
        end
      end
    end

    # see also exclusion_spec.rb
    describe 'exclude' do
      describe 'when a type other than Array provided' do
        it 'raises an exception' do
          args = { secret: secret, exclude: {} }
          expect { Rack::JWT::Auth.new(inner_app, args) }.to raise_error(ArgumentError)
        end
      end

      describe 'when Array contains non-String and non-Regexp elements' do
        it 'raises an exception' do
          args = { secret: secret, exclude: ['/foo', nil, '/bar', /\/foo/] }
          expect { Rack::JWT::Auth.new(inner_app, args) }.to raise_error(ArgumentError)
        end
      end

      describe 'when Array contains empty String elements' do
        it 'raises an exception' do
          args = { secret: secret, exclude: ['/foo', '', '/bar'] }
          expect { Rack::JWT::Auth.new(inner_app, args) }.to raise_error(ArgumentError)
        end
      end

      describe 'when Array contains elements that do not start with a /' do
        it 'raises an exception' do
          args = { secret: secret, exclude: ['/foo', 'bar', '/baz'] }
          expect { Rack::JWT::Auth.new(inner_app, args) }.to raise_error(ArgumentError)
        end
      end
    end
  end
end
