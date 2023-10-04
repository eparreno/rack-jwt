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

  describe 'when handling exlusions' do
    describe 'passes through matching exact path' do
      let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret, exclude: ['/static']) }

      it 'returns a 200' do
        get('/static')
        expect(last_response.status).to eq 200
      end
    end

    describe 'passes through matching regexp' do
      let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret, exclude: [/stati+/]) }

      it 'returns a 200' do
        get('/static')
        expect(last_response.status).to eq 200
      end
    end

    describe 'passes through matching exact path with trailing slash' do
      let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret, exclude: ['/static']) }

      it 'returns a 200' do
        get('/static/')
        expect(last_response.status).to eq 200
      end
    end

    describe 'passes through matching exact path with sub-path' do
      let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret, exclude: ['/static']) }

      it 'returns a 200' do
        get('/static/foo/bar')
        expect(last_response.status).to eq 200
      end
    end

    describe 'passes through matching path with multiple exclusions' do
      let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret, exclude: %w(/docs /books /static)) }

      it 'returns a 200' do
        get('/static/foo/bar')
        expect(last_response.status).to eq 200
      end
    end

    describe 'fails when no matching path and no token' do
      let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret, exclude: %w(/docs /books /static)) }

      it 'returns a 200' do
        get('/somewhere')
        expect(last_response.status).to eq 401
      end
    end
  end
end
