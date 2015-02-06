require 'spec_helper'

describe Rack::JWT::Auth do
  include Rack::Test::Methods

  let(:issuer) { Rack::JWT::Token }
  let(:secret) { 'foo' }
  let(:body)   {{ 'foo' => 'bar' }}

  let(:app) do
    main_app = lambda { |env| [200, env, [body.to_json]] }
    Rack::JWT::Auth.new(main_app, { secret: secret })
  end

  before do
    get('/', {}, headers)
  end

  context 'when no secret provided' do
    let(:headers) { {} }

    it 'raises an exception' do
      expect{ Rack::JWT::Auth.new(main_app, {}) }.to raise_error
    end
  end

  context 'when no authorization header provided' do
    let(:headers) { {} }

    subject { JSON.parse(last_response.body) }

    it 'returns 401 status code' do
      expect(last_response.status).to eq(401)
    end

    it 'returns an error message' do
      expect(subject['error']).to eq('Missing Authorization header')
    end
  end

  context 'when authorzation header does not contain the schema' do
    let(:token) { issuer.encode({ iss: 1 }, secret) }
    let(:headers) {{ 'HTTP_AUTHORIZATION' => token }}

    subject { JSON.parse(last_response.body) }

    it 'returns 401 status code' do
      expect(last_response.status).to eq(401)
    end

    it 'returns an error message' do
      expect(subject['error']).to eq('Invalid Authorization header format')
    end
  end

  context 'when authorization header contains an invalid schema' do
    let(:token) { issuer.encode({ iss: 1 }, secret) }
    let(:headers) {{ 'HTTP_AUTHORIZATION' => "WrongScheme #{token}" }}

    subject { JSON.parse(last_response.body) }

    it 'returns 401 status code' do
      expect(last_response.status).to eq(401)
    end

    it 'returns an error message' do
      expect(subject['error']).to eq('Invalid Authorization header format')
    end
  end

  context 'when token signature is invalid' do
    let(:token) { issuer.encode({ iss: 1 }, 'invalid secret') }
    let(:headers) {{ 'HTTP_AUTHORIZATION' => "Bearer #{token}" }}

    subject { JSON.parse(last_response.body) }

    it 'returns 401 status code' do
      expect(last_response.status).to eq(401)
    end

    it 'returns an error message' do
      expect(subject['error']).to eq('Invalid JWT token')
    end
  end

  context 'when token is valid' do
    let(:token) { issuer.encode({ iss: 1 }, secret) }
    let(:headers) {{ 'HTTP_AUTHORIZATION' => "Bearer #{token}" }}

    subject { JSON.parse(last_response.body) }

    it 'returns 200 status code' do
      expect(last_response.status).to eq(200)
    end

    it 'process the request' do
      expect(subject).to eq(body)
    end

    it 'adds the token payload to the request' do
      payload = last_response.header['jwt.payload']
      expect(payload['iss']).to eq(1)
    end

    it 'adds the token header to the request' do
      header = last_response.header['jwt.header']
      expect(header['alg']).to eq('HS256')
      expect(header['typ']).to eq('JWT')
    end
  end
end
