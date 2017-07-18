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

  describe 'handles the exception' do
    before(:each) do
      header 'Authorization', "Bearer #{issuer.encode(payload, secret, 'HS256')}"
      get('/')
    end

    let(:app) { Rack::JWT::Auth.new(inner_app, secret: 'secret') }

    describe '::JWT::VerificationError' do
      let(:inner_app) { ->(_env) { raise ::JWT::VerificationError } }

      it 'returns a 401 and the correct error msg' do
        expect(last_response.status).to eq 401
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body).to eq(error: 'Invalid JWT token : Signature Verification Error', status: 401)
      end
    end

    describe '::JWT::ExpiredSignature' do
      let(:inner_app) { ->(_env) { raise ::JWT::ExpiredSignature } }

      it 'returns a 401 and the correct error msg' do
        expect(last_response.status).to eq 401
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body).to eq(error: 'Invalid JWT token : Expired Signature (exp)', status: 401)
      end
    end

    describe '::JWT::IncorrectAlgorithm' do
      let(:inner_app) { ->(_env) { raise ::JWT::IncorrectAlgorithm } }

      it 'returns a 401 and the correct error msg' do
        expect(last_response.status).to eq 401
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body).to eq(error: 'Invalid JWT token : Incorrect Key Algorithm', status: 401)
      end
    end

    describe '::JWT::ImmatureSignature' do
      let(:inner_app) { ->(_env) { raise ::JWT::ImmatureSignature } }

      it 'returns a 401 and the correct error msg' do
        expect(last_response.status).to eq 401
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body).to eq(error: 'Invalid JWT token : Immature Signature (nbf)', status: 401)
      end
    end

    describe '::JWT::InvalidIssuerError' do
      let(:inner_app) { ->(_env) { raise ::JWT::InvalidIssuerError } }

      it 'returns a 401 and the correct error msg' do
        expect(last_response.status).to eq 401
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body).to eq(error: 'Invalid JWT token : Invalid Issuer (iss)', status: 401)
      end
    end

    describe '::JWT::InvalidIatError' do
      let(:inner_app) { ->(_env) { raise ::JWT::InvalidIatError } }

      it 'returns a 401 and the correct error msg' do
        expect(last_response.status).to eq 401
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body).to eq(error: 'Invalid JWT token : Invalid Issued At (iat)', status: 401)
      end
    end

    describe '::JWT::InvalidAudError' do
      let(:inner_app) { ->(_env) { raise ::JWT::InvalidAudError } }

      it 'returns a 401 and the correct error msg' do
        expect(last_response.status).to eq 401
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body).to eq(error: 'Invalid JWT token : Invalid Audience (aud)', status: 401)
      end
    end

    describe '::JWT::InvalidSubError' do
      let(:inner_app) { ->(_env) { raise ::JWT::InvalidSubError } }

      it 'returns a 401 and the correct error msg' do
        expect(last_response.status).to eq 401
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body).to eq(error: 'Invalid JWT token : Invalid Subject (sub)', status: 401)
      end
    end

    describe '::JWT::InvalidJtiError' do
      let(:inner_app) { ->(_env) { raise ::JWT::InvalidJtiError } }

      it 'returns a 401 and the correct error msg' do
        expect(last_response.status).to eq 401
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body).to eq(error: 'Invalid JWT token : Invalid JWT ID (jti)', status: 401)
      end
    end

    describe '::JWT::DecodeError' do
      let(:inner_app) { ->(_env) { raise ::JWT::DecodeError } }

      it 'returns a 401 and the correct error msg' do
        expect(last_response.status).to eq 401
        body = JSON.parse(last_response.body, symbolize_names: true)
        expect(body).to eq(error: 'Invalid JWT token : Decode Error', status: 401)
      end
    end
  end
end
