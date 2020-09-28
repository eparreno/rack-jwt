# frozen_string_literal: true

require 'spec_helper'

RSpec.describe 'reading the token from a cookie' do
  # behavior of this is changing after jwt v1.5.2 when you can specify a lambda for verify_jti
  # right now its hard-coded to verify against an MD5
  let(:jti_digest) { Digest::MD5.hexdigest([secret, Time.now.to_i].join(':').to_s) }
  let(:secret) { 'secret' } # use 'secret to match hardcoded 'secret' @ http://jwt.io'
  let(:header_token_payload) do
    {
      data: 'header data',
      exp: Time.now.to_i + 4 * 3600,
      nbf: Time.now.to_i - 3600,
      iss: 'https://my.awesome.website/',
      aud: 'audience',
      jti: jti_digest,
      iat: Time.now.to_i,
      sub: 'subject'
    }
  end
  let(:cookie_token_payload) do
    {
      data: 'cookie data',
      exp: Time.now.to_i + 4 * 3600,
      nbf: Time.now.to_i - 3600,
      iss: 'https://my.awesome.website/',
      aud: 'audience',
      jti: jti_digest,
      iat: Time.now.to_i,
      sub: 'subject'
    }
  end
  let(:inner_app) do
    ->(env) { [200, env, [env['jwt.payload'].to_json]] }
  end
  let(:app) do
    Rack::JWT::Auth.new(
      inner_app,
      decode_args
    )
  end
  let(:header_token) { Rack::JWT::Token.encode(header_token_payload, secret, 'HS256') }
  let(:cookie_token) { Rack::JWT::Token.encode(cookie_token_payload, secret, 'HS256') }
  let(:parsed_body) { JSON.parse(last_response.body, symbolize_names: true) }

  before do
    allow(Time).to receive(:now).and_return(Time.new(2014, 0o2, 0o6, 16, 12, 0, '-08:00'))
  end

  after do
    clear_cookies
  end

  context 'when the cookie setting is enabled' do
    let(:decode_args) do
      {
        secret: secret,
        verify: true,
        options: {
          algorithm: 'HS256',
          cookie_name: 'authToken',
          verify_expiration: true,
          verify_not_before: true,
          iss: 'https://my.awesome.website/',
          verify_iss: true,
          verify_iat: true,
          jti: jti_digest,
          verify_jti: true,
          aud: 'audience',
          verify_aud: true,
          sub: 'subject',
          verify_sub: true,
          leeway: 30
        }
      }
    end

    context 'when a valid auth cookie is sent with the request, but no auth header' do
      it 'decodes the cookie and adds the token to the headers' do
        set_cookie("authToken=#{cookie_token}")
        get('/')

        aggregate_failures do
          expect(last_response.status).to eq 200
          expect(parsed_body).to eq(cookie_token_payload)
          expect(last_response.headers['jwt.header']).to eq('typ' => 'JWT', 'alg' => 'HS256')
        end
      end
    end

    context 'when the cookie and Authorization header are both missing' do
      it 'responds with a 401 error' do
        get('/')

        aggregate_failures do
          expect(last_response.status).to eq 401
          expect(parsed_body).to eq(error: 'Missing token cookie and Authorization header')
          expect(last_response.headers['jwt.header']).to be_nil
        end
      end
    end

    context 'when a valid Authorization header, but no cookie is sent with the request' do
      it 'decodes the header token and adds it to the headers' do
        header 'Authorization', "Bearer #{header_token}"
        get('/')

        aggregate_failures do
          expect(last_response.status).to eq 200
          expect(parsed_body).to eq(header_token_payload)
          expect(last_response.headers['jwt.header']).to eq('typ' => 'JWT', 'alg' => 'HS256')
        end
      end
    end

    context 'when a valid Authorization header and auth cookie are both sent with the request' do
      it 'decodes the cookie token and adds it to the headers' do
        header 'Authorization', "Bearer #{header_token}"
        set_cookie("authToken=#{cookie_token}")
        get('/')

        aggregate_failures do
          expect(last_response.status).to eq 200
          expect(parsed_body).to eq(cookie_token_payload)
          expect(last_response.headers['jwt.header']).to eq('typ' => 'JWT', 'alg' => 'HS256')
        end
      end
    end

    context 'when an empty cookie is sent with the request' do
      it 'responds with a 401 error' do
        set_cookie('authToken=')
        get('/')

        aggregate_failures do
          expect(last_response.status).to eq 401
          expect(parsed_body).to eq(error: 'Empty token cookie')
          expect(last_response.headers['jwt.header']).to be_nil
        end
      end
    end
  end

  context 'when the cookie setting is disabled' do
    let(:decode_args) do
      {
        secret: secret,
        verify: true,
        options: {
          algorithm: 'HS256',
          verify_expiration: true,
          verify_not_before: true,
          iss: 'https://my.awesome.website/',
          verify_iss: true,
          verify_iat: true,
          jti: jti_digest,
          verify_jti: true,
          aud: 'audience',
          verify_aud: true,
          sub: 'subject',
          verify_sub: true,
          leeway: 30
        }
      }
    end

    context 'when the cookie and Authorization header are both missing' do
      it 'responds with a 401 error' do
        get('/')

        aggregate_failures do
          expect(last_response.status).to eq 401
          expect(parsed_body).to eq(error: 'Missing Authorization header')
          expect(last_response.headers['jwt.header']).to be_nil
        end
      end
    end

    context 'when a valid Authorization header, but no cookie is sent with the request' do
      it 'decodes the header token and adds it to the headers' do
        header 'Authorization', "Bearer #{header_token}"
        get('/')

        aggregate_failures do
          expect(last_response.status).to eq 200
          expect(parsed_body).to eq(header_token_payload)
          expect(last_response.headers['jwt.header']).to eq('typ' => 'JWT', 'alg' => 'HS256')
        end
      end
    end
  end
end
