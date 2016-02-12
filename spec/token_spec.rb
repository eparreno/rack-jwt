require 'spec_helper'

describe Rack::JWT::Token do

  describe "processing all valid algorithm types" do

    context "can create and restore a no-signature 'none' token" do
      let(:alg)       { 'none' }
      let(:payload)   { { 'foo' => 'bar' } }
      let(:secret)    { nil }
      let(:verify)    { false }
      let(:enc_token) { Rack::JWT::Token.encode(payload, secret, alg) }
      let(:dec_token) { Rack::JWT::Token.decode(enc_token, secret, verify, { :algorithm => alg }) }

      it 'decodes a proper payload' do
        expect(dec_token[0]).to eq(payload)
        expect(dec_token[1]["typ"]).to eq("JWT")
        expect(dec_token[1]["alg"]).to eq(alg)
      end
    end

    context "can create and restore an HMAC 'HS256' token" do
      let(:alg)       { 'HS256' }
      let(:payload)   { { 'foo' => 'bar' } }
      let(:secret)    { "secret" }
      let(:verify)    { true }
      let(:enc_token) { Rack::JWT::Token.encode(payload, secret, alg) }
      let(:dec_token) { Rack::JWT::Token.decode(enc_token, secret, verify, { :algorithm => alg }) }

      it 'decodes a proper payload' do
        expect(dec_token[0]).to eq(payload)
        expect(dec_token[1]["typ"]).to eq("JWT")
        expect(dec_token[1]["alg"]).to eq(alg)
      end
    end

    context "can create and restore an HMAC 'HS384' token" do
      let(:alg)       { 'HS384' }
      let(:payload)   { { 'foo' => 'bar' } }
      let(:secret)    { "secret" }
      let(:verify)    { true }
      let(:enc_token) { Rack::JWT::Token.encode(payload, secret, alg) }
      let(:dec_token) { Rack::JWT::Token.decode(enc_token, secret, verify, { :algorithm => alg }) }

      it 'decodes a proper payload' do
        expect(dec_token[0]).to eq(payload)
        expect(dec_token[1]["typ"]).to eq("JWT")
        expect(dec_token[1]["alg"]).to eq(alg)
      end
    end

    context "can create and restore an HMAC 'HS512' token" do
      let(:alg)       { 'HS512' }
      let(:payload)   { { 'foo' => 'bar' } }
      let(:secret)    { "secret" }
      let(:verify)    { true }
      let(:enc_token) { Rack::JWT::Token.encode(payload, secret, alg) }
      let(:dec_token) { Rack::JWT::Token.decode(enc_token, secret, verify, { :algorithm => alg }) }

      it 'decodes a proper payload' do
        expect(dec_token[0]).to eq(payload)
        expect(dec_token[1]["typ"]).to eq("JWT")
        expect(dec_token[1]["alg"]).to eq(alg)
      end
    end

    context "can create and restore an RSA 'RS256' token" do
      let(:alg)         { 'RS256' }
      let(:payload)     { { 'foo' => 'bar' } }
      let(:rsa_private) { OpenSSL::PKey::RSA.generate(2048) }
      let(:rsa_public)  { rsa_private.public_key }
      let(:verify)      { true }
      let(:enc_token)   { Rack::JWT::Token.encode(payload, rsa_private, alg) }
      let(:dec_token)   { Rack::JWT::Token.decode(enc_token, rsa_public, verify, { :algorithm => alg }) }

      it 'decodes a proper payload' do
        expect(dec_token[0]).to eq(payload)
        expect(dec_token[1]["typ"]).to eq("JWT")
        expect(dec_token[1]["alg"]).to eq(alg)
      end
    end

    context "can create and restore an RSA 'RS384' token" do
      let(:alg)         { 'RS384' }
      let(:payload)     { { 'foo' => 'bar' } }
      let(:rsa_private) { OpenSSL::PKey::RSA.generate(2048) }
      let(:rsa_public)  { rsa_private.public_key }
      let(:verify)      { true }
      let(:enc_token)   { Rack::JWT::Token.encode(payload, rsa_private, alg) }
      let(:dec_token)   { Rack::JWT::Token.decode(enc_token, rsa_public, verify, { :algorithm => alg }) }

      it 'decodes a proper payload' do
        expect(dec_token[0]).to eq(payload)
        expect(dec_token[1]["typ"]).to eq("JWT")
        expect(dec_token[1]["alg"]).to eq(alg)
      end
    end

    context "can create and restore an RSA 'RS512' token" do
      let(:alg)         { 'RS512' }
      let(:payload)     { { 'foo' => 'bar' } }
      let(:rsa_private) { OpenSSL::PKey::RSA.generate(2048) }
      let(:rsa_public)  { rsa_private.public_key }
      let(:verify)      { true }
      let(:enc_token)   { Rack::JWT::Token.encode(payload, rsa_private, alg) }
      let(:dec_token)   { Rack::JWT::Token.decode(enc_token, rsa_public, verify, { :algorithm => alg }) }

      it 'decodes a proper payload' do
        expect(dec_token[0]).to eq(payload)
        expect(dec_token[1]["typ"]).to eq("JWT")
        expect(dec_token[1]["alg"]).to eq(alg)
      end
    end

    context "can create and restore an ECDSA 'ES256' token" do
      let(:alg)      { 'ES256' }
      let(:payload)  { { 'foo' => 'bar' } }
      let(:verify)   { true }

      it 'decodes a proper payload' do
        ecdsa_key = OpenSSL::PKey::EC.new('prime256v1') # NOTE
        ecdsa_key.generate_key
        ecdsa_public = OpenSSL::PKey::EC.new(ecdsa_key)
        ecdsa_public.private_key = nil
        enc_token = Rack::JWT::Token.encode(payload, ecdsa_key, alg)
        dec_token = Rack::JWT::Token.decode(enc_token, ecdsa_public, verify, { :algorithm => alg })

        expect(dec_token[0]).to eq(payload)
        expect(dec_token[1]["typ"]).to eq("JWT")
        expect(dec_token[1]["alg"]).to eq(alg)
      end
    end

    context "can create and restore an ECDSA 'ES384' token" do
      let(:alg)      { 'ES384' }
      let(:payload)  { { 'foo' => 'bar' } }
      let(:verify)   { true }

      it 'decodes a proper payload' do
        ecdsa_key = OpenSSL::PKey::EC.new('secp384r1') # NOTE
        ecdsa_key.generate_key
        ecdsa_public = OpenSSL::PKey::EC.new(ecdsa_key)
        ecdsa_public.private_key = nil
        enc_token = Rack::JWT::Token.encode(payload, ecdsa_key, alg)
        dec_token = Rack::JWT::Token.decode(enc_token, ecdsa_public, verify, { :algorithm => alg })

        expect(dec_token[0]).to eq(payload)
        expect(dec_token[1]["typ"]).to eq("JWT")
        expect(dec_token[1]["alg"]).to eq(alg)
      end
    end

    context "can create and restore an ECDSA 'ES512' token" do
      let(:alg)      { 'ES512' }
      let(:payload)  { { 'foo' => 'bar' } }
      let(:verify)   { true }

      it 'decodes a proper payload' do
        ecdsa_key = OpenSSL::PKey::EC.new('secp521r1')  # NOTE
        ecdsa_key.generate_key
        ecdsa_public = OpenSSL::PKey::EC.new(ecdsa_key)
        ecdsa_public.private_key = nil
        enc_token = Rack::JWT::Token.encode(payload, ecdsa_key, alg)
        dec_token = Rack::JWT::Token.decode(enc_token, ecdsa_public, verify, { :algorithm => alg })

        expect(dec_token[0]).to eq(payload)
        expect(dec_token[1]["typ"]).to eq("JWT")
        expect(dec_token[1]["alg"]).to eq(alg)
      end
    end

  end

end
