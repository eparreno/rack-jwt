require 'spec_helper'

describe Rack::JWT::Auth do
  let(:issuer)  { Rack::JWT::Token }
  let(:secret)  { 'secret' } # use 'secret to match hardcoded 'secret' @ http://jwt.io'
  let(:verify)  { true }
  let(:payload) { { foo: 'bar' } }

  let(:inner_app) do
    ->(env) { [200, env, [payload.to_json]] }
  end

  let(:app) { Rack::JWT::Auth.new(inner_app, secret: secret, **app_args) }

  describe 'when handling exlusions' do
    describe 'passes through matching exact path' do
      let(:app_args) { { exclude: ['/static'] } }

      it 'returns a 200' do
        get('/static')
        expect(last_response.status).to eq 200
      end
    end

    describe 'passes through matching exact path with trailing slash' do
      let(:app_args) { { exclude: ['/static'] } }

      it 'returns a 200' do
        get('/static/')
        expect(last_response.status).to eq 200
      end
    end

    describe 'passes through matching exact path with sub-path' do
      let(:app_args) { { exclude: ['/static'] } }

      it 'returns a 200' do
        get('/static/foo/bar')
        expect(last_response.status).to eq 200
      end
    end

    describe 'passes through matching path with multiple exclusions' do
      let(:app_args) { { exclude: %w[/docs /books /static] } }

      it 'returns a 200' do
        get('/static/foo/bar')
        expect(last_response.status).to eq 200
      end
    end

    describe 'checks for both HTTP method and path' do
      context 'when using "only" specifier' do
        let(:app_args) do
          {
            exclude: {
              '/first' => { only: %i[get post] },
              '/second' => { only: [:delete] }
            }
          }
        end

        it 'returns a 200 for methods that match' do
          get('/first')
          expect(last_response.status).to eq 200

          post('/first')
          expect(last_response.status).to eq 200

          delete('/second')
          expect(last_response.status).to eq 200
        end

        it 'returns a 401 for methods that do not match' do
          delete('/first')
          expect(last_response.status).to eq 401

          get('/second')
          expect(last_response.status).to eq 401
        end
      end

      context 'when using shorthand single http verb symbol' do
        let(:app_args) { { exclude: { '/first' => :get } } } 

        it 'returns a 200 for methods that match' do
          get('/first')
          expect(last_response.status).to eq 200
        end

        it 'returns a 401 for methods that do not match' do
          delete('/first')
          expect(last_response.status).to eq 401
        end
      end

      context 'when using shorthand single http verb string' do
        let(:app_args) { { exclude: { '/first' => 'get' } } } 

        it 'returns a 200 for methods that match' do
          get('/first')
          expect(last_response.status).to eq 200
        end

        it 'returns a 401 for methods that do not match' do
          delete('/first')
          expect(last_response.status).to eq 401
        end
      end

      context 'when using a single http verb symbol instad of an array' do
        let(:app_args) { { exclude: { '/first' => {:only => :get } } } }

        it 'returns a 200 for methods that match' do
          get('/first')
          expect(last_response.status).to eq 200
        end

        it 'returns a 401 for methods that do not match' do
          delete('/first')
          expect(last_response.status).to eq 401
        end
      end

      context 'when using a single http verb string instad of an array' do
        let(:app_args) { { exclude: { '/first' => {:only => 'get' } } } }

        it 'returns a 200 for methods that match' do
          get('/first')
          expect(last_response.status).to eq 200
        end

        it 'returns a 401 for methods that do not match' do
          delete('/first')
          expect(last_response.status).to eq 401
        end
      end

      context 'when using "except" specifier' do
        let(:app_args) do
          {
            exclude: {
              '/first' => { except: %i[delete patch] },
              '/second' => { except: [:get] }
            }
          }
        end

        it 'returns a 200 for methods that do not match' do
          get('/first')
          expect(last_response.status).to eq 200

          post('/first')
          expect(last_response.status).to eq 200
        end

        it 'asd' do
          post('/second')
          expect(last_response.status).to eq 200
        end

        it 'returns a 401 for methods that match' do
          delete('/first')
          expect(last_response.status).to eq 401

          patch('/first')
          expect(last_response.status).to eq 401

          get('/second')
          expect(last_response.status).to eq 401
        end
      end

      context 'when using both "only" and "except" specifiers' do
        let(:app_args) { { exclude: { '/static' => { only: %i[get post], except: %i[post patch] } } } }

        it 'returns a 200 if both "only" and "except" match' do
          get('/static')
          expect(last_response.status).to eq 200
        end

        it 'returns a 401 if either only and except does not match' do
          post('/static')
          expect(last_response.status).to eq 401

          patch('/static')
          expect(last_response.status).to eq 401

          delete('/static')
          expect(last_response.status).to eq 401
        end
      end
    end

    describe 'fails when no matching path and no token' do
      let(:app_args) { { exclude: %w[/docs /books /static] } }

      it 'returns a 401' do
        get('/somewhere')
        expect(last_response.status).to eq 401
      end
    end
  end

  describe 'when handling exclusions via "optional"' do
    describe 'passes through matching exact path' do
      let(:app_args) { { optional: ['/static'] } }

      it 'returns a 200 if header is missing' do
        get('/static')
        expect(last_response.status).to eq 200
      end

      it 'returns a 401 if the header is bad' do
        header 'Authorization', "Bearer I'm not that bad of a header. Let me in please."
        get('/static')
        expect(last_response.status).to eq 401
      end

      it 'returns a 200 if the header is good' do
        header 'Authorization', "Bearer #{issuer.encode(payload, secret, 'HS256')}"
        get('/static')
        expect(last_response.status).to eq 200
      end
    end

    describe 'checks for both HTTP method and path' do
      let(:app_args) { { optional: { '/static' => { only: [:get] } } } }

      it 'returns a 200 when method is matches' do
        get('/static')
        expect(last_response.status).to eq 200
      end

      it 'returns a 401 when method does not match' do
        post('/static')
        expect(last_response.status).to eq 401
      end
    end

    describe 'fails when no matching path and no token' do
      let(:app_args) { { optional: %w[/docs /books /static] } }

      it 'returns a 401' do
        get('/somewhere')
        expect(last_response.status).to eq 401
      end
    end
  end
end
