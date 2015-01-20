{-# LANGUAGE OverloadedStrings, QuasiQuotes #-}
{-# OPTIONS_GHC -fno-warn-missing-signatures #-}

module OICIntegrationSpec where

import Data.Aeson (decode, fromJSON)
import Data.Aeson.Types (Result(..))
import Data.Aeson.QQ
import qualified Data.Text.Encoding as TE
import Jose.Jwk
-- import Network.Wai.Middleware.RequestLogger (logStdoutDev)
import Network.Wai.Test hiding (request)
import Test.Hspec

import Broch.Model
import Broch.OpenID.Discovery
import Broch.OpenID.Registration (ClientMetaData)
import Broch.OAuth2.Token

import OAuth2IntegrationSpec
import WaiTest

spec :: Spec
spec = do
    app <- runIO testapp
    let run t = runTest app t
    openIdConfigSpec run >> openIdFlowsSpec run

clientReg :: ClientMetaData
clientReg = c
  where
    Success c = fromJSON $ [aesonQQ|
        { token_endpoint_auth_method: "client_secret_basic"
        , subject_type: "public"
        , application_type: "web"
        , client_name: "Integration tests"
        , id_token_signed_response_alg: "HS256"
        , response_types: ["code", "token", "id_token", "code id_token", "code token"]
        , require_auth_time: true
        , default_max_age: 3600
        , contacts: ["admin@rndsa19sui.com"]
        , redirect_uris: ["http://localhost/authz_cb"]
        , jwks_uri: "http://localhost:8090/static/jwks.json"
        , grant_types: ["authorization_code", "implicit", "refresh_token", "urn:ietf:params:oauth:grant-type:jwt-bearer:"]
        }
|]

registerClient md = postJSON "/connect/register" md

clientRegistrationSpec run =
    describe "OpenID Client registration" $ do

        it "Supports dynamic registration" $ run $ do
            registerClient clientReg
            statusIs 201

openIdConfigSpec run =
    describe "The .well-known endpoints" $ do

        it "OpenID Configuration and JWKs are returned" $ run $ do
            get "/.well-known/openid-configuration"
            statusIs 200
            json1 <- withResponse $ return . simpleBody
            let Just cfg = decode $ json1 :: Maybe OpenIDConfiguration
            assertEqual "Returned issuer should match" (issuer cfg) (issuer $ defaultOpenIDConfiguration "http://testapp")
            get $ TE.encodeUtf8 $ jwks_uri cfg
            json2 <- withResponse $ return . simpleBody
            let Just jwks = decode $ json2 :: Maybe JwkSet
            assertEqual "There should be one JWK" 1 (length $ keys jwks)


userInfoRequest t = bearerAuth t >> get "/connect/userinfo"

redirectUri = "http://localhost:8080/app"
-- TODO: Move OpenID tests to separate module and rename this module to
-- OAuth2IntegrationSpec.
openIdFlowsSpec run =
    describe "OpenID authentication flows" $ do
        let auth = authzRequest "app" redirectUri [OpenID]
            token = tokenRequest "app" "appsecret" redirectUri
            nonce = ("nonce", "imthenonce")
        describe "A request with response_type=code" $ do
            it "Returns only a code from the authorization endpoint" $ run $ do
                AuthzResponse Nothing Nothing (Just code) <- auth Code []
                AccessTokenResponse t _ _ (Just _) (Just _) _ <- token AuthorizationCode code
                userInfoRequest t

        describe "A request with response_type=id_token" $ do
            it "Returns id_token" $ run $ do
                AuthzResponse (Just _) Nothing Nothing <- auth IdTokenResponse [nonce]
                return ()
            it "Requires openid scope" $ do
                -- What behaviour do we want when scope is missing
                -- but the respose_type is openid?
                pending

        describe "A request with response_type=code token" $ do
            it "Requires a nonce" $ run $ authzWithoutNonce CodeToken
            it "Supports code token response type" $ run $ do
                AuthzResponse Nothing (Just _) (Just _) <- auth CodeToken [nonce]
                return ()

        describe "A request with response_type=code id_token" $ do
            it "Requires a nonce" $ run $ authzWithoutNonce CodeIdToken
            it "Includes c_hash in id_token"
                pending

        describe "A request with response_type=token id_token" $ do
            it "Requires a nonce" $ run $ authzWithoutNonce TokenIdToken
            it "Includes at_hash in id_token"
                pending

        describe "A request with response_type=code token id_token" $ do
            it "Requires a nonce" $ run $ authzWithoutNonce CodeTokenIdToken
            it "Includes c_hash in id_token"
                pending
            it "Includes at_hash in id_token"
                pending

authzWithoutNonce typ = do
    sendAuthzRequest "app" redirectUri [OpenID] typ []
    loginIfRequired "cat" "cat"
    expectInvalidRequest

expectInvalidRequest = statusIs 302 >> getLocationParam "error" >>= assertEqual "invalid_request expected" "invalid_request"

