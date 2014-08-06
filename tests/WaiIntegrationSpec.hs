{-# LANGUAGE OverloadedStrings, QuasiQuotes #-}
{-# OPTIONS_GHC -fno-warn-missing-signatures #-}

module WaiIntegrationSpec where

import Control.Monad.IO.Class (liftIO)
import Data.Aeson (decode, fromJSON)
import Data.Aeson.Types (Result(..))
import Data.Aeson.QQ
import qualified Data.ByteString.Char8 as B
import Data.Int (Int64)
import qualified Data.Text.Encoding as TE
import Data.Time.Clock.POSIX
import Database.Persist.Sqlite (createSqlitePool)
import Jose.Jwk
-- import Network.Wai.Middleware.RequestLogger (logStdoutDev)
import Network.Wai.Test hiding (request)
import Test.Hspec

import Broch.Scotty
import Broch.OpenID.Discovery
import Broch.OpenID.Registration (ClientMetaData)
import WaiTest

integrationSpec :: Spec
integrationSpec = do
    app <- runIO testapp
    let run t = runTest app t
    clientRegistrationSpec run >> authCodeSuccessSpec run >> badClientSpec run >> openIdConfigSpec run

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

clientRegistrationSpec run =
    describe "OpenID Client registration" $ do

        it "Supports dynamic registration" $ run $ do
            postJSON "/connect/register" $ clientReg
            statusIs 201

authCodeSuccessSpec run =
    describe "A successful authorization_code flow" $ do

        it "logs in the user, provides a code and issues an access token to the client" $ run $ do
            let redirectUri = "http://localhost:8080/app"
            -- Auth code request for default client scopes
            authCodeRequest "app" redirectUri []
            statusIs 302

            get "/login"
            statusIs 200

            login "cat" "cat"
            statusIs 302
            -- Server redirects to the original authz request
            -- Resend original request
            getLocationHeader >>= get
            statusIs 302
            -- Redirect to approvals
            getLocationHeader >>= get
            statusIs 200
            now <- liftIO $ getPOSIXTime
            let expiry = round $ now + posixDayLength :: Int64
            post "/approval" [("client_id", "app"), ("scope", "scope1"), ("scope", "scope2"), ("expiry", B.pack $ show expiry)]
            statusIs 302
            -- Resend the original request *again*
            getLocationHeader >>= get
            statusIs 302
            code <- getLocationParam "code"
            get "/logout"
            reset
            -- Post as client.
            basicAuth "app" "appsecret"
            post "/oauth/token" [("client_id", "app"), ("grant_type", "authorization_code"), ("redirect_uri", redirectUri), ("code", code)]

badClientSpec run =
    describe "A possibly malicious client request" $ do

        it "returns a non-redirect error if redirect_uri is wrong" $ run $ do
            authCodeRequest "app" "http://notapp" []
            statusIs 302
            -- Get the login page
            getLocationHeader >>= get
            statusIs 200
            login "cat" "cat"
            statusIs 302
            -- Resend original request
            getLocationHeader >>= get
            statusIs 400

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

authCodeRequest cid redirectUri scopes = getP "/oauth/authorize" params
  where
    params = case scopes of
        [] -> baseParams
        _  -> ("scope", B.intercalate " " scopes) : baseParams
    baseParams = [("client_id", cid), ("state", "1234"), ("response_type", "code"), ("redirect_uri", redirectUri)]

testapp = createSqlitePool ":memory:" 2 >>= testBroch "http://testapp" >>= return -- . logStdoutDev

login uid pass = post "/login" [("username", uid), ("password", pass)]

