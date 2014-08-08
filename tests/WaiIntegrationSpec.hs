{-# LANGUAGE OverloadedStrings, QuasiQuotes #-}
{-# OPTIONS_GHC -fno-warn-missing-signatures #-}

module WaiIntegrationSpec where

import Control.Applicative ((<$>))
import Control.Monad (when)
import Control.Monad.IO.Class (liftIO)
import Data.Aeson (decode, fromJSON)
import Data.Aeson.Types (Result(..))
import Data.Aeson.QQ
import qualified Data.ByteString.Char8 as B
import Data.Int (Int64)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time.Clock.POSIX
import Database.Persist.Sqlite (createSqlitePool)
import Jose.Jwk
-- import Network.Wai.Middleware.RequestLogger (logStdoutDev)
import Network.Wai.Test hiding (request)
import Network.URI (uriPath)
import Test.Hspec

import Broch.Model
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
            authzResponse <- authzRequest "app" redirectUri Code []
            code <- case authzResponse of
                AuthzResponse Nothing Nothing (Just c) -> return c
                _ -> fail $ "Invalid response " ++ show authzResponse
            get "/logout"
            reset
            -- Post as client.
            basicAuth "app" "appsecret"
            post "/oauth/token" [("client_id", "app"), ("grant_type", "authorization_code"), ("redirect_uri", redirectUri), ("code", code)]

badClientSpec run =
    describe "A possibly malicious client request" $ do

        it "returns a non-redirect error if redirect_uri is wrong" $ run $ do
            sendAuthzRequest "app" "http://notapp" Code []
            -- Redirect to the login page
            followRedirect
            statusIs 200
            login "cat" "cat"
            -- Redirected to the original request
            followRedirect
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

-- TODO: Move OpenID tests to separate module and rename this module to
-- OAuth2IntegrationSpec.
openIdFlowsSpec run =
    describe "OpenID authentication flows" $ do
        describe "A request with response_type=code" $ do
            it "Supports openid scope" $ do
                pending

        describe "A request with response_type=token" $ do
            it "Supports requests containing a nonce" $ do
                pending

        describe "A request with response_type=id_token" $ do
            -- What behaviour do we want when scope is missing
            -- but the respose_type is openid?
            it "Requires openid scope" $ do
                pending

        describe "A request with response_type=code token" $ do
            it "Supports code token response type" $ do
                pending

        describe "A request with response_type=code id_token" $ do
            it "Includes c_hash in id_token"
                pending

        describe "A request with response_type=token id_token" $ do
            it "Includes at_hash in id_token"
                pending

data AuthzResponse = AuthzResponse
    { idToken      :: Maybe B.ByteString
    , accessToken  :: Maybe B.ByteString
    , authzCode    :: Maybe Text
    } deriving (Show)

authzRequest :: ClientId -> Text -> ResponseType -> [Scope] -> WaiTest AuthzResponse
authzRequest cid redirectUri rt scopes = do
    sendAuthzRequest cid redirectUri rt scopes
    loginIfRequired "cat" "cat"
    statusIsGood
    approveIfRequired
    q <- getLocationQuery
    return $ AuthzResponse (lookup "id_token" q) (lookup "access_token" q) (TE.decodeUtf8 <$> lookup "code" q)

sendAuthzRequest cid redirectUri rt scopes = getP "/oauth/authorize" params
  where
    params = case scopes of
        [] -> baseParams
        _  -> ("scope", formatScope scopes) : baseParams
    baseParams = [("client_id", cid), ("state", "1234"), ("response_type", responseTypeName rt), ("redirect_uri", redirectUri)]


testapp = createSqlitePool ":memory:" 2 >>= testBroch "http://testapp" >>= return -- . logStdoutDev

approveIfRequired :: WaiTest ()
approveIfRequired = withResponse $ \r ->
    when (isRedirect r) $ do
        p <- fmap uriPath getLocationURI
        when (p == "/approval") $ do
            -- Scope to approve
            scope <- getLocationParam "scope"
            cid   <- getLocationParam "client_id"
            followRedirect
            -- TODO: Check we're on the approvals page
            now <- liftIO $ getPOSIXTime
            let expiry = round $ now + posixDayLength :: Int64
            post "/approval" [("client_id", cid), ("expiry", T.pack $ show expiry), ("scope", scope)]
            followRedirect


loginIfRequired username password = withOptionalRedirect "/login" $ login username password >> followRedirect

login username pass = post "/login" [("username", username), ("password", pass)]

