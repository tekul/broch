{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-missing-signatures #-}

module OAuth2IntegrationSpec where

import Control.Applicative ((<$>))
import Control.Monad (when)
import Control.Monad.Logger
import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Char8 as B
import Data.Aeson (decode)
import Data.Int (Int64)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time.Clock.POSIX
import Database.Persist.Sqlite (createSqlitePool)
import Network.URI (uriPath)
import Network.Wai.Middleware.RequestLogger (logStdoutDev)
import Network.Wai.Test (SResponse(..))
import Test.Hspec
import Web.ClientSession (getDefaultKey)

import Broch.Model
import Broch.Server
import Broch.Server.Internal
import qualified Broch.Server.Session as Session
import Broch.OAuth2.Token (AccessTokenResponse(..))
import WaiTest

spec :: Spec
spec = do
    app <- runIO testapp
    let run t = runTest app t
    authCodeSuccessSpec run >> badClientSpec run

authCodeSuccessSpec run =
    describe "A successful authorization_code flow" $ do

        it "logs in the user, provides a code and issues an access token to the client" $ run $ do
            let redirectUri = "http://localhost:8080/app"
            authzResponse <- authzRequest "app" redirectUri [CustomScope "scope1", CustomScope "scope2"] Code []
            code <- case authzResponse of
                AuthzResponse Nothing Nothing (Just c) -> return c
                _ -> fail $ "Invalid response " ++ show authzResponse
            get "/logout"
            reset
            AccessTokenResponse _ _ _ Nothing (Just _) _ <- tokenRequest "app" "appsecret" redirectUri AuthorizationCode code
            return ()

badClientSpec run =
    describe "A possibly malicious client request" $ do

        it "returns a non-redirect error if redirect_uri is wrong" $ run $ do
            sendAuthzRequest "app" "http://notapp" [] Code []
            -- Redirect to the login page
            followRedirect
            statusIs 200
            login "cat" "cat"
            -- Redirected to the original request
            followRedirect
            statusIs 400

data AuthzResponse = AuthzResponse
    { idToken      :: Maybe B.ByteString
    , accessToken  :: Maybe B.ByteString
    , authzCode    :: Maybe Text
    } deriving (Show)

authzRequest :: ClientId -> Text -> [Scope] -> ResponseType -> [(Text, Text)] -> WaiTest AuthzResponse
authzRequest cid redirectUri scopes rt extraParams = do
    sendAuthzRequest cid redirectUri scopes rt extraParams
    loginIfRequired "cat" "cat"
    statusIsGood
    approveIfRequired
    l <- fmap (B.takeWhile (\s -> s /= '?' && s /= '#')) getLocationHeader
    assertEqual "Redirect location should match URI" (TE.decodeUtf8 l) redirectUri
    q <- getLocationParams
    return $ AuthzResponse (lookup "id_token" q) (lookup "access_token" q) (TE.decodeUtf8 <$> lookup "code" q)

sendAuthzRequest cid redirectUri scopes rt extraParams = getP "/oauth/authorize" $ params ++ extraParams
  where
    params = case scopes of
        [] -> baseParams
        _  -> ("scope", formatScope scopes) : baseParams
    baseParams = [("client_id", cid), ("state", "1234"), ("response_type", responseTypeName rt), ("redirect_uri", redirectUri)]


tokenRequest :: ClientId -> Text -> Text -> GrantType -> Text -> WaiTest AccessTokenResponse
tokenRequest cid secret redirectUri gt code = do
    basicAuth cid secret
    post "/oauth/token" [("client_id", cid), ("grant_type", grantTypeName gt), ("redirect_uri", redirectUri), ("code", code)]
    withResponse $ \r -> case decode $ simpleBody r of
        Nothing  -> liftIO $ print r >> (fail $ "Failed to JSON decode response body")
        Just atr -> return atr

testapp = do
    pool <- runNoLoggingT $ createSqlitePool ":memory:" 2
    let issuer = "http://testapp"
    csKey <- getDefaultKey
    router <- testBroch issuer pool
    let app = routerToApp (Session.defaultLoadSession 60 csKey) (TE.encodeUtf8 issuer) router
    return $ logStdoutDev app

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
