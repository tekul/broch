{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-missing-signatures #-}

module IntegrationSpec where

import Control.Arrow (second)
import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy.Char8 as BL
import Data.Aeson (decode)
import qualified Data.ByteString.Base64 as B64
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import Data.Time.Clock.POSIX
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Text.IO as TIO
import Database.Persist.Sql (SqlPersistM, runSqlPersistMPool)
import Database.Persist.Sqlite (createSqlitePool)
import System.IO (stderr)
import Test.Hspec (hspec)
import Network.HTTP.Types
import Network.URI
import Network.Wai.Test (SResponse(..))
import Yesod.Core (Yesod)
import Yesod.Auth (Route (..))
import Yesod.Test

import Broch.TestApp
import Broch.OpenID.Discovery


integrationSpec :: YesodSpec TestApp
integrationSpec = ydescribe "Authorization endpoint integration tests" $ authCodeSuccessSpec >> badClientSpec >> openIdConfigSpec

authCodeSuccessSpec =
    ydescribe "A successful authorization_code flow" $ do

        yit "logs in the user, provides a code and issues an access token to the client" $ do
            get HomeR
            statusIs 200

            let redirectUri = "http://localhost:8080/app"
            -- Auth code request for default client scopes
            authCodeRequest "app" redirectUri []
            statusIs 302

            get $ AuthR LoginR
            statusIs 200

            login "cat"
            statusIs 302
            -- Server redirects to the original authz request
            -- Resend original request
            getLocationHeader >>= get
            -- Redirect to approvals
            statusIs 302
            printLocationHeader
            request $ do
              setUrl ApprovalR
              addGetParam "client_id" "app"
              addGetParam "scope" "scope1 scope2"
            -- Post approvals form
            approvalRequest "app" ["scope1", "scope2"]
            statusIs 302
            printLocationHeader
            -- Resend the original request *again*
            getLocationHeader >>= get
            getLocationParam "state" >>= \s -> assertEqual "Invalid state parameter" s "1234"
            code <- getLocationParam "code"

            -- Post as client. TODO: Find a way to reset cookies as this
            -- isn't a browser request
            tokenRequest "app" "appsecret" code redirectUri
            statusIs 200

badClientSpec =
    ydescribe "A possibly malicious client request" $ do

        yit "returns a non-redirect error if redirect_uri is wrong" $ do
            authCodeRequest "app" "http://notapp" []
            statusIs 302
            -- Get the login page
            getLocationHeader >>= get
            statusIs 200
            login "cat"
            statusIs 302
            -- Resend original request
            getLocationHeader >>= get

            statusIs 400


openIdConfigSpec =
    ydescribe "The OpenID connect well-known endpoints" $ do

      yit "OpenID Configuration is returned" $ do
          get OpenIDConfigurationR
          statusIs 200
          Just content <- getResponse
          let Just cfg = decode $ simpleBody content :: Maybe OpenIDConfiguration
          liftIO $ putStrLn $ show cfg
          assertEqual "Returned issuer should match" (issuer cfg) (issuer defaultOpenIDConfiguration)


login :: Yesod site => BL.ByteString -> YesodExample site ()
login uid = postBody ("/auth/page/dummy" :: Text) $ BL.concat ["ident=", uid]


authCodeRequest cid redirectUri scopes = request $ do
    setUrl AuthorizeR
    addGetParam "client_id"     cid
    addGetParam "state"         "1234"
    addGetParam "response_type" "code"
    addGetParam "redirect_uri"  redirectUri
    if null scopes
      then return ()
      else addGetParam "scope" (T.intercalate " " scopes)

tokenRequest cid secret code redirectUri = request $ do
    setMethod "POST"
    setUrl TokenR
    basicAuth cid secret
    addPostParam "client_id" cid
    addPostParam "grant_type" "authorization_code"
    addPostParam "redirect_uri" redirectUri
    addPostParam "code" code


approvalRequest cid scopes = request $ do
    setMethod "POST"
    setUrl ApprovalR
    addPostParam "client_id" cid
    now <- liftIO $ getPOSIXTime
    let expiry = round $ now + posixDayLength
    addPostParam "expiry" $ T.pack $ show expiry
    mapM_ (addPostParam "scope") scopes

basicAuth :: Text -> Text -> RequestBuilder site ()
basicAuth name password = addRequestHeader ("Authorization", B.concat["Basic ", B64.encode (TE.encodeUtf8 (T.concat [name, ":", password]))])

getLocationParam :: Text -> YesodExample site Text
getLocationParam name = getLocationQuery >>= \q ->
    case lookup name q of
        Nothing -> fail $ "Query parameter not found: " ++ T.unpack name
        Just p  -> return p

getLocationQuery :: YesodExample site [(Text, Text)]
getLocationQuery = do
    l <- getLocationURI
    return $ map (second $ fromMaybe "") $ parseQueryText $ (B.pack . uriQuery) l

printLocationHeader :: YesodExample site ()
printLocationHeader = do
    t <- getLocationHeader
    liftIO $ TIO.hPutStrLn stderr t

getLocationURI :: YesodExample site URI
getLocationURI = do
    l <- getLocationHeader >>= return . T.unpack
    case parseURIReference l of
        Nothing -> fail $ "Invalid redirect URI: " ++ l
        Just r  -> return r

getLocationHeader :: YesodExample site Text
getLocationHeader = withResponse $ \ SResponse { simpleHeaders = h } ->
    case lookup "Location" h of
      Nothing -> fail "No location header found"
      Just l  -> return $ (T.pack . B.unpack) l

runDB :: SqlPersistM a -> YesodExample TestApp a
runDB qry = do
        p <- fmap pool getTestYesod
        liftIO $ runSqlPersistMPool qry p

main :: IO ()
main = do
    app <- createSqlitePool ":memory:" 2 >>= makeTestApp testClients
    hspec $ do
        yesodSpec app $ do
            integrationSpec

