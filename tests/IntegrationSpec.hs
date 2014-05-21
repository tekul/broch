{-# LANGUAGE OverloadedStrings #-}

module IntegrationSpec where

import Control.Arrow (second)
import Control.Monad.IO.Class (liftIO)
import qualified Data.ByteString.Char8 as B
import Data.ByteString.Base64 as B64
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Text.IO as TIO
import Database.Persist.Sql (SqlPersistM, runSqlPersistMPool)
import Database.Persist.Sqlite (createSqlitePool)
import System.IO (stderr)
import Test.Hspec (hspec, Spec)
import Network.HTTP.Types
import Network.URI
import Network.Wai.Test (SResponse(..))
import Yesod.Auth (Route (..))
import Yesod.Test

import Broch.TestApp


integrationSpec :: YesodSpec TestApp
integrationSpec =
    ydescribe "A successful authorization_code flow" $ do

        yit "logs in the user, provides a code and issues an access token to the client" $ do
            get HomeR
            statusIs 200

            let redirectUri = "http://localhost:8080/app"

            request $ do
               setUrl AuthorizeR
               addGetParam "client_id"     "app"
               addGetParam "state"         "1234"
               addGetParam "response_type" "code"
               addGetParam "redirect_uri"  redirectUri
            statusIs 302

            get $ AuthR LoginR
            statusIs 200

            -- Dummy login
            postBody ("/auth/page/dummy" :: Text) "ident=crap"
            statusIs 302
            -- Server redirects to the original authz request
            -- printLocationHeader

            getLocationHeader >>= get
            -- Redirect to client
            statusIs 302
            getLocationParam "state" >>= \s -> assertEqual "Invalid state parameter" s "1234"
            code <- getLocationParam "code"

            -- Post as client. TODO: Find a way to reset cookies as this
            -- isn't a browser request
            request $ do
                setMethod "POST"
                setUrl TokenR
                basicAuth "app" "appsecret"
                addPostParam "client_id" "app"
                addPostParam "grant_type" "authorization_code"
                addPostParam "redirect_uri" redirectUri
                addPostParam "code" code


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
    l <- getLocationHeader
    case parseURI (T.unpack l) of
        Nothing -> fail "Invalid redirect URI"
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
    app <- createSqlitePool ":memory:" 5 >>= makeTestApp testClients
    hspec $ do
        yesodSpec app $ do
            integrationSpec
