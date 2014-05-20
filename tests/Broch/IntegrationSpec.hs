{-# LANGUAGE OverloadedStrings #-}

module Broch.IntegrationSpec where

import Control.Monad.IO.Class (liftIO)
import Database.Persist hiding (get)
import Database.Persist.Sql (SqlPersistM, runSqlPersistMPool)
import Database.Persist.Sqlite (createSqlitePool)
import Test.Hspec (hspec, Spec)
import Yesod.Test

import Broch.TestApp


spec :: Spec
spec = undefined



integrationSpec :: YesodSpec TestApp
integrationSpec =
    ydescribe "A successful authorization_code flow" $ do

        yit "is redirected to the login page" $ do
            get HomeR
            statusIs 200

            request $ do
               setUrl AuthorizeR
               addGetParam "client_id"     "app"
               addGetParam "state"         "1234"
               addGetParam "response_type" "code"
               addGetParam "redirect_uri"  "http://localhost:8080/app"

            statusIs 302


runDB :: SqlPersistM a -> YesodExample TestApp a
runDB query = do
        p <- fmap pool getTestYesod
        liftIO $ runSqlPersistMPool query p

main :: IO ()
main = do
    app <- createSqlitePool "file::memory:?cache=shared" 5 >>= makeTestApp
    hspec $ do
        yesodSpec app $ do
            integrationSpec
