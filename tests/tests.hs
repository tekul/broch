{-# LANGUAGE OverloadedStrings #-}

module Main where

import Database.Persist.Sql (SqlPersistM, runSqlPersistMPool)
import Database.Persist.Sqlite (createSqlitePool)
import Test.Hspec (hspec)
import qualified Broch.OAuth2.TokenSpec as TokenSpec
import IntegrationSpec (integrationSpec)
import Yesod.Test

import Broch.TestApp

main :: IO ()
main = do
    app <- createSqlitePool ":memory:" 5 >>= makeTestApp testClients

    hspec $ do
        TokenSpec.spec
        yesodSpec app $ do
            integrationSpec


