{-# LANGUAGE OverloadedStrings #-}

module Main where

import Test.Hspec (hspec)
import qualified Broch.OAuth2.TokenSpec as TokenSpec
import qualified Broch.OAuth2.AuthorizationSpec as AuthorizationSpec
import WaiIntegrationSpec (integrationSpec)

main :: IO ()
main = hspec $ do
    TokenSpec.spec
    AuthorizationSpec.spec
    integrationSpec


