{-# LANGUAGE OverloadedStrings #-}

module Main where

import Control.Concurrent
import Data.Aeson (encode)
import Jose.Jwk
import Network.HTTP.Types
import Network.Wai
import qualified Network.Wai.Handler.Warp as W
import Test.Hspec (hspec)
import Broch.OAuth2.TestData (clientPublicJwks)
import qualified Broch.OAuth2.TokenSpec as TokenSpec
import qualified Broch.OAuth2.AuthorizationSpec as AuthorizationSpec
import qualified OAuth2IntegrationSpec
import qualified OICIntegrationSpec

keyServer :: Application
keyServer _ r = r $ responseLBS status200 [("Content-Type", "application/json")] (encode (JwkSet clientPublicJwks))

main :: IO ()
main = do
    tid <- forkIO $ W.runSettings (W.setPort 60129 $ W.setHost "0.0.0.0" W.defaultSettings) keyServer
    hspec $ do
        TokenSpec.spec
        AuthorizationSpec.spec
        OAuth2IntegrationSpec.spec
        OICIntegrationSpec.spec
    killThread tid
