{-# LANGUAGE OverloadedStrings #-}

import Prelude hiding (catch)

import Control.Exception
import Database.Persist.Sqlite (withSqlitePool)
import Network.Wai.Middleware.RequestLogger (logStdoutDev)
import Network.Wai.Handler.Warp
import Network.Wai.Handler.WarpTLS
import Network.TLS
import System.Directory
import System.IO.Error hiding (catch)

import Broch.Scotty

main :: IO ()
main = do
    removeFile "broch.db3" `catch` eek

    withSqlitePool "broch.db3" 2 $ \pool -> do
        waiApp <- testBroch "http://broch.io:3000" pool
        let tlsConfig = tlsSettings "broch.crt" "broch.key"
        let config    = defaultSettings
        -- runTLS tlsConfig config $ logStdoutDev waiApp
        run 3000 $ logStdoutDev waiApp
  where
    eek e
      | isDoesNotExistError e = return ()
      | otherwise             = throwIO e

