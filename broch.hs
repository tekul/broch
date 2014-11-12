{-# LANGUAGE OverloadedStrings #-}

import Prelude hiding (catch)

import Control.Exception
import Control.Monad.Logger (runNoLoggingT)
import Control.Monad.IO.Class (liftIO)
import Database.Persist.Sqlite (createSqlitePool)
import Network.Wai.Middleware.RequestLogger (logStdoutDev)
import Network.Wai.Handler.Warp
import Network.Wai.Handler.WarpTLS
import Network.TLS
import System.Directory
import System.IO.Error hiding (catch)
import Web.ClientSession (getDefaultKey)

import Broch.Server
import Broch.Server.Internal
import Broch.Server.Session (defaultLoadSession)

main :: IO ()
main = do
    removeFile "broch.db3" `catch` eek
    csKey  <- getDefaultKey

    pool   <- runNoLoggingT $ createSqlitePool "broch.db3" 2
    router <- testBroch "http://localhost:3000" pool
    let tlsConfig = tlsSettings "broch.crt" "broch.key"
    let config    = defaultSettings
    -- runTLS tlsConfig config $ logStdoutDev waiApp
    let waiApp = routerToApp (defaultLoadSession 3600 csKey) "http://localhost:3000" router
    run 3000 $ logStdoutDev waiApp
  where
    eek e
      | isDoesNotExistError e = return ()
      | otherwise             = throwIO e

