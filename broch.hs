{-# LANGUAGE OverloadedStrings #-}

import Prelude hiding (catch)

import Control.Exception
import Control.Monad.Logger (runNoLoggingT)
import Control.Monad.IO.Class (liftIO)
import Database.Persist.Sqlite (createSqlitePool)
import Network.Wai.Middleware.RequestLogger (logStdoutDev)
import Network.Wai.Handler.Warp
--import Network.Wai.Handler.WarpTLS
import Network.TLS
import System.Directory
import System.IO.Error hiding (catch)

import Broch.Server
import Broch.Test
import Broch.Server.Internal
import Broch.Server.Session (defaultKey, defaultLoadSession)

main :: IO ()
main = do
    removeFile "broch.db3" `catch` eek
    csKey  <- defaultKey
    let issuer = "http://localhost:3000"
    pool   <- runNoLoggingT $ createSqlitePool "broch.db3" 2
    router <- testBroch issuer pool
 --   let tlsConfig = tlsSettings "broch.crt" "broch.key"
    let config    = defaultSettings
    let waiApp = routerToApp (defaultLoadSession 3600 csKey) issuer router
    run 3000 $ logStdoutDev waiApp
    --runTLS tlsConfig config $ logStdoutDev waiApp
  where
    eek e
      | isDoesNotExistError e = return ()
      | otherwise             = throwIO e

