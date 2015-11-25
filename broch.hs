{-# LANGUAGE OverloadedStrings #-}

import Prelude hiding (catch)

import Control.Exception
import Control.Monad.Logger (runNoLoggingT)
import Control.Monad.IO.Class (liftIO)
import Data.Pool
import Database.Persist.Sqlite (createSqlitePool)
import Database.PostgreSQL.Simple
import Network.Wai.Middleware.RequestLogger (logStdoutDev)
import Network.Wai.Handler.Warp
--import Network.Wai.Handler.WarpTLS
-- import Network.TLS
import System.Directory
import System.IO.Error hiding (catch)
import Web.Routing.TextRouting

import Broch.PostgreSQL
import Broch.Server
import Broch.Server.Config
import Broch.Test
import Broch.Server.Internal
import Broch.Server.Session (defaultKey, defaultLoadSession)

main :: IO ()
main = do
    sessionKey <- defaultKey
    let issuer = "http://localhost:3000"
        connStr = "dbname=broch"
    --router <- sqliteConfig issuer
    router <- postgresqlConfig issuer connStr
 --   let tlsConfig = tlsSettings "broch.crt" "broch.key"
    -- let config    = defaultSettings
    let waiApp = routerToApp (defaultLoadSession 3600 sessionKey) issuer router
    run 3000 $ logStdoutDev waiApp
    --runTLS tlsConfig config $ logStdoutDev waiApp

postgresqlConfig issuer connStr = do
    pool <- createPool createConn close 1 60 20
    kr <- defaultKeyRing
    rotateKeys kr True
    config <- postgreSQLBackend pool <$> inMemoryConfig issuer kr
    let baseRouter = brochServer config defaultApprovalPage authenticatedSubject
        authenticate username password = return (if username == password then Just username else Nothing)
        extraRoutes =
            [ ("/home",   text "Hello, I'm the home page")
            , ("/login",  passwordLoginHandler defaultLoginPage authenticate)
            , ("/logout", invalidateSession >> complete)
            ]
    return $ foldl (\tree (r, h) -> addToRoutingTree r h tree) baseRouter extraRoutes
  where
    createConn = connectPostgreSQL connStr

sqliteConfig issuer = do
    removeFile "broch.db3" `catch` eek
    pool   <- runNoLoggingT $ createSqlitePool "broch.db3" 2
    testBroch issuer pool
  where
    eek e
      | isDoesNotExistError e = return ()
      | otherwise             = throwIO e
