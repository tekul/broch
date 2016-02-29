{-# LANGUAGE OverloadedStrings, RecordWildCards #-}

import Control.Exception hiding (Handler)
import Control.Monad.Logger (runNoLoggingT)
import Crypto.KDF.BCrypt (validatePassword)
import Data.ByteString (ByteString)
import Data.Pool
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Database.Persist.Sqlite (createSqlitePool)
import Database.PostgreSQL.Simple
import Network.Wai.Application.Static
import Network.Wai.Middleware.RequestLogger (logStdoutDev)
import Network.Wai.Handler.Warp
import Options.Applicative
import System.Directory
import System.IO.Error
import Web.Routing.TextRouting

import Broch.PostgreSQL
import Broch.Server
import Broch.Server.Config
import Broch.Test
import Broch.Server.Internal
import Broch.Server.Session (defaultKey, defaultLoadSession)

data BackEnd = POSTGRES | SQLITE deriving (Read, Show)

data BrochOpts = BrochOpts
    { issuer  :: T.Text
    , port    :: Int
    , connStr :: T.Text
    , webRoot :: FilePath
    , backEnd :: BackEnd
    }

backEndOption :: Parser BackEnd
backEndOption = option auto
    ( long "back-end"
   <> metavar "(POSTGRES or SQLITE)"
   <> value POSTGRES
   <> help "the database backend to use for storage"
    )

textOption :: Mod OptionFields String -> Parser T.Text
textOption x = T.pack <$> strOption x

parser :: Parser BrochOpts
parser = BrochOpts
    <$> textOption
        ( long "issuer"
       <> help "The OP's issuer URL"
       <> metavar "ISSUER"
       <> value "http://localhost:3000")
    <*> option auto
        ( long "port"
       <> metavar "PORT"
       <> value 3000
       <> help "The port to listen on")
    <*> textOption
        ( long "connection-string"
       <> help "The postgresql connection string"
       <> metavar "DATABASE"
       <> value "dbname=broch")
    <*> strOption
        ( long "web-root"
       <> help "The directory from which to server static content"
       <> metavar "WEBROOT"
       <> value "webroot")
    <*> backEndOption

main :: IO ()
main = execParser (info parser mempty) >>= runWithOptions

runWithOptions :: BrochOpts -> IO ()
runWithOptions BrochOpts {..} = do
    sessionKey <- defaultKey
    router <- case backEnd of
        POSTGRES -> postgresqlConfig issuer (TE.encodeUtf8 connStr)
        SQLITE   -> sqliteConfig issuer
    let broch = routerToMiddleware (defaultLoadSession 3600 sessionKey) issuer router
        app   = staticApp (defaultWebAppSettings "webroot")
    run port (logStdoutDev (broch app))

postgresqlConfig :: T.Text -> ByteString -> IO (RoutingTree (Handler ()))
postgresqlConfig issuer connStr = do
    pool <- createPool createConn close 1 60 20
    kr <- defaultKeyRing
    rotateKeys kr True
    config <- postgreSQLBackend pool <$> inMemoryConfig issuer kr
    let baseRouter = brochServer config defaultApprovalPage authenticatedSubject authenticateSubject
        authenticate username password = passwordAuthenticate pool validatePassword username (TE.encodeUtf8 password)
        extraRoutes =
            [ ("/home",   text "Hello, I'm the home page")
            , ("/login",  passwordLoginHandler defaultLoginPage authenticate)
            , ("/logout", invalidateSession >> complete)
            ]
    return $ foldl (\tree (r, h) -> addToRoutingTree r h tree) baseRouter extraRoutes
  where
    createConn = connectPostgreSQL connStr

sqliteConfig :: T.Text -> IO (RoutingTree (Handler ()))
sqliteConfig issuer = do
    removeFile "broch.db3" `catch` eek
    pool   <- runNoLoggingT $ createSqlitePool "broch.db3" 2
    testBroch issuer pool
  where
    eek e
      | isDoesNotExistError e = return ()
      | otherwise             = throwIO e
