{-# LANGUAGE OverloadedStrings, RecordWildCards #-}

import Control.Exception hiding (Handler)
import Control.Monad (msum, when)
import Control.Monad.Logger (runNoLoggingT)
import Crypto.KDF.BCrypt (validatePassword)
import qualified Data.ByteArray.Encoding as BE
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BC
import Data.Pool (createPool)
import Data.Maybe (fromMaybe, isNothing)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Database.Persist.Sqlite (createSqlitePool)
import Database.PostgreSQL.Simple
import Network.Wai.Application.Static
import Network.Wai.Middleware.RequestLogger (logStdoutDev)
import Network.Wai.Handler.Warp
import Options.Applicative
import System.Directory
import System.Environment (getEnvironment)
import System.Exit (die)
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

parser :: String -> String -> Int -> String -> Parser BrochOpts
parser issuer db port webroot = BrochOpts
    <$> textOption
        ( long "issuer"
       <> help "The OP's issuer URL"
       <> metavar "ISSUER"
       <> value issuer)
    <*> option auto
        ( long "port"
       <> metavar "PORT"
       <> value port
       <> help "The port to listen on")
    <*> textOption
        ( long "connection-string"
       <> help "The postgresql connection string"
       <> metavar "DATABASE"
       <> value db)
    <*> strOption
        ( long "web-root"
       <> help "The directory from which to serve static content"
       <> metavar "WEBROOT"
       <> value webroot)
    <*> backEndOption

main :: IO ()
main = do
    env <- getEnvironment
    let issuer  = fromMaybe "http://localhost:3000" $ lookup "ISSUER" env
        port    = maybe 3000 read                   $ lookup "PORT" env
        db      = fromMaybe "dbname=broch"          $ lookup "DATABASE" env
        webroot = fromMaybe "webroot"               $ lookup "WEBROOT" env
        desc    = fullDesc <> progDesc "Run a standalone OpenID Connect server"
    sidSalt <- decodeSalt $ lookup "SUBJECT_ID_SALT" env
    opts <- execParser (info (helper <*> parser issuer db port webroot) desc)
    when (isNothing sidSalt) $ putStrLn "Subject identifiers will be shared between clients. Set SUBJECT_ID_SALT to use pairwise identifiers)"
    runWithOptions opts sidSalt

decodeSalt :: Maybe String -> IO (Maybe ByteString)
decodeSalt Nothing = return Nothing
decodeSalt (Just s) = case bs of
    Left  _ -> die "salt value must be hex or base64 encoded"
    Right b -> return (Just b)
  where
    bs = let b = BC.pack s in msum [BE.convertFromBase BE.Base64 b, BE.convertFromBase BE.Base16 b]

runWithOptions :: BrochOpts -> Maybe ByteString -> IO ()
runWithOptions BrochOpts {..} sidSalt = do
    sessionKey <- defaultKey
    router <- case backEnd of
        POSTGRES -> postgresqlConfig issuer (TE.encodeUtf8 connStr) sidSalt
        SQLITE   -> sqliteConfig issuer
    let broch = routerToMiddleware (defaultLoadSession 3600 sessionKey) issuer router
        app   = staticApp (defaultWebAppSettings "webroot")
    run port (logStdoutDev (broch app))

postgresqlConfig :: T.Text -> ByteString -> Maybe ByteString -> IO (RoutingTree (Handler ()))
postgresqlConfig issuer connStr sidSalt = do
    pool <- createPool createConn close 1 60 20
    kr <- defaultKeyRing
    rotateKeys kr True
    config <- postgreSQLBackend pool <$> inMemoryConfig issuer kr sidSalt
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
