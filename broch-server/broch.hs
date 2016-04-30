{-# LANGUAGE OverloadedStrings, RecordWildCards #-}

import Control.Monad (msum, when)
import Crypto.KDF.BCrypt (validatePassword)
import qualified Data.ByteArray.Encoding as BE
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BC
import Data.Pool (createPool, withResource)
import Data.Maybe (fromMaybe, isNothing)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Database.PostgreSQL.Simple
import qualified Database.SQLite.Simple as SQLite
import Network.Wai.Application.Static
import Network.Wai.Middleware.RequestLogger (logStdoutDev)
import Network.Wai.Handler.Warp
import Options.Applicative
import System.Environment (getEnvironment)
import System.Exit (die)
import Web.Routing.TextRouting

import qualified Broch.PostgreSQL as BP
import qualified Broch.SQLite as BS
import Broch.Server
import Broch.Server.Config
import Broch.Server.Internal
import Broch.Server.Session (defaultKey, defaultLoadSession)

data BackEnd = POSTGRES | SQLITE deriving (Read, Show)

data BrochOpts = BrochOpts
    { issuer  :: T.Text
    , port    :: Int
    , connStr :: String
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
    <*> strOption
        ( long "connection-string"
       <> help "The postgresql connection string or sqlite database file name"
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
        db      = fromMaybe "default"               $ lookup "DATABASE" env
        webroot = fromMaybe "webroot"               $ lookup "WEBROOT" env
        desc    = fullDesc <> progDesc "Run an OpenID Connect server"
    sidSalt <- decodeSalt $ lookup "SUBJECT_ID_SALT" env
    opts <- setConnStr <$> execParser (info (helper <*> parser issuer db port webroot) desc)
    when (isNothing sidSalt) $ putStrLn "Subject identifiers will be shared between clients. Set SUBJECT_ID_SALT to use pairwise identifiers)"
    runWithOptions opts sidSalt
  where
    setConnStr opts
        | connStr opts == "default" = opts { connStr = defaultConnStr (backEnd opts)}
        | otherwise = opts
    defaultConnStr be = case be of
        POSTGRES -> "dbname=broch"
        SQLITE   -> "broch.db3"

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
    kr <- defaultKeyRing
    rotateKeys kr True
    (mkBackEnd, passwordAuthenticate) <- case backEnd of
        POSTGRES -> do
            pool <- createPool (connectPostgreSQL (BC.pack connStr)) close 1 60 20
            return (BP.postgreSQLBackend pool, BP.passwordAuthenticate pool)
        SQLITE   -> do
            pool <- createPool (SQLite.open connStr) SQLite.close 1 60 20
            withResource pool $ \c -> BS.createSchema c
            return (BS.sqliteBackend pool, \v u p -> withResource pool $ \c -> BS.passwordAuthenticate c v u p)

    config <- mkBackEnd <$> inMemoryConfig issuer kr sidSalt
    let app = staticApp (defaultWebAppSettings "webroot")
        baseRouter = brochServer config defaultApprovalPage authenticatedSubject authenticateSubject
        authenticate username password = passwordAuthenticate validatePassword username (TE.encodeUtf8 password)
        extraRoutes =
            [ ("/home",   text "Hello, I'm the home page")
            , ("/login",  passwordLoginHandler defaultLoginPage authenticate)
            , ("/logout", invalidateSession >> complete)
            ]
        router = foldl (\tree (r, h) -> addToRoutingTree r h tree) baseRouter extraRoutes
        broch = routerToMiddleware (defaultLoadSession 3600 sessionKey) issuer router

    run port (logStdoutDev (broch app))
