{-# LANGUAGE OverloadedStrings, RecordWildCards #-}

import Control.Monad (msum, when)
import Crypto.KDF.BCrypt (validatePassword)
import qualified Data.ByteArray.Encoding as BE
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as BC
import Data.Pool (createPool)
import Data.Maybe (fromMaybe, isNothing)
import Data.Monoid ((<>))
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Database.PostgreSQL.Simple
import Network.Wai.Application.Static (staticApp, defaultWebAppSettings)
import Network.Wai.Middleware.RequestLogger (logStdoutDev)
import Network.Wai.Handler.Warp (run)
import Options.Applicative
import System.Environment (getEnvironment)
import System.Exit (die)
import qualified Web.Routing.Combinators as R
import qualified Web.Routing.SafeRouting as R

import qualified Broch.PostgreSQL as BP
import Broch.Server
import Broch.Server.Config
import Broch.Server.Internal
import Broch.Server.Session (defaultKey, defaultLoadSession)

data BrochOpts = BrochOpts
    { issuer  :: T.Text
    , port    :: Int
    , connStr :: String
    , webRoot :: FilePath
    }

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
       <> help "The postgresql connection string"
       <> metavar "DATABASE"
       <> value db)
    <*> strOption
        ( long "web-root"
       <> help "The directory from which to serve static content"
       <> metavar "WEBROOT"
       <> value webroot)

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
        | connStr opts == "default" = opts { connStr = defaultConnStr}
        | otherwise = opts
    defaultConnStr = "dbname=broch"

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
    pool <- createPool (connectPostgreSQL (BC.pack connStr)) close 1 60 20
    let passwordAuthenticate = BP.passwordAuthenticate pool

    config <- BP.postgreSQLBackend pool <$> inMemoryConfig issuer kr sidSalt
    let app = staticApp (defaultWebAppSettings "webroot")
        baseRouter = brochServer config defaultApprovalPage authenticatedSubject authenticateSubject
        authenticate username password = passwordAuthenticate validatePassword username (TE.encodeUtf8 password)
        extraRoutes =
            [ ("/home",   text "Hello, I'm the home page")
            , ("/login",  passwordLoginHandler defaultLoginPage authenticate)
            , ("/logout", invalidateSession >> text "You have been logged out")
            ]
        router = foldl (\pathMap (r, h) -> R.insertPathMap' (R.toInternalPath (R.static r)) (const h) pathMap) baseRouter extraRoutes
        broch = routerToMiddleware (defaultLoadSession 3600 sessionKey) issuer router

    run port (logStdoutDev (broch app))
