{-# LANGUAGE TypeFamilies, OverloadedStrings, GADTs,
             FlexibleContexts, MultiParamTypeClasses, TemplateHaskell,
             GeneralizedNewtypeDeriving, QuasiQuotes #-}

module Broch.TestApp

where

import           Control.Monad.Logger (runStderrLoggingT)
import qualified Crypto.PubKey.RSA as RSA
import qualified Data.Map as Map
import           Data.Text
import           Database.Persist.Sql (ConnectionPool, runSqlPool, runMigration, runSqlPersistMPool)
import qualified Network.Wai as W
import qualified Web.ClientSession as CS
import           Text.Shakespeare.I18N (RenderMessage(..))
import           Yesod.Core
import           Yesod.Auth
import           Yesod.Form
import           Yesod.Auth.Dummy

import           Broch.Class
import           Broch.Model
import           Broch.Random
import           Broch.Handler.Authorize
import           Broch.Handler.Token
import           Broch.Handler.OpenID
import qualified Broch.Persist as BP

data TestApp = TestApp
    { pool        :: ConnectionPool
    , privateKey  :: RSA.PrivateKey
--    , createAuthz :: Text -> Text -> Client -> POSIXTime -> [Text] -> Maybe Text -> IO ()
--    , loadAuthzByCode :: Text -> IO (Maybe Authorization)
    }

mkYesod "TestApp" [parseRoutes|
/                 HomeR GET
/oauth/token      TokenR POST
/oauth/authorize  AuthorizeR GET
/auth AuthR Auth  getAuth
/.well-known/openid-configuration OpenIDConfigurationR GET
/.well-known/jwks JwksR GET
|]

instance Yesod TestApp where
    authRoute _ = Just $ AuthR LoginR

    isAuthorized HomeR _       = return Authorized
    isAuthorized TokenR _      = return Authorized
    isAuthorized AuthorizeR _  = isUser
    isAuthorized (AuthR LoginR) _       = return Authorized
    isAuthorized _     _       = return Authorized --return $ Unauthorized "Keep out"
    -- Don't handle sessions for the token endpoint
    makeSessionBackend _ = do
        let dontSaveSession _ = return []
        let noSession         = return (Map.empty, dontSaveSession)
        dbe <- defaultClientSessionBackend 120 CS.defaultKeyFile
        return $ Just $ SessionBackend $ \req ->
            case W.pathInfo req of
                ["oauth", "token"] -> noSession
                [".well-known", _] -> noSession
                _                  -> sbLoadSession dbe req

isUser = do
    mu <- maybeAuthId
    return $ case mu of
        Nothing -> AuthenticationRequired
        Just _  -> Authorized


instance YesodAuth TestApp where
    type AuthId TestApp = Text
    getAuthId = return . Just . credsIdent

    maybeAuthId = lookupSession "_ID" >>= \mId -> return $ mId >>= fromPathPiece

    loginDest _ = HomeR
    logoutDest _ = HomeR

    authPlugins _ = [authDummy] -- [authBrowserId, authGoogleEmail]

    authHttpManager = error "authHttpManager not set"


instance RenderMessage TestApp FormMessage where
    renderMessage _ _ = defaultFormMessage


instance OAuth2Server TestApp where
    getClient app cid = runDB app $ BP.getClientById cid

    createAuthorization app code uid clnt now scp uri = runDB app $
                            BP.createAuthorization code uid clnt now scp uri

    -- Dummy implementation
    authenticateResourceOwner _ username password
        | username == password = return $ Just username
        | otherwise            = return Nothing

    getAuthorization app code = runDB app $ BP.getAuthorizationByCode code

    getPrivateKey = privateKey

runDB app = flip runSqlPersistMPool (pool app)


instance OpenIDConnectServer TestApp


getHomeR = do
    maid <- maybeAuthId
    defaultLayout $ do
        setTitle "Home page"
        [whamlet|
<h2>Home Page
<p>Your current auth ID: #{show maid}
$maybe _ <- maid
    <p>
        <a href=@{AuthR LogoutR}>Logout
$nothing
    <p>
        <a href=@{AuthR LoginR}>Go to the login page
<p>Nothing to see here yet. Maybe you want to try an <a href=@{AuthorizeR}>authorization request?
|]

testClients =
    [ Client "admin" (Just "adminsecret") [ClientCredentials]                []                            300 300 [] True []
    , Client "cf"    Nothing              [ResourceOwner]                    ["http://cf.com"]             300 300 [] True []
    , Client "app"   (Just "appsecret")   [AuthorizationCode, RefreshToken]  ["http://localhost:8080/app"] 300 300 [] False []
    ]

makeTestApp :: [Client] -> ConnectionPool -> IO TestApp
makeTestApp cs p = do
    runStderrLoggingT $ runSqlPool (runMigration BP.migrateAll) p
    mapM_ (\c -> runSqlPersistMPool (BP.createClient c) p) cs
    (_, kPr) <- withCPRG $ \g -> RSA.generate g 64 65537

    return $ TestApp p kPr

