{-# LANGUAGE TypeFamilies, OverloadedStrings, GADTs,
             FlexibleContexts, MultiParamTypeClasses, TemplateHaskell,
             GeneralizedNewtypeDeriving, QuasiQuotes #-}


import Yesod.Core (Yesod(..), RenderRoute(..), Approot(..), mkYesod, getYesod, parseRoutes, lookupSession, defaultLayout, setTitle, whamlet, toWaiApp, AuthResult(..), SessionBackend(..), defaultClientSessionBackend)
import Yesod.Auth
import Yesod.Auth.BrowserId
import Yesod.Auth.GoogleEmail
import Yesod.Auth.Dummy
import Yesod.Form
import Yesod.Core.Handler (HandlerT)
import Web.PathPieces (fromPathPiece)
import Database.Persist.Sqlite (ConnectionPool, withSqlitePool, runSqlPool, runSqlPersistMPool, runMigration)
import Crypto.PubKey.OpenSsh
import qualified Crypto.PubKey.RSA as RSA
import Control.Monad.IO.Class (liftIO)
import Control.Monad.Logger (runStderrLoggingT)
import Data.Aeson
import Data.String.QQ
import Data.Text (Text)
import Data.ByteString (ByteString)
import Data.Time.Clock.POSIX (POSIXTime)
import qualified Data.Map as Map
import qualified Network.Wai as W
import Network.Wai.Middleware.RequestLogger (logStdoutDev)
import Network.Wai.Handler.Warp (run)
import Network.HTTP.Conduit (Manager, newManager)
import Network.HTTP.Client (defaultManagerSettings)
import Text.Shakespeare.I18N (RenderMessage(..))
import qualified Web.ClientSession as CS

import Jose.Jwk

import Broch.Token
import Broch.Model
import Broch.Handler.Authorize
import Broch.Class
import Broch.Handler.Token
import Broch.Handler.OpenID
import qualified Broch.Persist as BP

data BrochApp = BrochApp
    { httpManager :: Manager
    , brochPool   :: ConnectionPool
    , privateKey  :: RSA.PrivateKey
    , createAuthz :: Text -> Text -> Client -> POSIXTime -> [Text] -> Maybe Text -> IO ()
    , loadAuthzByCode :: Text -> IO (Maybe Authorization)
    }

mkYesod "BrochApp" [parseRoutes|
/                 HomeR GET
/oauth/token      TokenR POST
/oauth/authorize  AuthorizeR GET
/auth AuthR Auth  getAuth
/.well-known/openid-configuration OpenIDConfigurationR GET
/.well-known/jwks JwksR GET
|]

instance Yesod BrochApp where
    authRoute _ = Just $ AuthR LoginR
    approot = ApprootStatic "http://localhost:4000" -- required for BrowserID

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

instance YesodAuth BrochApp where
    type AuthId BrochApp = Text
    getAuthId = return . Just . credsIdent

    maybeAuthId = lookupSession "_ID" >>= \mId -> return $ mId >>= fromPathPiece

    loginDest _ = HomeR
    logoutDest _ = HomeR

    authPlugins _ = [authDummy] -- [authBrowserId, authGoogleEmail]

    authHttpManager = httpManager

instance RenderMessage BrochApp FormMessage where
    renderMessage _ _ = defaultFormMessage


instance OAuth2Server BrochApp where
    getClient _ cid = return $ lookupClient cid

    createAuthorization app = createAuthz app

    -- Dummy implementation
    authenticateResourceOwner _ username password
        | username == password = return $ Just username
        | otherwise            = return Nothing

    getAuthorization = loadAuthzByCode

    getPrivateKey _ = privKey


instance OpenIDConnectServer BrochApp


--runDB (BrochApp _ pool _) f = runSqlPool f pool

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

lookupClient = findClient clients
  where
    findClient []   _  = Nothing
    findClient (c:cs) cid
        | cid == clientId c = Just c
        | otherwise         = findClient cs cid

clients =
    [ Client "admin" (Just "adminsecret") [ClientCredentials]                []                            300 300 [] True []
    , Client "cf"    Nothing              [ResourceOwner]                    ["http://cf.com"]             300 300 [] True []
    , Client "app"   (Just "appsecret")   [AuthorizationCode, RefreshToken]  ["http://localhost:8080/app"] 300 300 [] False []
    ]

privKey = rsaKey
  where
    Right (OpenSshPrivateKeyRsa rsaKey) = decodePrivate privKeyString

privKeyString :: ByteString
privKeyString = [s|
-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA1+DQxJYVMbw0jKENd+iyQk7bA51rt2Vx9glNFq1aD5Zl6kdR
xZfYVyLUngt3YaH0UcHiRpN9xg4VikmhyCaRblSLo+h/xvEn7di8K1rj2zCwZuxC
r9NjfpkMPYdNgo1Mnw/O36rq67HsZuESSsjG646lMLWoK3B7ob3cwaDn1744KaQg
vMKnYlcd40qtzilZFRdUgRGtqIY4ngD3CpxJ+jabLe7oUiwvluqEtCxvWUs1/3Yp
jlrXl4IWWEFzsvoibeXx883THtIiax9WQQZ5j8cyTYSetKI4CQwokJOeyCInVmY1
c7riqIFwDBYqxNkg23jgghfBkSCw7FC6Pw7nZQIDAQABAoIBAAyZeXXP0KLbejGv
AKs78JOAKLY4TN4iVJloh5BIQ9ZfD8mxqesfZqgHR2OGBcyz+B+BcmRuHUwe7FDq
5T9aSOiolJHXcwW4c30lRi49msjjOZh4N5gtfUQZSKaarAJvnsY11Pwm7JkfBE4o
2rl0qG99HtUN9Se74+tXuneunXlw7CtwdHUIIpXyFDM4v+skmHzH/XQ0IheJ9c3H
Xu0PH3U5wSQYd/lc5pp+2G3Bc3mJFPSjhanA8SJwU8on8Q67NQnXG3nNaHzpoa5O
hWENDSXY7fn0R2MV/nhJ6A3FkrmqbcwAph9ViwSFDm/nfGdy7CGg8SiHOaaUXrBz
VTrl+I0CgYEA/z8dQZupmXD6k74G4U8GzXwt4KMY74tK0W2524ETgZzTizbdSEmj
AYHBDpu00GE+4fhPBaLwa99pAV3786t4hrfTk9lBgV9dRleGBx72XibhTKfhSuf0
JcnQ7JXYDXYj7eP3Uw39SVztYTPZ/mpiwPO/cWHawOYvpdfxB8xGT3sCgYEA2IPz
gLpj+P0pzGJfoat5TxGvaQMCsfSJSNIZJdC+Fvtj10l7xLihz9JFTvgmJ2+tqLXv
54gwESPSQbhdg1SoG3lKkOh+YPxrhFaDcdSZKZr0f8pMKgMRJ5QBDQR2VKrc/0Hy
hgmrgTJojr81htgyzipyXuXZ7+HBGtHYhg8/fp8CgYEAwkpqnKw+1xvWwWtelVaw
WO3zhhDgREcFNpGNbfa8wGZ96HRk0EetGtKH//SqGAxN73gxvpqe4531siK2TG7z
maiIFvzDDhVnTMoGrZj19Akoak9IANq7T6BlthEBmo2ZH9XtR31YleV0lA8CGtUk
QrfHvCi+eSM+lcDgKg1mX80CgYAh3cnZyc3XZWoDUSPaOuMXrhF84H6sbS6IGGzc
kGEbYSkFxLW6WJLe2eoDZyc4pexI5mRnF9NE6xB5PShLYZOF8JvsPKF/9BuxMIMQ
7AslCdrSnkb5j09AnJLpgVgs+CjnOF6B/sM3yzW1lkz+EZUo0FThaRyEvBAjbM1s
crggywKBgA6ULXlWWpwDJJnS8Nr8eW83RWTXtbNYwZGy/rzAfbG74M/Xbs/LmpC1
SFWWRG75oRhgfStYzME0BhiRl3UBUUa7gpzhh1XT7Itqsn6LES/fYU8qGzO3o8iH
8PlgBGndr6IXrT23kpnLmDFNSO4sMPyK3l0gEou2OpbrSAwZruvg
-----END RSA PRIVATE KEY-----
|]


main :: IO ()
main = withSqlitePool "broch.db3" 5 $ \pool -> do
    runStderrLoggingT $ runSqlPool (runMigration BP.migrateAll) pool
    man <- newManager defaultManagerSettings
    let loadAuthz code = runSqlPersistMPool (BP.getAuthorizationByCode code) pool
    let newAuthz  code uid client now scope mUri = flip runSqlPersistMPool pool $
                            BP.createAuthorization code uid client now scope mUri
    waiApp <- toWaiApp $ BrochApp man pool privKey newAuthz loadAuthz
    run 4000 $ logStdoutDev waiApp

