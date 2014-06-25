{-# LANGUAGE TypeFamilies, OverloadedStrings, GADTs,
             FlexibleContexts, MultiParamTypeClasses, TemplateHaskell,
             GeneralizedNewtypeDeriving, QuasiQuotes #-}

module Broch.TestApp

where

import           Control.Monad.Logger (runStderrLoggingT)
import qualified Crypto.PubKey.RSA as RSA
import qualified Data.Map as Map
import           Data.Text
import           Data.Time.Clock.POSIX (posixSecondsToUTCTime)
import           Database.Persist.Sql (ConnectionPool, runSqlPool, runMigration, runSqlPersistMPool)
import qualified Network.Wai as W
import qualified Web.ClientSession as CS
import           Yesod.Core
import           Yesod.Auth
import           Yesod.Form
import           Yesod.Auth.Dummy

import           Broch.Model
import qualified Broch.Persist as BP
import           Broch.Random
import           Broch.Yesod.Class
import           Broch.Yesod.Handler.Approval
import           Broch.Yesod.Handler.Authorize
import           Broch.Yesod.Handler.Token
import           Broch.Yesod.Handler.OpenID

data TestApp = TestApp
    { pool        :: ConnectionPool
    , privateKey  :: RSA.PrivateKey
    }

mkYesod "TestApp" [parseRoutes|
/                 HomeR GET
/oauth/token      TokenR POST
/oauth/authorize  AuthorizeR GET
/approval         ApprovalR GET POST
/auth AuthR Auth  getAuth
/.well-known/openid-configuration OpenIDConfigurationR GET
/.well-known/jwks JwksR GET
|]

-- /connect/userinfo UserInfoR GET

instance Yesod TestApp where
    authRoute _ = Just $ AuthR LoginR

    isAuthorized HomeR _       = return Authorized
    isAuthorized TokenR _      = return Authorized
--    isAuthorized AuthorizeR _  = isUser
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
{--
isUser = do
    mu <- maybeAuthId
    return $ case mu of
        Nothing -> AuthenticationRequired
        Just _  -> Authorized
--}

data TestUser = TestUser Text

instance Subject TestUser where
    subjectId (TestUser u) = u


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
    getClient cid = runDB $ BP.getClientById cid

    createAuthorization code user clnt now scp uri = runDB $
                            BP.createAuthorization code (subjectId user) clnt now scp uri

    -- Dummy implementation
    authenticateResourceOwner username password
        | username == password = return $ Just username
        | otherwise            = return Nothing

    getAuthorization code = runDB $ BP.getAuthorizationByCode code

    getApproval user clnt now = runDB $ BP.getApproval (subjectId user) (clientId clnt) now

    saveApproval = runDB . BP.createApproval

    getPrivateKey = fmap privateKey getYesod

    approvalRoute _ = ApprovalR

runDB f = do
    TestApp p _ <- getYesod
    runSqlPool f p


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
    , Client "app"   (Just "appsecret")   [AuthorizationCode, RefreshToken]  ["http://localhost:8080/app"] 300 300 [CustomScope "scope1", CustomScope "scope2"] False []
    ]

makeTestApp :: [Client] -> ConnectionPool -> IO TestApp
makeTestApp cs p = do
    runStderrLoggingT $ runSqlPool (runMigration BP.migrateAll) p
    mapM_ (\c -> runSqlPersistMPool (BP.createClient c) p) cs
    (_, kPr) <- withCPRG $ \g -> RSA.generate g 64 65537

    return $ TestApp p kPr

