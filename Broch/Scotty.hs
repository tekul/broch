{-# LANGUAGE OverloadedStrings, GeneralizedNewtypeDeriving #-}
module Broch.Scotty where

import           Blaze.ByteString.Builder (toLazyByteString)
import           Control.Concurrent.STM
import           Control.Monad.Reader
import qualified Crypto.PubKey.RSA as RSA
import           Data.Aeson hiding (json)
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Lazy as BL
import           Data.Int (Int64)
import           Data.List ((\\))
import qualified Data.HashMap.Strict as HM
import qualified Data.Map as Map
import           Data.Maybe (fromJust)
import           Data.Text.Lazy (Text)
import qualified Data.Text.Lazy as L
import qualified Data.Text as T
import           Data.Text.Read (decimal)
import qualified Data.Text.Encoding as TE
import qualified Data.Text.Lazy.Encoding as LE
import           Data.Time.Clock.POSIX
import           Database.Persist.Sql (runMigrationSilent, runSqlPersistMPool)
import qualified Jose.Jws as Jws
import           Jose.Jwk
import           Jose.Jwa
import           Network.HTTP.Types
import qualified Network.Wai as W
import qualified Text.Blaze.Html5 as H
import           Text.Blaze.Html5.Attributes hiding (scope)
import           Text.Blaze.Html.Renderer.Text (renderHtml)
import qualified Web.ClientSession as CS
import           Web.Cookie
import           Web.Scotty.Trans

import           Broch.Model
import           Broch.OAuth2.Authorize
import           Broch.OAuth2.Token
import           Broch.OpenID.Discovery
import           Broch.OpenID.IdToken
import           Broch.OpenID.Registration
import qualified Broch.Persist as BP
import           Broch.Random
import           Broch.Token

testClients =
    [ Client "admin" (Just "adminsecret") [ClientCredentials]                []                            300 300 [] True
    , Client "cf"    Nothing              [ResourceOwner]                    ["http://cf.com"]             300 300 [] True
    , Client "app"   (Just "appsecret")   [AuthorizationCode, RefreshToken]  ["http://localhost:8080/app"] 300 300 [CustomScope "scope1", CustomScope "scope2"] False
    ]


newtype BrochState = BrochState { issuerUrl :: T.Text}

newtype BrochM a = BrochM { runBrochM :: ReaderT (TVar BrochState) IO a }
                     deriving (Functor, Monad, MonadIO, MonadReader (TVar BrochState))

brochM :: MonadTrans t => BrochM a -> t BrochM a
brochM = lift

gets :: (BrochState -> b) -> BrochM b
gets f = ask >>= liftIO . readTVarIO >>= return . f

modify :: (BrochState -> BrochState) -> BrochM ()
modify f = ask >>= liftIO . atomically . flip modifyTVar' f

testBroch issuer pool = do
    liftIO $ runSqlPersistMPool (runMigrationSilent BP.migrateAll) pool
    liftIO $ mapM_ (\c -> runSqlPersistMPool (BP.createClient c) pool) testClients
    -- Create everything we need for the oauth endpoints
    -- First we need an RSA key for signing tokens
    let runDB = flip runSqlPersistMPool pool
    let getClient = liftIO . runDB . BP.getClientById
    let createAuthorization code uid clnt now scp n uri = liftIO $ runDB $
                            BP.createAuthorization code uid clnt now scp n uri

    let getAuthorization = liftIO . runDB . BP.getAuthorizationByCode
    let authenticateResourceOwner username password
            | username == password = return $ Just username
            | otherwise            = return Nothing
    let saveApproval a = runDB $ BP.createApproval a
    (kPub, kPr) <- withCPRG $ \g -> RSA.generate g 64 65537
    let createAccessToken = createJwtAccessToken $ RSA.private_pub kPr
    let decodeRefreshToken _ jwt = return $ decodeJwtRefreshToken kPr (TE.encodeUtf8 jwt)
    let getApproval uid clnt now = runDB $ BP.getApproval uid (clientId clnt) now
    let keySet = JwkSet [RsaPublicJwk kPub (Just "brochkey") Nothing Nothing]
    let config = toJSON $ defaultOpenIDConfiguration issuer
    let registerClient :: ClientMetaData -> IO Client
        registerClient c = do
            cid <- liftIO generateCode
            sec <- liftIO generateCode
            let client = makeClient (TE.decodeUtf8 cid) (TE.decodeUtf8 sec) c
            runDB $ BP.createClient client
            return client
        createIdToken uid client nonce now code accessToken = return $ createIdTokenJws RS256 kPr issuer (clientId client) nonce uid now code accessToken


    -- Create the cookie encryption key
    -- TODO: abstract session data access
    csKey <- CS.getDefaultKey

    sync <- newTVarIO $ BrochState { issuerUrl = issuer }

    let runM m = runReaderT (runBrochM m) sync
        runActionToIO = runM

    scottyAppT runM runActionToIO $ do
        get "/" $ redirectFull "/home" :: ScottyT Text BrochM ()

        get "/home" $ text "Hello, I'm the home page."

        get "/oauth/authorize" $ authorizationHandler csKey getClient createAuthorization getApproval createAccessToken createIdToken
        post "/oauth/token" $ tokenHandler getClient getAuthorization authenticateResourceOwner createAccessToken createIdToken decodeRefreshToken
        get "/login" $ do
            html $ renderHtml $ loginPage

        post "/login" $ do
            uid  <- param "username"
            pwd  <- param "password"
            user <- liftIO $ authenticateResourceOwner uid pwd

            case user of
                Nothing -> redirectFull "/login"
                Just u  -> do
                    setEncryptedCookie csKey "bsid" (TE.encodeUtf8 u)
                    l <- getCachedLocation csKey "/home"
                    redirectFull $ L.toStrict l

        get "/approval" $ do
            user   <- getAuthId csKey
            now    <- liftIO getPOSIXTime
            Just client <- param "client_id" >>= getClient
            scope  <- param "scope" >>= return . (L.splitOn " ")
            html $ renderHtml $ approvalPage client scope (round now)

        post "/approval" $ do
            user   <- getAuthId csKey
            clntId <- param "client_id"
            expiryTxt <- param "expiry"
            scope     <- param "scope"
            let Right (expiry, _) = decimal expiryTxt
                approval = Approval user clntId (map scopeFromName scope) (TokenTime $ fromIntegral (expiry :: Int64))
            liftIO $ saveApproval approval
            l <- getCachedLocation csKey "/uhoh"
            clearCachedLocation
            -- Redirect to authorization doesn't seem to work with oictests
            redirectFull $ L.toStrict l

        post "/connect/register" $ do
            b <- body
            case eitherDecode b of
                Left err -> status badRequest400 >> text (L.pack err)
                Right v@(Object o) -> do
                    case fromJSON v of
                        Error e    -> status badRequest400 >> text (L.pack e)
                        Success md -> do
                            c <- liftIO $ registerClient md
                            -- Cheat here. Add the extra fields to the
                            -- original JSON object
                            json . Object $ HM.union o $ HM.fromList [("client_id", String $ clientId c), ("client_secret", String . fromJust $ clientSecret c), ("registration_access_token", String "this_is_a_worthless_fake"), ("registration_client_uri", String $ T.concat [issuer, "/client/", clientId c])]
        get "/logout" $ logout

        get "/.well-known/openid-configuration" $ json $ toJSON config

        get "/.well-known/jwks" $ json $ toJSON $ keySet


redirectFull u = do
    baseUrl <- brochM $ gets issuerUrl
    let location = L.fromStrict $ T.concat [baseUrl, u]
    liftIO $ putStrLn $ "Redirecting to: " ++ show location
    redirect location

authorizationHandler csKey getClient createAuthorization getApproval createAccessToken createIdToken = do
    -- request >>= debug . W.rawQueryString

    user <- getAuthId csKey
    env  <- fmap toMap params
    now  <- liftIO getPOSIXTime

    response <- processAuthorizationRequest getClient (liftIO generateCode) createAuthorization resourceOwnerApproval createAccessToken createIdToken user env now
    case response of
        Left e    -> evilClientError e
        Right url -> redirect $ L.fromStrict url

  where
    evilClientError err = status badRequest400 >> text (L.pack $ show err)

    fakeApproval _ _ requestedScope _ = return requestedScope

    resourceOwnerApproval uid client requestedScope now = do
        -- Try to load a previous approval
        maybeApproval <- liftIO $ getApproval uid client now
        case maybeApproval of
            -- TODO: Check scope overlap and allow asking for extra scope
            -- not previously granted
            Just (Approval _ _ scope _) -> return (scope \\ requestedScope)
            -- Nothing exists: Redirect to approval handler with scopes and client id
            Nothing -> do
                let query = renderSimpleQuery True [("client_id", TE.encodeUtf8 $ clientId client), ("scope", TE.encodeUtf8 $ T.intercalate " " (map scopeName requestedScope))]
                cacheLocation csKey
                redirectFull $ TE.decodeUtf8 $ B.concat ["/approval", query]

tokenHandler getClient getAuthorization authenticateResourceOwner createAccessToken createIdToken decodeRefreshToken = do
    client <- basicAuthClient getClient
    case client of
        Left (st, err) -> status st >> text err
        Right c        -> do
            env  <- fmap toMap params
            now  <- liftIO getPOSIXTime
            resp <- processTokenRequest env c now getAuthorization authenticateResourceOwner createAccessToken createIdToken decodeRefreshToken
            case resp of
                Left bad -> status badRequest400 >> json (toJSON bad)
                Right tr -> json $ toJSON tr


debug :: (MonadIO m, Show a) => a -> m ()
debug = liftIO . putStrLn . show

loginPage = H.html $ do
    H.head $ do
      H.title "Login."
    H.body $ do
        H.form H.! method "post" H.! action "/login" $ do
            H.input H.! type_ "text" H.! name "username"
            H.input H.! type_ "password" H.! name "password"
            H.input H.! type_ "submit" H.! value "Login"

--approvalPage :: Client -> [Text] -> Int64 -> H.Html
approvalPage client scopes now = H.docTypeHtml $ H.html $ do
    H.head $ do
      H.title "Approvals"
    H.body $ do
        H.h2 $ "Authorization Approval Request"
        H.form H.! method "post" H.! action "/approval" $ do
            H.input H.! type_ "hidden" H.! name "client_id" H.! value (H.toValue (clientId client))
            H.label H.! for "expiry" $ "Expires after"
            H.select H.! name "expiry" $ do
                H.option H.! value (H.toValue oneDay) H.! selected "" $ "One day"
                H.option H.! value (H.toValue oneWeek) $ "One week"
                H.option H.! value (H.toValue oneMonth) $ "30 days"
            forM_ scopes $ \s -> do
                H.input H.! type_ "checkBox" H.! name "scope" H.! value (H.toValue s) H.! checked ""
                H.toHtml s
                H.br

            H.input H.! type_ "submit" H.! value "Approve"
  where
    aDay    = round posixDayLength :: Int64
    oneDay  = now + aDay
    oneWeek = now + 7*aDay
    oneMonth = now + 30*aDay


logout = clearCookie "bsid"

getAuthId key = do
    uid <- getEncryptedCookie key "bsid"
    case uid of
        Just u  -> return (TE.decodeUtf8 u)
        Nothing -> cacheLocation key >> redirectFull "/login"

clearCachedLocation = clearCookie "loc"

cacheLocation key = do
    r <- request
    setEncryptedCookie key "loc" $ B.concat [W.rawPathInfo r, W.rawQueryString r]

getCachedLocation key defaultUrl = getEncryptedCookie key "loc" >>=
                                      return . (maybe defaultUrl (L.fromStrict . TE.decodeUtf8))


makeCookie :: B.ByteString -> B.ByteString -> SetCookie
makeCookie n v = def { setCookieName = n, setCookieValue = v, setCookieHttpOnly = True, setCookiePath = Just "/" }

renderSetCookie' :: SetCookie -> Text
renderSetCookie' = LE.decodeUtf8 . toLazyByteString . renderSetCookie

getEncryptedCookie key n = getCookie n >>= return . join .fmap (CS.decrypt key)

setEncryptedCookie key n v = do
    v' <- liftIO $ CS.encryptIO key v
    setCookie n v'

setCookie n v = setHeader "Set-Cookie" $ renderSetCookie' $ makeCookie n v

clearCookie n = setHeader "Set-Cookie" $ renderSetCookie' $ (makeCookie n "") { setCookieMaxAge = Just 0 }

getCookie name = do
    cookies <- fmap (fmap (parseCookies . BL.toStrict . LE.encodeUtf8)) $ header "Cookie"
    case cookies of
        Nothing -> return Nothing
        Just cs -> return $ lookup name cs


toMap :: [(Text, Text)] -> Map.Map T.Text [T.Text]
toMap = Map.unionsWith (++) . map (\(x, y) -> Map.singleton (L.toStrict x) [(L.toStrict y)])

basicAuthClient getClient = do
    r <- request
    case basicAuthCredentials r of
        Left  msg           -> return $ Left (unauthorized401, msg)
        Right (cid, secret) -> do
            client <- getClient cid
            return $ maybe (Left (forbidden403, "Authentication failed")) Right $ client >>= validateSecret secret

-- TODO: Use Byteable comparison
validateSecret :: T.Text -> Client -> Maybe Client
validateSecret secret client = clientSecret client >>= \s ->
                                  if secret == s
                                  then Just client
                                  else Nothing

-- | Extract the Basic authentication credentials from a WAI request.
-- Returns an error message if the header is missing or cannot be decoded.
basicAuthCredentials :: W.Request -> Either Text (T.Text, T.Text)
basicAuthCredentials r = do
    authzHdr <- maybe (Left "Authentication required") return $ lookup hAuthorization $ W.requestHeaders r
    maybe (Left "Invalid authorization header") return $ decodeHeader authzHdr
  where
    decodeHeader h = case B.split ' ' h of
                       ["Basic", b] -> either (const Nothing) creds $ B64.decode b
                       _            -> Nothing
    creds bs = case fmap (T.break (== ':')) $ TE.decodeUtf8' bs of
                 Left _       -> Nothing
                 Right (u, p) -> if T.length p == 0
                                 then Nothing
                                 else Just (u, T.tail p)

