{-# LANGUAGE OverloadedStrings, ScopedTypeVariables, RecordWildCards #-}

module Broch.Server where

import           Control.Error hiding (err)
import           Control.Exception (SomeException, catch)
import           Control.Monad.State.Strict
import           Crypto.Random (getRandomBytes, MonadRandom)
import           Data.Aeson as A hiding (json)
import           Data.ByteArray.Encoding
import           Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Char8 as B
import qualified Data.HashMap.Strict as HM
import           Data.Int (Int64)
import           Data.List (intersect, (\\))
import qualified Data.Map.Strict as Map
import           Data.Maybe (fromJust)
import           Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.IO as TIO
import           Data.Text.Read (decimal)
import qualified Data.Text.Encoding as TE
import           Data.Time.Clock
import           Data.Time.Clock.POSIX
import           Jose.Jwk
import           Jose.Jwa
import           Jose.Jwt (Jwt(..), IntDate(..))
import           Network.HTTP.Types
import qualified Network.Wai as W
import           Network.HTTP.Conduit (httpLbs, newManager, managerConnCount, redirectCount, tlsManagerSettings, parseUrl, responseBody)
import           Text.Blaze.Html (Html)
import           Web.Routing.TextRouting

import           Broch.Model hiding (Email)
import           Broch.OAuth2.Authorize
import           Broch.OAuth2.ClientAuth
import           Broch.OAuth2.Token
import           Broch.OpenID.Discovery (mkOpenIDConfiguration)
import           Broch.OpenID.IdToken
import           Broch.OpenID.Registration
import           Broch.OpenID.UserInfo
import qualified Broch.Server.BlazeUI as UI
import           Broch.Server.Config
import           Broch.Server.Internal
import           Broch.Token
import           Broch.URI

data Usr = Usr SubjectId UTCTime deriving (Show, Read)

instance Subject Usr where
    subjectId (Usr s _) = s
    authTime  (Usr _ t) = utcTimeToPOSIXSeconds t

userIdKey :: ByteString
userIdKey = "_uid"

requestIdKey :: Text
requestIdKey = "_rid"

-- | Renders a login page using the built-in UI.
defaultLoginPage :: Maybe Text -> Html
defaultLoginPage = UI.loginPage

-- | Renders an approval page using the built-in web UI.
defaultApprovalPage :: Client -> [Scope] -> Int64 -> Html
defaultApprovalPage = UI.approvalPage

-- | Standard handler for login GET and POST.
-- A GET request will render the login page, a POST will attempt to authenticate
-- the user with the supplied username and password information.
passwordLoginHandler
    :: (Maybe Text -> Html)
    -- ^ A function which renders the login page
    -> AuthenticateResourceOwner IO
    -- ^ The function to process an authentication request
    -> Handler ()
passwordLoginHandler loginPage authenticate = httpMethod >>= \m -> case m of
    GET  -> do
        rid <- maybeQueryParam requestIdKey
        html (loginPage rid)
    POST -> do
        uid  <- postParam "username"
        pwd  <- postParam "password"
        rid  <- fmap TE.encodeUtf8 <$> maybePostParam requestIdKey
        user <- liftIO $ authenticate uid pwd

        case user of
            Nothing -> redirect $ maybe "/login" (\r -> B.concat ["/login?_rid=", r]) rid
            Just u  -> do
                now <- liftIO getCurrentTime
                sessionInsert userIdKey (B.pack $ show $ Usr u now)
                maybe (return ()) (sessionInsert (TE.encodeUtf8 requestIdKey)) rid
                redirect =<< getCachedLocation "/home"
    _    -> methodNotAllowed

-- | Returns the current user and whether they were authenticated during the current authorization request.
-- In order to satisfy the "prompt=login" situation, the request is tagged with a random parameter which is also
-- passed as a parameter to the login URL and rendered in the login page. When logging in successfully, the
-- tag (if present) is stored in the session.
--
-- When this function is called, and the session contains a user, the current request can be checked to
-- see if it contains a parameter with the same name as the request ID cached in the session. If it does, the
-- current request has the same ID as the one which prompted the login and @True@ is returned as the second
-- parameter in the tuple.
authenticatedSubject :: Handler (Maybe (Usr, Bool))
authenticatedSubject = do
    usr  <- sessionLookup userIdKey
    rid1 <- sessionLookup (TE.encodeUtf8 requestIdKey)
    rid2 <- case rid1 of
        Nothing -> return Nothing
        Just r  -> maybeQueryParam (TE.decodeUtf8 r)
    return $ case usr of
        Nothing -> Nothing
        Just u  -> Just (unpackUsr u, isJust rid2)
  where
    unpackUsr = read . T.unpack . TE.decodeUtf8

authenticateSubject :: Handler ()
authenticateSubject = do
    bs <- getRandomBytes 8 :: Handler ByteString
    let tag = convertToBase Base64URLUnpadded bs
    location <- request >>= \r -> return $ B.concat [W.rawPathInfo r, W.rawQueryString r, "&", tag, "="]
    cacheLocationUrl location
    sessionDelete userIdKey
    redirect $ B.concat ["/login?_rid=", tag]

-- | Creates the server routing table from a configuration.
--
-- This is where everything is plugged in to build the
brochServer :: (Subject s)
    => Config IO s
    -> (Client -> [Scope] -> Int64 -> Html)
    -> Handler (Maybe (s, Bool))
    -> Handler ()
    -> RoutingTree (Handler ())
brochServer config@Config {..} approvalPage authenticatedUser authenticateUser =
    foldl (\tree (r, h) -> addToRoutingTree r h tree) emptyRoutingTree
        [ ("/oauth/authorize",  authorizationHandler)
        , ("/oauth/token",      tokenHandler)
        , ("/approval",         approvalHandler)
        , ("/connect/userinfo", userInfoHandler)
        , ("/connect/register", registrationHandler)
        , (".well-known/openid-configuration", json oidConfig)
        , (".well-known/jwks",  liftIO (publicKeys keyRing) >>= json . JwkSet )
        ]
  where
    -- TODO: Sort this mess out
    loadClient = liftIO . getClient
    createAuthz  cd s cl t scps mn mr = liftIO $ createAuthorization cd s cl t scps mn mr
    authenticateRO u p = liftIO $ authenticateResourceOwner u p
    createAccess  c gt scps now  = liftIO . createAccessToken c gt scps now
    decodeRefresh c t = liftIO $ decodeRefreshToken c t
    oidConfig = mkOpenIDConfiguration config

    createIdToken uid aTime client nons now code aToken = do
        let claims  = idTokenClaims issuerUrl client nons (sectorSubjectId uid (sectorIdentifier client)) aTime now code aToken
            rpKeys  = fromMaybe [] (clientKeys client)
            csKey   = fmap (\k -> SymmetricJwk (TE.encodeUtf8 k) Nothing Nothing Nothing) (clientSecret client)
            prefs   = fromMaybe (AlgPrefs (Just RS256) NotEncrypted) $ idTokenAlgs client

        sigKeys <- liftIO (signingKeys keyRing)
        createJwtToken (maybe sigKeys (: sigKeys) csKey) rpKeys prefs claims


    registerClient c = do
        cid <- generateCode
        sec <- generateCode
        -- TODO: Avoid creating new mgr each call
        mgr <- newManager tlsManagerSettings { managerConnCount = 1 }
        let retrieveJwks :: Text -> ExceptT RegistrationError IO [Jwk]
            retrieveJwks uri = do
                jsn <- httpGet uri
                let jwkError s = T.pack ("Failed to decode retrieved client JWKs: " ++ s)
                either (throwE . InvalidMetaData . jwkError) (return . keys) (eitherDecode' jsn)

            checkSectorIdentifierUri =
                case sector_identifier_uri c of
                    Just uri -> do
                        jsn <- httpGet uri
                        let uriError s = T.pack ("Failed to decode sector_identifier_uri contents: " ++ s)
                        ruris <- either (throwE . InvalidMetaData . uriError) return (eitherDecode' jsn :: Either String [Text])
                        unless (foldl (\acc u -> acc && u `elem` ruris) True (redirect_uris c))
                            (throwE (InvalidMetaData "Registered redirect_uri values do not match sector_identifier_uri contents"))

                    Nothing  -> return ()

            httpGet uri = ExceptT $ do
                req <- parseUrl (T.unpack uri)
                Right . responseBody <$> httpLbs req { redirectCount = 0 } mgr
                `catch` \(e :: SomeException) -> do
                    let errMsg = T.concat ["Failed to retrieve URI '", uri, "': ", T.pack (show e)]
                    TIO.putStrLn errMsg
                    return $ Left (InvalidMetaData errMsg)

        -- retrieve client keys if URI set
        runExceptT $ do
            client <- hoistEither $ makeClient oidConfig (TE.decodeUtf8 cid) (TE.decodeUtf8 sec) c
            checkSectorIdentifierUri
            ks     <- case clientKeysUri client of
                Just uri -> Just <$> retrieveJwks uri
                Nothing  -> return $ clientKeys client
            liftIO $ createClient client { clientKeys = ks }
            return client

    registrationHandler = do
        b <- body
        let invalidMetaData msg = status badRequest400 >> json (InvalidMetaData msg)
        case eitherDecode' b of
            Left err -> invalidMetaData $ T.pack ("Client registration data was not valid JSON: " ++ err)
            Right v@(Object o) -> case fromJSON v of
                Error e    -> invalidMetaData $ T.pack ("Client registration data does not match expected format: " ++ e)
                Success md -> do
                    reg <- liftIO $ registerClient md
                    case reg of
                        -- Cheat here. Add the extra fields to the
                        -- original JSON object
                        Right c -> do
                            status created201
                            json . Object $ HM.union o $ HM.fromList [("client_id", String $ clientId c), ("client_secret", String . fromJust $ clientSecret c)]
                        Left  e -> status badRequest400 >> json e
            Right _            -> invalidMetaData "Client registration data must be a JSON Object"

    userInfoHandler = withBearerToken decodeAccessToken [OpenID] $ \g -> do
        -- TODO: Handle missing client situation
        Just client <- loadClient (granteeId g)
        userInfo    <- liftIO $ getUserInfo (fromJust (granterId g)) client

        case userInfo of
            Nothing -> status internalServerError500 >> text "User not found"
            Just ui -> claimsResponse client $ scopedClaims (grantScope g) ui

    claimsResponse client claims =
        case userInfoAlgs client of
            Nothing -> json claims
            Just (AlgPrefs Nothing NotEncrypted) -> json claims
            Just a  -> do
                sigKeys <- liftIO (signingKeys keyRing)
                jwtRes <- liftIO $ createJwtToken sigKeys (fromMaybe [] (clientKeys client)) a claims
                case jwtRes of
                    Right (Jwt jwt) -> setHeader hContentType "application/jwt" >> rawBytes (BL.fromStrict jwt)
                    Left  e         -> status internalServerError500 >> text (T.pack ("Failed to create user info JWT" ++ show e))

    approvalHandler = withAuthenticatedUser authenticatedUser $ \s -> httpMethod >>= \m -> case m of
        GET -> do
            now    <- liftIO getPOSIXTime
            Just client <- queryParam "client_id" >>= loadClient
            scope  <- fmap (map scopeFromName . T.splitOn " ") (queryParam "scope")
            html $ approvalPage client scope (round now)

        POST -> do
            clntId    <- postParam "client_id"
            expiryTxt <- postParam "expiry"
            scpParams <- fmap (Map.lookup "scope") postParams
            requested <- fmap (Map.lookup "requested_scope") postParams

            let Right (expiry, _) = decimal expiryTxt
                uid = subjectId s
                approvedScope  = maybe [] (map scopeFromName) scpParams
                requestedScope = maybe [] (map scopeFromName) requested
                deniedScope    = requestedScope \\ approvedScope
                approval = Approval uid clntId approvedScope deniedScope (IntDate $ fromIntegral (expiry :: Int64))
            _ <- liftIO $ createApproval approval
            l <- getCachedLocation "/uhoh"
            clearCachedLocation
            -- Redirect to authorization doesn't seem to work with oictests
            redirect l

        _    -> methodNotAllowed

    authorizationHandler = do
        -- request >>= debug . W.rawQueryString
        env  <- queryParams

        now  <- liftIO getPOSIXTime

        response <- processAuthorizationRequest responseTypesSupported loadClient generateCode createAuthz resourceOwnerApproval createAccess createIdToken authenticatedUser env now
        case response of
            Right url                      -> redirectExternal (renderURI url)
            Left (MaliciousClient e)       -> evilClientError e
            Left (ClientRedirectError url) -> redirectExternal (renderURI url)
            Left RequiresAuthentication    -> authenticateUser

      where
        evilClientError e = status badRequest400 >> text (T.pack $ show e)

        resourceOwnerApproval :: Subject s => s -> Broch.Model.Client -> [Scope] -> POSIXTime -> Handler [Scope]
        resourceOwnerApproval u client requestedScope now = do
            -- Try to load a previous approval
            maybeApproval <- liftIO $ getApproval (subjectId u) client now

            let redirectToApprovalsPage = do
                    let query = renderSimpleQuery True [("client_id", TE.encodeUtf8 $ clientId client), ("scope", TE.encodeUtf8 $ formatScope requestedScope)]
                    cacheLocation
                    redirect $ B.concat ["/approval", query]

            case maybeApproval of
                Just (Approval _ _ scope denied _) -> do
                    -- Check if enough scope was approved in previous request
                    -- or if the extra was previously denied. If so, only return
                    -- the previously approved scope.
                    let overlap = (scope ++ denied) `intersect` requestedScope
                    if overlap == requestedScope
                        then return scope
                        else redirectToApprovalsPage
                Nothing -> redirectToApprovalsPage

    tokenHandler = do
        r <- request
        let authzHdr = lookup hAuthorization $ W.requestHeaders r
        env    <- postParams
        now    <- liftIO getPOSIXTime
        clientAuth <- authenticateClient env authzHdr now loadClient
        case clientAuth of
            Left InvalidClient401 -> status unauthorized401 >> setHeader "WWW-Authenticate" "Basic" >> json (toJSON InvalidClient401)
            Left bad              -> status badRequest400   >> json (toJSON bad)
            Right client -> do
                resp <- processTokenRequest env client now (liftIO . getAuthorization) authenticateRO createAccess createIdToken decodeRefresh
                case resp of
                    Right tokenResponse     -> json $ toJSON tokenResponse
                    Left  (InternalError _) -> status internalServerError500 >> text "Internal error"
                    Left  bad               -> status badRequest400 >> json (toJSON bad)

debug :: (MonadIO m, Show a) => a -> m ()
debug = liftIO . print

-- Create a random authorization code
generateCode :: MonadRandom m => m ByteString
generateCode = do
    code <- getRandomBytes 8
    return (convertToBase Base16 (code :: ByteString))

clearCachedLocation :: Handler ()
clearCachedLocation = sessionDelete "_loc"

-- | Cache the current request URL
cacheLocation :: Handler ()
cacheLocation = request >>= \r -> cacheLocationUrl $ B.concat [W.rawPathInfo r, W.rawQueryString r]

-- | Cache an explicit URL
cacheLocationUrl :: ByteString -> Handler ()
cacheLocationUrl = sessionInsert "_loc"

-- | Retrieve the currently cached location, providing a default URL for use if none is found.
getCachedLocation :: ByteString -> Handler ByteString
getCachedLocation defaultUrl = fromMaybe defaultUrl <$> sessionLookup "_loc"


withAuthenticatedUser :: (Subject s)
    => Handler (Maybe (s, Bool))
    -> (s -> Handler ())
    -> Handler ()
withAuthenticatedUser currentUser f = do
    user <- currentUser
    case user of
        Nothing -> status forbidden403 >> text "Unauthorized"
        Just (u, _) -> f u

withBearerToken :: (B.ByteString -> IO (Maybe AccessGrant))
                -> [Scope]
                -> (AccessGrant -> Handler ())
                -> Handler ()
withBearerToken decodeToken requiredScope f = do
    t <- bearerToken
    g <- liftIO $ decodeToken t
    maybe unauthorized runWithToken g
  where
    unauthorized = status unauthorized401 >> setHeader "WWW-Authenticate" "Bearer" >> complete

    bearerToken = do
        r  <- request
        ps <- postParams
        case msum [bearerHeader r, bearerBody ps] of
            Just t  -> return t
            Nothing -> unauthorized

    bearerBody ps = case Map.lookup "access_token" ps of
        Just [t] -> Just (TE.encodeUtf8 t)
        _        -> Nothing

    bearerHeader r = do
        h <- lookup hAuthorization $ W.requestHeaders r
        case B.split ' ' h of
            ["Bearer", t] -> Just t
            _             -> Nothing

    runWithToken g@(AccessGrant _ _ _ scp (IntDate ex)) = do
        -- Check expiry and scope
        now <- liftIO getPOSIXTime
        unless (ex > now) $ invalidToken "Token has expired"
        unless (requiredScope `intersect` scp == requiredScope) $ insufficientScope requiredScope
        f g

    invalidToken msg = do
        status unauthorized401
        setHeader "WWW-Authenticate" $ B.concat ["Bearer, error=\"invalid_token\", error_description=\"", msg, "\""]
        complete

    insufficientScope s = do
        status forbidden403
        setHeader "WWW-Authenticate" $ B.concat ["Bearer, error=\"insufficient_scope\", scope=\"", TE.encodeUtf8 $ formatScope s, "\""]
        complete
