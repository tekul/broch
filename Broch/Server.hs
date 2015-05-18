{-# LANGUAGE OverloadedStrings, ScopedTypeVariables, RecordWildCards #-}

module Broch.Server where

import           Control.Applicative
import           Control.Error hiding (err)
import           Control.Exception (SomeException, catch)
import           Control.Monad.State.Strict
import           Data.Aeson as A hiding (json)
import           Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Base16 as Hex
import qualified Data.HashMap.Strict as HM
import           Data.Int (Int64)
import           Data.List (intersect)
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
import           Network.HTTP.Conduit (simpleHttp)
import           Web.Routing.TextRouting

import           Broch.Model hiding (Email)
import           Broch.OAuth2.Authorize
import           Broch.OAuth2.ClientAuth
import           Broch.OAuth2.Token
import           Broch.OpenID.Discovery (mkOpenIDConfiguration)
import           Broch.OpenID.IdToken
import           Broch.OpenID.Registration
import           Broch.OpenID.UserInfo
import           Broch.Random
import           Broch.Server.BlazeUI
import           Broch.Server.Config
import           Broch.Server.Internal
import           Broch.Token

data Usr = Usr SubjectId UTCTime deriving (Show, Read)

instance Subject Usr where
    subjectId (Usr s _) = s
    authTime  (Usr _ t) = utcTimeToPOSIXSeconds t

userIdKey :: ByteString
userIdKey = "_uid"

passwordLoginHandler :: AuthenticateResourceOwner IO -> Handler ()
passwordLoginHandler authenticate = httpMethod >>= \m -> case m of
    GET  -> html loginPage
    POST -> do
        uid  <- postParam "username"
        pwd  <- postParam "password"
        user <- liftIO $ authenticate uid pwd

        case user of
            Nothing -> redirect "/login"
            Just u  -> do
                now <- liftIO getCurrentTime
                sessionInsert userIdKey (B.pack $ show $ Usr u now)
                redirect =<< getCachedLocation "/home"
    _    -> methodNotAllowed

authenticatedSubject :: Handler Usr
authenticatedSubject = do
    usr <- sessionLookup userIdKey
    case usr of
        Just u  -> return (read $ T.unpack $ TE.decodeUtf8 u :: Usr)
        Nothing -> cacheLocation >> redirect "/login"


brochServer :: (Subject s) => Config IO s -> Handler s -> RoutingTree (Handler ())
brochServer config@Config {..} authenticatedUser =
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
{--

        -- SCIM API

        post   "/Users" $ do
            -- parse JSON request to SCIM user
            -- store user
            -- create meta and etag
            -- re-read user and return
            b <- body
            case eitherDecode b of
                Left err -> status badRequest400 >> text (L.pack err)
                Right scimUser ->
                    -- TODO: Check data, username etc
                    liftIO $ createUser scimUser

        get    "/Users/:uid" undefined
        put    "/Users/:uid" undefined
        patch  "/Users/:uid" $ status notImplemented501
        delete "/Users/:uid" undefined
        post   "/Groups" undefined
        get    "/Groups/:uid" undefined
        put    "/Groups/:uid" undefined
        patch  "/Groups/:uid" undefined
        delete "/Groups/:uid" undefined
--}
    -- TODO: Sort this mess out
    loadClient = liftIO . getClient
    createAuthz  cd s cl t scps mn mr = liftIO $ createAuthorization cd s cl t scps mn mr
    authenticateRO u p = liftIO $ authenticateResourceOwner u p
    createAccess  c gt scps now  = liftIO . createAccessToken c gt scps now
    decodeRefresh c t = liftIO $ decodeRefreshToken c t
    oidConfig = mkOpenIDConfiguration config

    createIdToken uid aTime client nons now code aToken = do
        let claims  = idTokenClaims issuerUrl client nons uid aTime now code aToken
            rpKeys  = fromMaybe [] (clientKeys client)
            csKey   = fmap (\k -> SymmetricJwk (TE.encodeUtf8 k) Nothing Nothing Nothing) (clientSecret client)
            prefs   = fromMaybe (AlgPrefs (Just RS256) NotEncrypted) $ idTokenAlgs client

        sigKeys <- liftIO (signingKeys keyRing)
        liftIO $ withCPRG $ \g -> createJwtToken g (maybe sigKeys (: sigKeys) csKey) rpKeys prefs claims

    registerClient c = do
        cid <- generateCode
        sec <- generateCode
        let retrieveJwks :: Text -> EitherT RegistrationError IO [Jwk]
            retrieveJwks uri = do
                jsn <- httpGet (T.unpack uri)
                let jwkError s = T.pack ("Failed to decode retrieved client JWKs: " ++ s)
                either (left . InvalidMetaData . jwkError) (right . keys) (eitherDecode' jsn)

            checkSectorIdentifierUri =
                case sector_identifier_uri c of
                    Just uri -> do
                        jsn <- httpGet (T.unpack uri)
                        let uriError s = T.pack ("Failed to decode sector_identifier_uri contents: " ++ s)
                        ruris <- either (left . InvalidMetaData . uriError) right (eitherDecode' jsn :: Either String [Text])
                        unless (foldl (\acc u -> acc && u `elem` ruris) True (redirect_uris c))
                            (left (InvalidMetaData "Registered redirect_uri values do not match sector_identifier_uri contents"))

                    Nothing  -> return ()

            -- TODO: Better HTTP client code. No redirect following
            httpGet uri = EitherT . liftIO $ (Right <$> simpleHttp uri)
                `catch` \(e :: SomeException) -> do
                    let errMsg = T.pack ("Failed to retrieve URI '" ++ uri ++ "': " ++ show e)
                    TIO.putStrLn errMsg
                    return $ Left (InvalidMetaData errMsg)

        -- retrieve client keys if URI set
        runEitherT $ do
            client <- hoistEither $ makeClient (TE.decodeUtf8 cid) (TE.decodeUtf8 sec) c
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
                            json . Object $ HM.union o $ HM.fromList [("client_id", String $ clientId c), ("client_secret", String . fromJust $ clientSecret c), ("registration_access_token", String "this_is_a_worthless_fake"), ("registration_client_uri", String $ T.concat [issuerUrl, "/client/", clientId c])]
                        Left  e -> status badRequest400 >> json e
            Right _            -> invalidMetaData "Client registration data must be a JSON Object"

    userInfoHandler = withBearerToken decodeAccessToken [OpenID] $ \g -> do
        -- TODO: Handle missing client situation
        Just client <- loadClient (granteeId g)
        userInfo    <- liftIO $ getUserInfo (fromJust (granterId g)) client
        let claims  =  scopedClaims (grantScope g) userInfo

        case userInfoAlgs client of
            Nothing -> json claims
            Just (AlgPrefs Nothing NotEncrypted) -> json claims
            Just a  -> do
                sigKeys <- liftIO (signingKeys keyRing)
                jwtRes <- liftIO $ withCPRG $ \rng -> createJwtToken rng sigKeys (fromMaybe [] (clientKeys client)) a claims
                case jwtRes of
                    Right (Jwt jwt) -> setHeader hContentType "application/jwt" >> rawBytes (BL.fromStrict jwt)
                    Left  e         -> status internalServerError500 >> text (T.pack ("Failed to create user info JWT" ++ show e))

    approvalHandler = httpMethod >>= \m -> case m of
        GET -> do
            _      <- authenticatedUser
            now    <- liftIO getPOSIXTime
            Just client <- queryParam "client_id" >>= loadClient
            scope  <- liftM (T.splitOn " ") $ queryParam "scope"
            html $ approvalPage client scope (round now)

        POST -> do
            uid       <- subjectId <$> authenticatedUser
            clntId    <- postParam "client_id"
            expiryTxt <- postParam "expiry"
            scpParams <- liftM (Map.lookup "scope") postParams

            let Right (expiry, _) = decimal expiryTxt
                scope    = maybe [] (map scopeFromName) scpParams
                approval = Approval uid clntId scope (IntDate $ fromIntegral (expiry :: Int64))
            _ <- liftIO $ createApproval approval
            l <- getCachedLocation "/uhoh"
            clearCachedLocation
            -- Redirect to authorization doesn't seem to work with oictests
            redirect l

        _    -> methodNotAllowed

    authorizationHandler = do
        -- request >>= debug . W.rawQueryString

        user <- authenticatedUser
        env  <- queryParams
        now  <- liftIO getPOSIXTime

        response <- processAuthorizationRequest loadClient (liftIO generateCode) createAuthz resourceOwnerApproval createAccess createIdToken user env now
        case response of
            Right url                      -> redirectExternal $ TE.encodeUtf8 url
            Left (MaliciousClient e)       -> evilClientError e
            Left (ClientRedirectError url) -> redirectExternal $ TE.encodeUtf8 url
            Left RequiresReauthentication  -> cacheLocation >> redirect "/login"

      where
        evilClientError e = status badRequest400 >> text (T.pack $ show e)

        resourceOwnerApproval :: Subject s => s -> Broch.Model.Client -> [Scope] -> POSIXTime -> Handler [Scope]
        resourceOwnerApproval u client requestedScope now = do
            -- Try to load a previous approval

            maybeApproval <- liftIO $ getApproval (subjectId u) client now

            case maybeApproval of
                -- TODO: Check scope overlap and allow asking for extra scope
                -- not previously granted
                Just (Approval _ _ scope _) -> return $ scope `intersect` requestedScope
                -- Nothing exists: Redirect to approval handler with scopes and client id
                Nothing -> do
                    let query = renderSimpleQuery True [("client_id", TE.encodeUtf8 $ clientId client), ("scope", TE.encodeUtf8 $ formatScope requestedScope)]
                    cacheLocation
                    redirect $ B.concat ["/approval", query]

    tokenHandler = do
        r <- request
        let authzHdr = lookup hAuthorization $ W.requestHeaders r
        env    <- postParams
        now    <- liftIO getPOSIXTime
        clientAuth <- authenticateClient env authzHdr now loadClient (liftIO . withCPRG)
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
generateCode :: IO ByteString
generateCode = liftM Hex.encode $ randomBytes 8

clearCachedLocation :: Handler ()
clearCachedLocation = sessionDelete "_loc"

cacheLocation :: Handler ()
cacheLocation = request >>= \r -> sessionInsert "_loc" $ B.concat [W.rawPathInfo r, W.rawQueryString r]

getCachedLocation :: ByteString -> Handler ByteString
getCachedLocation defaultUrl = liftM (fromMaybe defaultUrl) $ sessionLookup "_loc"


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
