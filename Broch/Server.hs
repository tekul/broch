{-# LANGUAGE OverloadedStrings, ScopedTypeVariables #-}

module Broch.Server where

import           Control.Applicative
import           Control.Error hiding (err)
import           Control.Exception (SomeException, catch)
import           Control.Monad.State.Strict
import qualified Crypto.BCrypt as BCrypt
import qualified Crypto.PubKey.RSA as RSA
import           Data.Aeson as A hiding (json)
import qualified Data.ByteString.Base64 as B64
import           Data.ByteString (ByteString)
import qualified Data.ByteString.Lazy as BL
import qualified Data.ByteString.Char8 as B
import           Data.Default.Generics as DD
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
import           Data.UUID (toString)
import           Data.UUID.V4
import           Database.Persist.Sql (ConnectionPool, runMigrationSilent, runSqlPersistMPool)
import           Jose.Jwk
import           Jose.Jwa
import           Jose.Jwt (Jwt(..), IntDate(..))
import           Network.HTTP.Types
import qualified Network.Wai as W
import           Network.HTTP.Conduit (simpleHttp)
import qualified Text.Blaze.Html5 as H
import           Text.Blaze.Html5.Attributes hiding (scope, id)

import           Broch.Model hiding (Email)
import           Broch.OAuth2.Authorize
import           Broch.OAuth2.ClientAuth
import           Broch.OAuth2.Token
import           Broch.OpenID.Discovery (defaultOpenIDConfiguration)
import           Broch.OpenID.IdToken
import           Broch.OpenID.Registration
import           Broch.OpenID.UserInfo
import qualified Broch.Persist as BP
import           Broch.Random
import           Broch.Scim
import           Broch.Server.Internal
import           Broch.Token

testClients :: [Client]
testClients =
    [ Client "admin" (Just "adminsecret") [ClientCredentials, AuthorizationCode] ["http://admin"]              300 300 [] True ClientSecretBasic Nothing Nothing Nothing Nothing Nothing Nothing
    , Client "cf"    Nothing              [ResourceOwner]                        ["http://cf.com"]             300 300 [] True ClientAuthNone Nothing Nothing Nothing Nothing Nothing Nothing
    , Client "app"   (Just "appsecret")   [AuthorizationCode, Implicit, RefreshToken]  ["http://localhost:8080/app"] 300 300 [OpenID, CustomScope "scope1", CustomScope "scope2"] False ClientSecretBasic Nothing Nothing Nothing Nothing Nothing Nothing
    ]

testUsers :: [ScimUser]
testUsers =
    [ DD.def
        { scimUserName = "cat"
        , scimPassword = Just "cat"
        , scimName     = Just $ DD.def {nameFormatted = Just "Tom Cat", nameFamilyName = Just "Cat", nameGivenName = Just "Tom"}
        , scimEmails = Just [DD.def {emailValue = "cat@example.com"}]
        }
    , DD.def { scimUserName = "dog", scimPassword = Just "dog" }
    ]


data Usr = Usr SubjectId UTCTime deriving (Show, Read)

instance Subject Usr where
    subjectId (Usr s _) = s
    authTime  (Usr _ t) = utcTimeToPOSIXSeconds t

testBroch :: Text -> ConnectionPool -> IO Router
testBroch issuer pool = do
    _ <- runSqlPersistMPool (runMigrationSilent BP.migrateAll) pool
    mapM_ (\c -> runSqlPersistMPool (BP.createClient c) pool) testClients
    -- Create everything we need for the oauth endpoints
    -- First we need an RSA key for signing tokens
    let runDB = flip runSqlPersistMPool pool
    let getClient = liftIO . runDB . BP.getClientById
    let createAuthorization code usr clnt now scp n uri = liftIO $ runDB $
                            BP.createAuthorization code usr clnt now scp n uri

    let getAuthorization = liftIO . runDB . BP.getAuthorizationByCode
    let authenticateResourceOwner username password = do
            u <- liftIO . runDB $ BP.getUserByUsername username
            case u of
                Nothing          -> return Nothing
                Just (uid, hash) -> return $ if BCrypt.validatePassword (TE.encodeUtf8 hash) (TE.encodeUtf8 password)
                                                 then Just uid
                                                 else Nothing

    let saveApproval a = runDB $ BP.createApproval a
    (kPub, kPr) <- withCPRG $ \g -> RSA.generate g 64 65537
    let createAccessToken = createJwtAccessToken $ RSA.private_pub kPr
    let decodeRefreshToken _ jwt = decodeJwtRefreshToken kPr (TE.encodeUtf8 jwt)
    let getApproval usr clnt now = runDB $ BP.getApproval (subjectId usr) (clientId clnt) now
    let publicKeySet = JwkSet [RsaPublicJwk kPub (Just "brochkey") Nothing Nothing]
        privateKey   = RsaPrivateJwk kPr (Just "brochkey") Nothing Nothing
        opSigKeys    = [privateKey]
    let config = defaultOpenIDConfiguration issuer
    let registerClient :: ClientMetaData -> IO (Either RegistrationError Client)
        registerClient c = do
            cid <- generateCode
            sec <- generateCode
            let retrieveJwks :: Text -> EitherT RegistrationError IO (Maybe [Jwk])
                retrieveJwks uri = do
                    -- TODO: Better HTTP client code. No redirect following
                    js <- EitherT . liftIO $ (Right <$> simpleHttp (T.unpack uri))
                        `catch` \(e :: SomeException) -> do
                            let errMsg = T.pack ("Failed to retrieve JWKs from URI: " ++ show e)
                            TIO.putStrLn errMsg
                            return $ Left (InvalidMetaData errMsg)
                    let jwkError s = T.pack ("Failed to decode retrieved client JWKs: " ++ s)
                    either (left . InvalidMetaData . jwkError) (right . Just . keys) (eitherDecode' js)

            -- retrieve client keys if URI set
            runEitherT $ do
                client <- hoistEither $ makeClient (TE.decodeUtf8 cid) (TE.decodeUtf8 sec) c
                ks     <- case clientKeysUri client of
                    Just uri -> retrieveJwks uri
                    Nothing  -> return $ clientKeys client
                liftIO . runDB $ BP.createClient client { clientKeys = ks }
                return client

        createIdToken uid aTime client nons now code aToken = do
            let claims  = idTokenClaims issuer client nons uid aTime now code aToken
                rpKeys  = fromMaybe [] (clientKeys client)
                csKey   = fmap (\k -> SymmetricJwk (TE.encodeUtf8 k) Nothing Nothing Nothing) (clientSecret client)
                sigKeys = maybe opSigKeys (: opSigKeys) csKey
                prefs   = fromMaybe (AlgPrefs (Just RS256) NotEncrypted) $ idTokenAlgs client
            token <- liftIO $ withCPRG $ \g -> createJwtToken g sigKeys rpKeys prefs claims
            either (const $ error "Failed to create IdToken") return token

        hashPassword p = do
            hash <- liftIO $ BCrypt.hashPasswordUsingPolicy BCrypt.fastBcryptHashingPolicy (TE.encodeUtf8 p)
            maybe (error "Hash failed") (return . TE.decodeUtf8) hash

        createUser scimData = do
            now <- Just <$> liftIO getCurrentTime
            uid <- (T.pack . toString) <$> liftIO nextRandom
            password <- hashPassword =<< maybe randomPassword return (scimPassword scimData)
            let meta = Meta now now Nothing Nothing
            runDB $ BP.createUser uid password scimData { scimId = Just uid, scimMeta = Just meta }

        getUser = liftIO . runDB . BP.getUserById

        userInfoHandler = withBearerToken (decodeJwtAccessToken kPr) [OpenID] $ \g -> do
            scimUser <- getUser $ fromJust $ granterId g
            -- TODO: Handle missing client situation
            Just client   <- getClient (granteeId g)
            -- Convert from SCIM... yuk
            let claims = scopedClaims (grantScope g) $ scimUserToUserInfo $ fromJust scimUser
            case userInfoAlgs client of
                Nothing -> json claims
                Just (AlgPrefs Nothing NotEncrypted) -> json claims
                Just a  -> do
                    jwtRes <- liftIO $ withCPRG $ \rng -> createJwtToken rng [privateKey] (fromMaybe [] (clientKeys client)) a claims
                    case jwtRes of
                        Right (Jwt jwt) -> setHeader hContentType "application/jwt" >> rawBytes (BL.fromStrict jwt)
                        Left  e         -> status internalServerError500 >> text (T.pack ("Failed to create user info JWT" ++ show e))

    mapM_ createUser testUsers

    let router path = case path of
          [""]         -> redirect "/home"
          ["home"]     -> text "Hello, I'm the home page"
          ["explode"]  -> error "Boom!"
          ("oauth":ps) -> case ps of
              ["authorize"] -> authorizationHandler getClient createAuthorization getApproval createAccessToken createIdToken
              ["token"]     -> tokenHandler getClient getAuthorization authenticateResourceOwner createAccessToken createIdToken decodeRefreshToken
              _             -> notFound
          ["login"]    -> loginHandler authenticateResourceOwner
          ["logout"]   -> invalidateSession >> complete
          ["approval"] -> approvalHandler getClient saveApproval
          ("connect":ps) -> case ps of
              ["userinfo"] -> userInfoHandler
              ["register"] -> registrationHandler registerClient
              _            -> notFound
          (".well-known":ps) -> case ps of
              ["openid-configuration"] -> json config
              ["jwks"]                 -> json publicKeySet
              _                        -> notFound
          _            -> notFound

    return router

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
  where
    randomPassword = (TE.decodeUtf8 . B64.encode) <$> randomBytes 12

    userIdKey = "_uid"

    registrationHandler :: RegisterClient IO -> Handler ()
    registrationHandler registerClient = do
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
                            json . Object $ HM.union o $ HM.fromList [("client_id", String $ clientId c), ("client_secret", String . fromJust $ clientSecret c), ("registration_access_token", String "this_is_a_worthless_fake"), ("registration_client_uri", String $ T.concat [issuer, "/client/", clientId c])]
                        Left  e -> status badRequest400 >> json e
            Right _            -> invalidMetaData "Client registration data must be a JSON Object"

    loginHandler authenticate = httpMethod >>= \m -> case m of
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

    approvalHandler getClient saveApproval = httpMethod >>= \m -> case m of
        GET -> do
            _      <- getAuthId
            now    <- liftIO getPOSIXTime
            Just client <- queryParam "client_id" >>= getClient
            scope  <- liftM (T.splitOn " ") $ queryParam "scope"
            html $ approvalPage client scope (round now)

        POST -> do
            uid       <- subjectId <$> getAuthId
            clntId    <- postParam "client_id"
            expiryTxt <- postParam "expiry"
            scpParams <- liftM (Map.lookup "scope") postParams

            let Right (expiry, _) = decimal expiryTxt
                scope    = maybe [] (map scopeFromName) scpParams
                approval = Approval uid clntId scope (IntDate $ fromIntegral (expiry :: Int64))
            _ <- liftIO $ saveApproval approval
            l <- getCachedLocation "/uhoh"
            clearCachedLocation
            -- Redirect to authorization doesn't seem to work with oictests
            redirect l

        _    -> methodNotAllowed

    authorizationHandler getClient createAuthorization getApproval createAccessToken createIdToken = do
        -- request >>= debug . W.rawQueryString

        user <- getAuthId
        env  <- queryParams
        now  <- liftIO getPOSIXTime

        response <- processAuthorizationRequest getClient (liftIO generateCode) createAuthorization resourceOwnerApproval createAccessToken createIdToken user env now
        case response of
            Right url                      -> redirectExternal $ TE.encodeUtf8 url
            Left (MaliciousClient e)       -> evilClientError e
            Left (ClientRedirectError url) -> redirectExternal $ TE.encodeUtf8 url
            Left RequiresReauthentication  -> cacheLocation >> redirect "/login"

      where
        evilClientError e = status badRequest400 >> text (T.pack $ show e)

        fakeApproval _ _ requestedScope _ = return requestedScope

        resourceOwnerApproval uid client requestedScope now = do
            -- Try to load a previous approval
            maybeApproval <- liftIO $ getApproval uid client now
            case maybeApproval of
                -- TODO: Check scope overlap and allow asking for extra scope
                -- not previously granted
                Just (Approval _ _ scope _) -> return $ scope `intersect` requestedScope
                -- Nothing exists: Redirect to approval handler with scopes and client id
                Nothing -> do
                    let query = renderSimpleQuery True [("client_id", TE.encodeUtf8 $ clientId client), ("scope", TE.encodeUtf8 $ formatScope requestedScope)]
                    cacheLocation
                    redirect $ B.concat ["/approval", query]

    tokenHandler getClient getAuthorization authenticateResourceOwner createAccessToken createIdToken decodeRefreshToken = do
        r <- request
        let authzHdr = lookup hAuthorization $ W.requestHeaders r
        env    <- postParams
        now    <- liftIO getPOSIXTime
        clientAuth <- authenticateClient env authzHdr now getClient (liftIO . withCPRG)
        case clientAuth of
            Left InvalidClient401 -> status unauthorized401 >> setHeader "WWW-Authenticate" "Basic" >> json (toJSON InvalidClient401)
            Left bad              -> status badRequest400   >> json (toJSON bad)
            Right client -> do
                resp <- processTokenRequest env client now getAuthorization authenticateResourceOwner createAccessToken createIdToken decodeRefreshToken
                case resp of
                    Right tokenResponse -> json $ toJSON tokenResponse
                    Left  bad           -> status badRequest400 >> json (toJSON bad)

    getAuthId = do
        usr <- sessionLookup userIdKey
        case usr of
            Just u  -> return (read $ T.unpack $ TE.decodeUtf8 u :: Usr)
            Nothing -> cacheLocation >> redirect "/login"

debug :: (MonadIO m, Show a) => a -> m ()
debug = liftIO . print

loginPage :: H.Html
loginPage = H.html $ do
    H.head $
      H.title "Login."
    H.body $
        H.form H.! method "post" H.! action "/login" $ do
            H.input H.! type_ "text" H.! name "username"
            H.input H.! type_ "password" H.! name "password"
            H.input H.! type_ "submit" H.! value "Login"

approvalPage :: Client -> [Text] -> Int64 -> H.Html
approvalPage client scopes now = H.docTypeHtml $ H.html $ do
    H.head $
      H.title "Approvals"
    H.body $ do
        H.h2 "Authorization Approval Request"
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

