{-# LANGUAGE OverloadedStrings #-}

-- | Authorization request processing.
--
-- Front ends call the web-agnostic @processAuthorizationRequest@ function
-- to process the request data.

module Broch.OAuth2.Authorize
    ( AuthorizationRequestError (..)
    , EvilClientError (..)
    , processAuthorizationRequest
    )
where

import Control.Error
import Control.Monad (liftM, liftM2, when, unless)
import Control.Monad.Trans (lift)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as B
import Data.List (sort)
import Data.Time.Clock.POSIX
import Data.Text (Text)

import qualified Data.Map as Map
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE

import Jose.Jwt (Jwt(..))

import Broch.Model
import Broch.URI
import Broch.OAuth2.Internal

-- | Error conditions returned by the @processAuthorizationRequest@ function.
data AuthorizationRequestError
    -- | An error which should not be returned to the client
    -- but reported to the user instead. Typically an invalid
    -- redirect_uri.
    = MaliciousClient EvilClientError
    -- | The user needs to be authenticated (again).
    -- Occurs, for example, when the OpenID client uses the @max_age@
    -- request parameter to indicate that the user must have been
    -- authenticated within a particular time window.
    | RequiresAuthentication -- TODO add requested type (popup etc)
    -- | The request has an error which should be reported to
    -- the client via a redirect.
    | ClientRedirectError URI deriving (Show, Eq)

-- | Categories of "malicious client" error.
-- Allows the front end to provide more information
-- to the end user on why a request is invalid.
data EvilClientError
    = InvalidClient Text
    | InvalidRedirectUri Text
    | MissingRedirectUri
    | FragmentInUri
    deriving (Show, Eq)

-- | Authorization errors which will be reported to the client via a redirect.
-- See the OAuth2 and OpenID Connect specs for more information.
data AuthorizationError
    = InvalidRequest Text
    | UnauthorizedClient
    | AccessDenied
    | UnsupportedResponseType
    | InvalidScope Text
    | ServerError
    | Unavailable
    | LoginRequired

type GenerateCode m = m ByteString
type ResourceOwnerApproval m s = s -> Client -> [Scope] -> POSIXTime -> m [Scope]

data Prompt
    = None
    | Login
    | Consent
    | SelectAccount
    deriving (Show, Eq)

processAuthorizationRequest :: (Monad m, Subject s)
    => [ResponseType]
    -- ^ Supported response types
    -> LoadClient m
    -- ^ Function to load a client
    -> GenerateCode m
    -- ^ Function to generate an authorization code
    -> CreateAuthorization m s
    -- ^ Function to store the authorization request for retrieval at the token endpoint.
    -- May involve a UI interaction, if the client has not previously been granted access.
    -> ResourceOwnerApproval m s
    -- ^ Function which obtains the resource owner's approval for the request.
    -> CreateAccessToken m
    -- ^ Creates the access token which will be returned for implicit grant or
    -- OpenID hybrid grant requests. If these aren't enabled it won't be invoked.
    -> CreateIdToken m
    -- ^ Creates the ID token which will be returned with the authorization
    -- response for the relevant OpenID connect requests.
    -> m (Maybe (s, Bool))
    -- ^ The currently authenticated user, if available, and whether they were
    -- authenticated during the current request.
    -> Map.Map Text [Text]
    -- ^ The authorization request parameters.
    -> POSIXTime
    -- ^ The current time.
    -> m (Either AuthorizationRequestError URI)
    -- ^ The successful redirect URL which the front end should return to the client.
    -- If an error is returned, the front end's behaviour will depend on the
    -- specific error type as defined above.
processAuthorizationRequest supportedResponseTypes getClient genCode createAuthorization resourceOwnerApproval createAccessToken createIdToken currentUser env now = runExceptT $ do
    -- Potential for a malicious client error
    (client, uri) <- getClientAndRedirectURI
    let redirectURI = fromMaybe (defaultRedirectURI client) uri
        errRedirect = errorRedirector redirectURI

    -- Decode the request, and fail with a client redirect if invalid
    (state, responseType, requestedScope, nonce, maxAge, prompt) <- fmapLT errRedirect $ getAuthorizationRequest client

    -- Deal with (Re)authentication as necessary or raise
    -- the appropriate error if the prompt parameter won't allow it.
    user <- authenticatedUser prompt maxAge errRedirect
    scope <- lift $ resourceOwnerApproval user client requestedScope now

    -- Create the successful response redirect (unless id_token creation fails)
    responseParams <- fmapLT errRedirect $ authorizationResponse responseType user client scope nonce uri

    return $ buildRedirect redirectURI responseType (addStateParam state responseParams)
  where
    authenticatedUser prompt maxAge errRedirect = do
        mUser <- lift currentUser
        let t0 = maybe now fromIntegral maxAge
            loginRequired = Login `elem` prompt
        case mUser of
            Just (u, loggedInThisReq) -> if (loginRequired && not loggedInThisReq)
                                            || (now - authTime u > t0)
                          then throwE RequiresAuthentication
                          else return u
            _ -> throwE $ if None `elem` prompt then errRedirect LoginRequired else RequiresAuthentication

    authorizationResponse responseType user client scope nonce uri = do
        let codeResponse    = doCode
            tokenResponse   = tokenParams =<< doAccessToken
            idTokenResponse = doIdToken

        case responseType of
            Code             -> liftM2 (:) (codeParam =<< codeResponse) $ scopeParam scope
            Token            -> tokenResponse
            IdTokenResponse  -> idTokenResponse Nothing Nothing
            CodeToken        -> liftM2 (:) (codeParam =<< codeResponse) tokenResponse
            -- The remaining hybrid responses need changes to the id_token
            -- http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
            TokenIdToken     -> do
                te@(t, _) <- doAccessToken
                liftM2 (++) (tokenParams te) $ idTokenResponse Nothing (Just t)
            CodeIdToken      -> do
                code      <- codeResponse
                liftM2 (:) (codeParam code) $ idTokenResponse (Just code) Nothing
            CodeTokenIdToken -> do
                code      <- codeResponse
                te@(t, _) <- doAccessToken
                liftM2 (:) (codeParam code) $ liftM2 (++) (tokenParams te)
                    $ idTokenResponse (Just code) (Just t)
      where
        doCode = do
            code <- lift genCode
            lift $ createAuthorization (TE.decodeUtf8 code) user client now scope nonce uri
            return code

        codeParam code = return ("code", code)

        doAccessToken = do
            token <- lift $ createAccessToken (Just $ subjectId user) client Implicit scope now
            case token of
                Right (t, _, ttl) -> return (t, ttl)
                Left _            -> throwE ServerError

        tokenParams (token, expires) =
            return [("access_token", token), ("token_type", "bearer"), ("expires_in", B.pack $ show (round expires :: Int))]

        doIdToken code accessToken = do
            idt  <- lift $ createIdToken (subjectId user) (authTime user) client nonce now code accessToken
            idt' <- case idt of
                Right (Jwt jwt) -> return jwt
                Left jwtErr     -> throwE (InvalidRequest $ T.pack ("Failed to create id_token " ++ show jwtErr))
            return [("id_token", idt')]

    scopeParam scope = return $ case scope of
        [] -> []
        s  -> [("scope", TE.encodeUtf8 $ T.intercalate " " $ map scopeName s)]

    getAuthorizationRequest client = do
        state          <- maybeParam env "state" `failW` InvalidRequest
        responseType   <- hoistEither getResponseType
        unless (responseType `elem` supportedResponseTypes) (throwE UnsupportedResponseType)
        unless (checkResponseType client responseType) $ throwE UnauthorizedClient
        maybeScope     <- liftM (fmap splitOnSpace) $ maybeParam env "scope" `failW` InvalidRequest
        nonce          <- maybeParam env "nonce" `failW` InvalidRequest
        -- TODO: Validate that maxAge is a reasonable time period
        maxAge         <- getMaxAge `failW` InvalidRequest
        requestedScope <- checkScope client maybeScope `failW` InvalidRequest
        prompt         <- getPrompt `failW` InvalidRequest
        let isOpenID   = OpenID `elem` requestedScope

        -- http://openid.net/specs/openid-connect-core-1_0.html#Authentication
        when (responseType == Token && isOpenID) $
            throwE $ InvalidRequest "openid scope cannot be user with 'token' response type"
        -- Implicit and Hybrid OpenID requests require a nonce
        -- http://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthRequest
        -- http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
        when (responseType /= Code  && isOpenID && isNothing nonce) $
            throwE $ InvalidRequest "A nonce is required for this response type"

        return (state, responseType, requestedScope, nonce, maxAge, prompt)

    getPrompt = do
        promptParam <- maybeParam env "prompt"
        case promptParam of
            Nothing -> return []
            Just p  -> do
                ps <- mapM mkPrompt (T.split (== ' ') p)
                when (None `elem` ps && Login `elem` ps) (Left "prompt cannot include both 'none' and 'login'")
                return ps
      where
        mkPrompt p = case p of
            "none"  -> return None
            "login" -> return Login
            "consent" -> return Consent
            "select-account" -> return SelectAccount
            x -> Left (T.concat ["Unrecognise 'prompt' value: ", x])

    errorRedirector :: URI -> AuthorizationError -> AuthorizationRequestError
    errorRedirector redirectBase e =
        let stateParam = maybeParam env "state"
            st         = either (const Nothing) id stateParam
            -- The response type may be invalid at this point, so default to code
            -- TOOD: Use client registered response types?
            rt         = either (const Code) id getResponseType
        in ClientRedirectError $ buildRedirect redirectBase rt (errorParams st e)

    buildRedirect base rt params = case rt of
        Code -> addQueryParams base params
        _    -> setFragmentParams base params

    getMaxAge = do
        maxAge <- maybeParam env "max_age"
        case maxAge of
            Nothing -> return Nothing
            Just a  -> do
                maxAgeSeconds <- maybe (Left "Invalid max_age parameter") Right (readMay $ T.unpack a :: Maybe Int)
                return $ Just maxAgeSeconds

    getResponseType :: Either AuthorizationError ResponseType
    getResponseType = do
        rtParam <- either (Left . InvalidRequest) return $ requireParam env "response_type"
        maybe  (Left UnsupportedResponseType) return $ lookup (normalize rtParam) responseTypes


    -- TODO: Create a type "CheckResponseType" and use it to allow configuration of
    -- supported response types and build openid configuration
    checkResponseType client rt =
        let checkGrant gt = gt `elem` authorizedGrantTypes client
        in  case rt of
                Code            -> checkGrant AuthorizationCode
                Token           -> checkGrant Implicit
                IdTokenResponse -> checkGrant Implicit
                TokenIdToken    -> checkGrant Implicit
                _               -> checkGrant AuthorizationCode && checkGrant Implicit

    defaultRedirectURI client = head $ redirectURIs client

    -- scopes <- validate scopes are allowed for client in question.
    -- Calculate intersection with user scopes
    checkScope client maybeScope = checkClientScope client $ fmap (map scopeFromName) maybeScope

    normalize = T.intercalate " " . sort . splitOnSpace
    splitOnSpace = T.splitOn " "

    -- "Evil client" checking
    -- Get and checks the parameters for which an error should not be reported
    -- to the client, but to the resource owner.
    -- If a redirect_uri parameter is supplied it must be valid.
    -- If none is supplied, the default for the client will be used.
    getClientAndRedirectURI = do
        cid    <- requireParam env "client_id" `failW` (MaliciousClient . InvalidClient)
        uri    <- maybeParseParam env "redirect_uri" parseURI `failW` (MaliciousClient . InvalidRedirectUri)
        client <- maybe (throwE $ MaliciousClient $ InvalidClient "Client does not exist") return =<< lift (getClient cid)
        validateRedirectURI client uri
        return (client, uri)
      where
        -- Check the redirect_uri is registered for the client.
        -- If more than one is registered, the parameter must be supplied (see OAuth2 3.1.2.3).
        validateRedirectURI client Nothing = case redirectURIs client of
            [_] -> return ()
            _   -> throwE $ MaliciousClient MissingRedirectUri
        validateRedirectURI client (Just uri)
            | uri `elem` redirectURIs client = return ()
            | otherwise = throwE . MaliciousClient $ InvalidRedirectUri "redirect_uri is not registered for client"

    failW :: Monad m => Either e1 a -> (e1 -> e2) -> ExceptT e2 m a
    failW (Right a) _ = return a
    failW (Left m)  f = throwE $ f m

errorParams :: Maybe Text -> AuthorizationError -> [(ByteString, ByteString)]
errorParams state authzError = addStateParam state params
  where
    params = ("error", e) : maybe [] (\d -> [("error_description", d)]) desc
    (e, desc) = case authzError of
        InvalidRequest d      -> ("invalid_request", Just $ TE.encodeUtf8 d)
        UnauthorizedClient    -> ("unauthorized_client", Nothing)
        AccessDenied          -> ("access_denied", Nothing)
        UnsupportedResponseType -> ("unsupported_response_type", Nothing)
        InvalidScope d        -> ("invalid_scope", Just $ TE.encodeUtf8 d)
        ServerError           -> ("server_error", Nothing)
        Unavailable           -> ("temporarily_unavailable", Nothing)
        LoginRequired         -> ("login_required", Nothing)

addStateParam :: Maybe Text -> [(ByteString, ByteString)] -> [(ByteString, ByteString)]
addStateParam state ps = maybe ps (\s -> ("state", TE.encodeUtf8 s) : ps) state
