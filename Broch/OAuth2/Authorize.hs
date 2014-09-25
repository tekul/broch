{-# LANGUAGE OverloadedStrings #-}

module Broch.OAuth2.Authorize
    ( AuthorizationRequestError (..)
    , EvilClientError (..)
    , processAuthorizationRequest
    , generateCode
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

import qualified Data.ByteString.Base16 as Hex
import qualified Data.Map as Map
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE

import Network.HTTP.Types

import Broch.Model
import Broch.Random
import Broch.OAuth2.Internal


data AuthorizationRequestError = MaliciousClient EvilClientError
                               | RequiresReauthentication -- TODO add requested type (popup etc)
                               | ClientRedirectError Text deriving (Show, Eq)

data EvilClientError = InvalidClient Text
                     | InvalidRedirectUri
                     | FragmentInUri
                     deriving (Show, Eq)

data AuthorizationError = InvalidRequest Text
                        | UnauthorizedClient
                        | AccessDenied
                        | UnsupportedResponseType
                        | InvalidScope Text
                        | ServerError
                        | Unavailable

type GenerateCode m = m ByteString
type ResourceOwnerApproval m s = s -> Client -> [Scope] -> POSIXTime -> m [Scope]

processAuthorizationRequest :: (Monad m, Subject s) => LoadClient m
                            -> GenerateCode m
                            -> CreateAuthorization m s
                            -> ResourceOwnerApproval m s
                            -> CreateAccessToken m
                            -> CreateIdToken m
                            -> s
                            -> Map.Map Text [Text]
                            -> POSIXTime
                            -> m (Either AuthorizationRequestError Text)
processAuthorizationRequest getClient genCode createAuthorization resourceOwnerApproval createAccessToken createIdToken user env now = runEitherT $ do
    -- Potential for a malicious client error
    (client, uri) <- getClientAndRedirectURI
    let redirectURI = fromMaybe (defaultRedirectURI client) uri

    -- Decode the request, and fail with a client redirect if invalid
    (state, responseType, requestedScope, nonce, maxAge) <- getAuthorizationRequest redirectURI client
    when (authRequired maxAge) $ left RequiresReauthentication

    scope <- lift $ resourceOwnerApproval user client requestedScope now

    -- Create the successful response redirect
    responseParams <- lift $ authorizationResponse responseType client scope nonce uri
    let qs = TE.decodeUtf8 $ renderSimpleQuery False $ addStateParam state responseParams

    return $ T.concat [redirectURI, T.cons (separator responseType) qs]
  where
    authRequired Nothing       = False
    authRequired (Just maxAge) = now - authTime user > fromIntegral maxAge

    authorizationResponse responseType client scope nonce uri = do
        let codeResponse    = doCode client scope nonce uri
            tokenResponse   = tokenParams =<< doAccessToken client scope
            idTokenResponse = doIdToken client nonce

        case responseType of
            Code             -> liftM2 (:) (codeParam =<< codeResponse) $ scopeParam scope
            Token            -> tokenResponse
            IdTokenResponse  -> idTokenResponse Nothing Nothing
            CodeToken        -> liftM2 (:) (codeParam =<< codeResponse) tokenResponse
            -- The remaining hybrid responses need changes to the id_token
            -- http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
            TokenIdToken     -> do
                te@(t, _) <- doAccessToken client scope
                liftM2 (++) (tokenParams te) $ idTokenResponse Nothing (Just t)
            CodeIdToken      -> do
                code      <- codeResponse
                liftM2 (:) (codeParam code) $ idTokenResponse (Just code) Nothing
            CodeTokenIdToken -> do
                code      <- codeResponse
                te@(t, _) <- doAccessToken client scope
                liftM2 (:) (codeParam code) $ liftM2 (++) (tokenParams te)
                    $ idTokenResponse (Just code) (Just t)

    doCode client scope nonce uri = do
        code <- genCode
        createAuthorization (TE.decodeUtf8 code) user client now scope nonce uri
        return code

    codeParam code = return ("code", code)

    doAccessToken client scope = do
        (t, _, ttl) <- createAccessToken (Just $ subjectId user) client Implicit scope now
        let expires = B.pack $ show (round ttl :: Int)
        return (t, expires)

    tokenParams (token, expires) =
        return [("access_token", token), ("token_type", "bearer"), ("expires_in", expires)]

    doIdToken client nonce code accessToken = do
        t <- createIdToken (subjectId user) client nonce now code accessToken
        return [("id_token", t)]

    scopeParam scope = return $ case scope of
        [] -> []
        s  -> [("scope", TE.encodeUtf8 $ T.intercalate " " $ map scopeName s)]


    getAuthorizationRequest redirectBase client = do
        let stateParam = maybeParam env "state"
            st         = either (const Nothing) id stateParam
            sep        = case getResponseType of
                             Right rt -> separator rt
                             _        -> '?' -- TODO: Use client grant/response types

            clientRedirect e = ClientRedirectError $ T.concat [redirectBase, errorURL sep st e]
            invalidRequest m = clientRedirect $ InvalidRequest m

        -- All that was just to work out how to handle the error.
        -- Now check the actual parameter values.
        state          <- stateParam `failW` invalidRequest
        responseType   <- either (left . clientRedirect) return $ getResponseType
        unless (checkResponseType client responseType) $ left $ clientRedirect UnauthorizedClient
        maybeScope     <- maybeParam env "scope" `failW` invalidRequest >>= return . (fmap splitOnSpace)
        nonce          <- maybeParam env "nonce" `failW` invalidRequest
        maxAge         <- getMaxAge `failW` invalidRequest
        requestedScope <- checkScope client maybeScope `failW` invalidRequest
        let isOpenID   = OpenID `elem` requestedScope

        -- http://openid.net/specs/openid-connect-core-1_0.html#Authentication
        when (responseType == Token && isOpenID) $
            left $ invalidRequest "openid scope cannot be user with 'token' response type"
        -- Implicit and Hybrid OpenID requests require a nonce
        -- http://openid.net/specs/openid-connect-core-1_0.html#ImplicitAuthRequest
        -- http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
        when (responseType /= Code  && isOpenID && isNothing nonce) $
            left $ invalidRequest "A nonce is required for this response type"

        return (state, responseType, requestedScope, nonce, maxAge)

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

    separator responseType = if responseType == Code then '?' else '#'

    -- "Evil client" checking
    -- Get and checks the parameters for which an error should not be reported
    -- to the client, but to the resource owner.
    -- If a redirect_uri parameter is supplied it must be valid.
    -- If none is supplied, the default for the client will be used.
    getClientAndRedirectURI = do
        cid    <- requireParam env "client_id" `failW` (MaliciousClient . InvalidClient)
        uri    <- maybeParam env "redirect_uri" `failW` (const $ MaliciousClient InvalidRedirectUri)
        client <- maybe (left $ MaliciousClient $ InvalidClient "Client does not exist") return =<< lift (getClient cid)
        validateRedirectURI client uri
        right (client, uri)
      where
        -- | Check the redirectURI is registered for the client
        validateRedirectURI _ Nothing = return ()
        validateRedirectURI client (Just uri)
          | T.any (== '#') uri        = left $ MaliciousClient $ FragmentInUri
          | otherwise                 = if uri `elem` redirectURIs client
                                            then right ()
                                            else left $ MaliciousClient  InvalidRedirectUri

    failW :: Monad m => Either Text a -> (Text -> e) -> EitherT e m a
    failW (Right a) _ = return a
    failW (Left m)  f = left $ f m

errorURL :: Char -> Maybe Text -> AuthorizationError -> Text
errorURL separator state authzError = T.cons separator $ TE.decodeUtf8 qs
  where
    qs = renderSimpleQuery False $ addStateParam state params
    params = ("error", e) : maybe [] (\d -> [("error_description", d)]) desc
    (e, desc) = case authzError of
        InvalidRequest d      -> ("invalid_request", Just $ TE.encodeUtf8 d)
        UnauthorizedClient    -> ("unauthorized client", Nothing)
        AccessDenied          -> ("access_denied", Nothing)
        UnsupportedResponseType -> ("unsupported_response_type", Nothing)
        InvalidScope d        -> ("invalid_scope", Just $ TE.encodeUtf8 d)
        ServerError           -> ("server_error", Nothing)
        Unavailable           -> ("temporarily_unavailable", Nothing)

addStateParam :: Maybe Text -> [SimpleQueryItem] -> [SimpleQueryItem]
addStateParam state ps = maybe ps (\s -> ("state", TE.encodeUtf8 s) : ps) state

-- Create a random authorization code
generateCode :: IO ByteString
generateCode = liftM Hex.encode $ randomBytes 8


