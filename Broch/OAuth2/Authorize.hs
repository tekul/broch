{-# LANGUAGE OverloadedStrings #-}

module Broch.OAuth2.Authorize
    ( EvilClientError (..)
    , processAuthorizationRequest
    , generateCode
    )
where

import Control.Monad (liftM, liftM2, unless)
import Control.Monad.Trans.Class (lift)
import Control.Monad.Trans.Either
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as B
import Data.List (sort)
import Data.Time.Clock.POSIX
import Data.Maybe (fromMaybe)
import Data.Text (Text)

import qualified Data.ByteString.Base16 as Hex
import qualified Data.Map as Map
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE

import Network.HTTP.Types

import Broch.Model
import Broch.Random
import Broch.OAuth2.Internal

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
                            -> m (Either EvilClientError Text)
processAuthorizationRequest getClient genCode createAuthorization resourceOwnerApproval createAccessToken createIdToken user env now = do
    curi <- getClientAndRedirectURI getClient env
    case curi of
        Left e -> return $ Left e
        Right (client, uri) -> do
            let redirectURI = fromMaybe (defaultRedirectURI client) uri

            responseUrl <- authorizationResponseURL client uri
            return . Right $ T.concat [redirectURI, responseUrl]

  where
    authorizationResponseURL client uri =
        case getAuthorizationRequest client of
            Left err -> return err
            Right (state, responseType, requestedScope, nonce) -> do
                scope <- resourceOwnerApproval user client requestedScope now
                let separator         = case responseType of
                                          Code -> '?'
                                          _    -> '#'
                    codeResponse      = doCode client scope nonce uri
                    tokenResponse     = doAccessToken client scope
                    idTokenResponse   = doIdToken client nonce

                responseParams <- case responseType of
                    Code             -> liftM2 (:) codeResponse $ scopeParam scope
                    Token            -> tokenResponse
                    IdTokenResponse  -> idTokenResponse
                    CodeToken        -> liftM2 (:) codeResponse tokenResponse
                    -- TODO: These need changes to the id_token
                    -- http://openid.net/specs/openid-connect-core-1_0.html#HybridIDToken
                    TokenIdToken     -> undefined
                    CodeIdToken      -> undefined
                    CodeTokenIdToken -> undefined

                return $ T.cons separator $ TE.decodeUtf8 $ renderSimpleQuery False $ addStateParam state responseParams

    doCode client scope nonce uri = do
        code <- genCode
        createAuthorization (TE.decodeUtf8 code) user client now scope nonce uri
        return ("code", code)

    doAccessToken client scope = do
        (t, _, ttl) <- createAccessToken (Just $ subjectId user) client Implicit scope now
        let expires = B.pack $ show (round ttl :: Int)
        return [("access_token", t), ("token_type", "bearer"), ("expires_in", expires)]

    doIdToken client nonce = do
        t <- createIdToken (subjectId user) client nonce now
        return [("id_token", t)]

    scopeParam scope = return $ case scope of
        [] -> []
        s  -> [("scope", TE.encodeUtf8 $ T.intercalate " " $ map scopeName s)]


    getAuthorizationRequest :: Client -> Either Text (Maybe Text, ResponseType, [Scope], Maybe Text)
    getAuthorizationRequest client = do
        let stateParam = maybeParam env "state"
            st         = either (\_ -> Nothing) id stateParam
            separator  = case getResponseType of
                             Right Code -> '?'
                             Right _    -> '#'
                             Left  _    -> '?' -- TODO: Use client grant/response types
            err e      = T.cons separator $ errorURL st e

        -- All that was just to work out how to handle the error.
        -- Now check the actual parameter values.
        either (Left . err) return $ do
            state          <- either (Left . InvalidRequest) return $ stateParam
            responseType   <- getResponseType
            checkResponseType client responseType
            maybeScope     <- either (Left . InvalidRequest) (return . fmap splitOnSpace) $ maybeParam env "scope"
            nonce          <- either (Left . InvalidRequest) return $ maybeParam env "nonce"
            requestedScope <- checkScope client $ fmap (map scopeFromName) maybeScope

            return (state, responseType, requestedScope, nonce)

    getResponseType :: Either AuthorizationError ResponseType
    getResponseType = do
        rtParam        <- either (Left . InvalidRequest) return $ requireParam env "response_type"
        responseType   <- maybe  (Left UnsupportedResponseType) return $ lookup (normalize rtParam) responseTypes
        return responseType

    -- TODO: Create a type "CheckResponseType" and use it to allow configuration of
    -- supported response types and build openid configuration
    checkResponseType client rt =
        let checkGrant gt = unless (gt `elem` authorizedGrantTypes client) $ Left UnauthorizedClient
        in  case rt of
                Code            -> checkGrant AuthorizationCode
                Token           -> checkGrant Implicit
                IdTokenResponse -> checkGrant Implicit
                TokenIdToken    -> checkGrant Implicit
                _               -> checkGrant AuthorizationCode >> checkGrant Implicit

    defaultRedirectURI client = head $ redirectURIs client

    -- scopes <- validate scopes are allowed for client in question.
    -- Calculate intersection with user scopes
    checkScope client maybeScope = case checkClientScope client maybeScope of
        Right s -> Right s
        Left  m -> Left $ InvalidRequest m

    normalize = T.intercalate " " . sort . splitOnSpace
    splitOnSpace = T.splitOn " "


-- Authorization endpoint helper functions

-- "Evil client" checking
-- Get and checks the parameters for which an error should not be reported
-- to the client, but to the resource owner.
-- If a redirect_uri parameter is supplied it must be valid.
-- If none is supplied, the default for the client will be used.

getClientAndRedirectURI :: (Monad m) => LoadClient m -> Map.Map Text [Text] -> m (Either EvilClientError (Client, Maybe Text))
getClientAndRedirectURI getClient env = runEitherT $ do
    cid    <- either (left . InvalidClient) return $ requireParam env "client_id"
    uri    <- either (\_ -> left InvalidRedirectUri) return $ maybeParam env "redirect_uri"
    client <- maybe (left $ InvalidClient "Client does not exist") return =<< (lift $ getClient cid)
    validateRedirectURI client uri
    right (client, uri)
  where
    -- | Check the redirectURI is registered for the client
    validateRedirectURI _ Nothing = return ()
    validateRedirectURI client (Just uri)
      | T.any (== '#') uri        = left FragmentInUri
      | otherwise                 = if uri `elem` redirectURIs client
                                        then right ()
                                        else left InvalidRedirectUri

errorURL :: Maybe Text -> AuthorizationError -> Text
errorURL state authzError = TE.decodeUtf8 qs
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


