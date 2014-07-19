{-# LANGUAGE OverloadedStrings #-}

module Broch.OAuth2.Authorize
    ( EvilClientError (..)
    , processAuthorizationRequest
    , generateCode
    )
where

import Control.Monad (liftM, unless)
import Control.Monad.Error (lift)
import Control.Monad.Trans.Either
import Data.ByteString (ByteString)
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
            -- Get the state parameter
            -- Needs to be separate since later errors require that it is returned to
            -- the client with the error message.
            case maybeParam env "state" of
                Left badState -> return . Right $ errorURL False redirectURI Nothing (InvalidRequest badState)
                Right state   -> do
                    let err = return . Right . (errorURL False redirectURI state)
                    -- TODO: Need to consider response_type separately as
                    -- it also influences the default error url (fragment
                    -- or query)
                    case getAuthorizationRequest client of
                        Left e -> err e
                        Right (responseType, requestedScope, nonce) -> do
                            scope <- resourceOwnerApproval user client requestedScope now

                            case responseType of
                                Code  -> do
                                    code <- genCode
                                    createAuthorization (TE.decodeUtf8 code) user client now scope nonce uri
                                    return . Right $ authzCodeResponseURL redirectURI state code (map scopeName scope)
                                Token -> do
                                    -- TODO: Create token
                                    error "Implicit grant not supported"
                                IdTokenResponse -> do
                                    idt <- createIdToken (subjectId user) client nonce now
                                    return . Right $ implicitResponseURL redirectURI state Nothing (Just idt)

                                _     -> error "Response type not supported"
  where
    getAuthorizationRequest :: Client -> Either AuthorizationError (ResponseType, [Scope], Maybe Text)
    getAuthorizationRequest client = do
        rtParam        <- either (Left . InvalidRequest) return $ requireParam env "response_type"
        responseType   <- maybe  (Left UnsupportedResponseType) return $ lookup (normalize rtParam) responseTypes
        checkResponseType client responseType
        maybeScope     <- either (Left . InvalidRequest) (return . fmap splitOnSpace) $ maybeParam env "scope"
        nonce          <- either (Left . InvalidRequest) return $ maybeParam env "nonce"
        requestedScope <- checkScope client $ fmap (map scopeFromName) maybeScope
        case responseType of
            Code  -> return (responseType, requestedScope, nonce)
            Token -> Left UnsupportedResponseType -- "Implicit grant is not supported"
            _     -> Left UnsupportedResponseType

    defaultRedirectURI client = head $ redirectURIs client

    checkResponseType client rt = case rt of
        Code -> unless (AuthorizationCode `elem` authorizedGrantTypes client) $ Left UnauthorizedClient
        _    -> Left UnsupportedResponseType

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


authzCodeResponseURL :: Text -> Maybe Text -> ByteString -> [Text] -> Text
authzCodeResponseURL redirectURI state code scope = buildURL False redirectURI state params
  where
    params = ("code", code) : case scope of
        [] -> []
        s  -> [("scope", TE.encodeUtf8 $ T.intercalate " " s)]

implicitResponseURL :: Text
                    -> Maybe Text
                    -> Maybe ByteString
                    -> Maybe ByteString
                    -> Text
implicitResponseURL redirectURI state accessToken idToken = buildURL True redirectURI state params
  where
    params   = maybe atParams (\t -> ("id_token", t) : atParams) $ idToken
    atParams = maybe [] (\t -> [("access_token", t), ("token_type", "bearer")]) $ accessToken

errorURL :: Bool -> Text -> Maybe Text -> AuthorizationError -> Text
errorURL useFragment redirectURI state authzError = buildURL useFragment redirectURI state params
  where
    params = ("error", e) : maybe [] (\d -> [("error_description", d)]) desc
    (e, desc) = case authzError of
        InvalidRequest d      -> ("invalid_request", Just $ TE.encodeUtf8 d)
        UnauthorizedClient    -> ("unauthorized client", Nothing)
        AccessDenied          -> ("access_denied", Nothing)
        UnsupportedResponseType -> ("unsupported_response_type", Nothing)
        InvalidScope d        -> ("invalid_scope", Just $ TE.encodeUtf8 d)
        ServerError           -> ("server_error", Nothing)
        Unavailable           -> ("temporarily_unavailable", Nothing)

buildURL :: Bool -> Text -> Maybe Text -> [SimpleQueryItem] -> Text
buildURL useFragment redirectURI state params = T.concat [redirectURI, separator, qs]
  where
    separator = if useFragment then "#" else "?"
    ps = maybe params (\s -> ("state", TE.encodeUtf8 s) : params) state
    qs = TE.decodeUtf8 $ renderSimpleQuery False ps

-- Create a random authorization code
generateCode :: IO ByteString
generateCode = liftM Hex.encode $ randomBytes 8


