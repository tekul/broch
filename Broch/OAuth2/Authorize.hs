{-# LANGUAGE TypeFamilies, OverloadedStrings, GADTs,
             FlexibleContexts, MultiParamTypeClasses,
             GeneralizedNewtypeDeriving #-}

module Broch.OAuth2.Authorize
    ( EvilClientError (..)
    , AuthorizationError (..)
    , getClientAndRedirectURI
    , getState
    , getGrantData
    , defaultRedirectURI
    , generateCode
    , authzCodeResponseURL
    , authzErrorURL
    )
where

import Control.Monad (liftM, unless)
import Control.Monad.Error (lift)
import Control.Monad.Trans.Either
import Data.ByteString (ByteString)
import Data.List (sort, intersect, (\\))
import Data.Maybe (catMaybes, fromMaybe)
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
                        deriving (Show, Eq)


-- Authorization endpoint helper functions

-- "Evil client" checking
-- Get and checks the parameters for which an error should not be reported
-- to the client, but to the resource owner.


getClientAndRedirectURI :: (Monad m) => (ClientId -> m (Maybe Client)) -> Map.Map Text [Text] -> m (Either EvilClientError (Client, Maybe Text))
getClientAndRedirectURI getClient env = runEitherT $ do
    (cid, mURI) <- getClientParams env
    client      <- maybe (left $ InvalidClient "Client does not exist") return =<< (lift $ getClient cid)
    validateRedirectURI client mURI
    right (client, mURI)



-- The client id and redirect URI
getClientParams :: (Monad m) => Map.Map Text [Text] -> EitherT EvilClientError m (ClientId, Maybe Text)
getClientParams env = do
    cid    <- either (left . InvalidClient) return $ requireParam env "client_id"
    mURI   <- either (\_ -> left InvalidRedirectUri) return $ maybeParam env "redirect_uri"
    return (cid, mURI)

-- | If a redirect_uri parameter is supplied it must be valid.
--   If none is supplied, the default for the client will be used.
validateRedirectURI :: (Monad m) => Client -> Maybe Text -> EitherT EvilClientError m ()
validateRedirectURI client maybeUri = case maybeUri of
    Just u  -> validate u
    Nothing -> return ()
  where
    validate uri
      | T.any (== '#') uri           = left FragmentInUri
      | validRedirectUri client uri  = right ()
      | otherwise                    = left InvalidRedirectUri

-- Other data extraction and validation functions for which errors should
-- be reported to the client


-- Get the state parameter
-- Needs to be separate since later errors require that it is returned to
-- the client with the error message.
getState :: Map.Map Text [Text] -> Either AuthorizationError (Maybe Text)
getState env = either (Left . InvalidRequest) return $ maybeParam env "state"

-- response type and scope
getGrantData :: Map.Map Text [Text] -> Text -> Client -> Either AuthorizationError (ResponseType, [Text])
getGrantData env user client =  do
    param <- either (Left . InvalidRequest) return $ requireParam env "response_type"
    rt    <- maybe (Left UnsupportedResponseType) return $ lookup (normalize param) responseTypes
    checkResponseType client rt
    maybeScope <- either (Left . InvalidRequest) (return . fmap splitOnSpace) $ maybeParam env "scope"
    scope <-  checkScope user client maybeScope
    return (rt, scope)

checkResponseType :: Client -> ResponseType -> Either AuthorizationError ()
checkResponseType client rt = case rt of
    Code -> unless (AuthorizationCode `elem` authorizedGrantTypes client) $ Left UnauthorizedClient
    _    -> Left UnsupportedResponseType

-- scopes <- validate scopes are allowed for client in question.
-- Calculate intersection with user scopes
checkScope :: Text -> Client -> Maybe [Text] -> Either AuthorizationError [Text]
checkScope user client maybeScope = case checkClientScope client maybeScope of
  Right s -> Right s
  Left  m -> Left $ InvalidRequest m

checkApproval u c r = return ()

-- | Check the redirectURI is registered for the client
validRedirectUri :: Client -> Text -> Bool
validRedirectUri client uri = uri `elem` redirectURIs client


-- TODO: Refactor redirect methods and add a fragment version
authzCodeResponseURL :: Text -> Maybe Text -> ByteString -> [Text] -> Text
authzCodeResponseURL redirectURI maybeState code scope = T.append redirectURI qs
  where
    qs  = TE.decodeUtf8 $ renderSimpleQuery True params
    params = catMaybes
       [ Just ("code", code)
       , fmap (\s -> ("state", TE.encodeUtf8 s)) maybeState
       , case scope of
           [] -> Nothing
           s  -> Just ("scope", TE.encodeUtf8 $ T.intercalate " " s)
       ]


authzErrorURL :: Text -> Maybe Text -> AuthorizationError -> Text
authzErrorURL redirectURI maybeState authzError = T.append redirectURI qs
  where
    qs  = TE.decodeUtf8 $ renderSimpleQuery True params
    params = catMaybes
       [ Just ("error", e)
       , fmap (\d -> ("error_description", d)) desc
       , fmap (\s -> ("state", TE.encodeUtf8 s)) maybeState
       ]
    (e, desc) = case authzError of
      InvalidRequest d      -> ("invalid_request", Just $ TE.encodeUtf8 d)
      UnauthorizedClient    -> ("unauthorized client", Nothing)
      AccessDenied          -> ("access_denied", Nothing)
      UnsupportedResponseType -> ("unsupported_response_type", Nothing)
      InvalidScope d        -> ("invalid_scope", Just $ TE.encodeUtf8 d)
      ServerError           -> ("server_error", Nothing)
      Unavailable           -> ("temporarily_unavailable", Nothing)

-- Create a random authorization code
generateCode :: IO ByteString
generateCode = liftM Hex.encode $ randomBytes 8


defaultRedirectURI client = head $ redirectURIs client


-- Utility functions


normalize = T.intercalate " " . sort . splitOnSpace
splitOnSpace = T.splitOn " "

