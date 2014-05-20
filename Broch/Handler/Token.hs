{-# LANGUAGE TypeFamilies, OverloadedStrings, GADTs,
             FlexibleContexts, MultiParamTypeClasses,
             GeneralizedNewtypeDeriving #-}

module Broch.Handler.Token
  ( postTokenR
  , OAuth2Server(..)
  , TokenTTL
  ) where

import Prelude hiding (exp)

import Yesod.Core.Handler (HandlerT, sendResponseStatus, permissionDenied, runRequestBody)
import Yesod.Core (MonadHandler, waiRequest, getYesod)

import Data.Aeson
import Data.Text (Text)
import Data.Time.Clock.POSIX
import qualified Data.ByteString.Base64 as B64
import qualified Data.ByteString.Char8 as B
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import qualified Data.Map as Map

import Control.Monad (liftM)
import Control.Monad.IO.Class (liftIO)
import qualified Network.Wai as W

import Network.HTTP.Types

import Broch.Model
import Broch.OAuth2.Token
import Broch.Class

postTokenR :: OAuth2Server site => HandlerT site IO Value
postTokenR = do
    -- TODO: Replace with a generic client auth method based on the
    -- supported auth types
    client    <- basicAuthClient
    env       <- runRequestBody >>= \(params, _) -> return $ toMap params
    --env       <- liftM (toMap . reqGetParams) getRequest
    now       <- liftIO getPOSIXTime
    oauth2    <- getYesod

    response  <- liftIO $ processTokenRequest env client now (getAuthorization oauth2) (authenticateResourceOwner oauth2) (createAccessToken oauth2) (decodeRefreshToken oauth2)
    case response of
      Left err -> sendResponseStatus badRequest400 $ toJSON err
      Right tr -> return $ toJSON tr


basicAuthClient :: (OAuth2Server site) => HandlerT site IO Client
basicAuthClient = do
    hdrs          <- liftM W.requestHeaders waiRequest
    authzHdr      <- maybe (send401 "Authentication required") return $ lookup hAuthorization hdrs
    (cid, secret) <- maybe (send401 "Invalid authorization header") return $ decodeHeader authzHdr
    oauth2        <- getYesod
    maybeClient   <- liftIO $ getClient oauth2 cid
    maybe (permissionDenied "Authentication failed") return $ maybeClient >>= validateSecret secret
  where
    send401 :: MonadHandler m => Text -> m a
    send401 = sendResponseStatus unauthorized401
    decodeHeader h = case B.split ' ' h of
                       ["Basic", b] -> either (const Nothing) creds $ B64.decode b
                       _            -> Nothing
    creds bs = case fmap (T.break (== ':')) $ TE.decodeUtf8' bs of
                 Left _       -> Nothing
                 Right (u, p) -> if T.length p == 0
                                 then Nothing
                                 else Just (u, T.tail p)

validateSecret :: Text -> Client -> Maybe Client
validateSecret secret client = clientSecret client >>= \s ->
                                  if secret == s
                                  then Just client
                                  else Nothing

toMap :: [(Text, a)] -> Map.Map Text [a]
toMap = Map.unionsWith (++) . map (\(x, y) -> Map.singleton x [y])


