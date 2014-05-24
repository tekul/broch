{-# LANGUAGE BangPatterns, TypeFamilies, OverloadedStrings, GADTs,
             FlexibleContexts, MultiParamTypeClasses,
             GeneralizedNewtypeDeriving #-}

module Broch.OAuth2.Token
    ( TokenType (..)
    , AccessTokenResponse (..)
    , TokenError (..)
    , processTokenRequest
    )
where

import Control.Monad (when)
import Control.Monad.Error (lift)
import Control.Monad.Trans.Either

import Data.Aeson
import Data.Map (Map)
import Data.ByteString (ByteString)
import Data.Text (Text)
import Data.Time (NominalDiffTime)
import Data.Time.Clock.POSIX (POSIXTime)

import qualified Data.Text as T
import qualified Data.Text.Encoding as TE

import Broch.Model
import qualified Broch.OAuth2.Internal as I

data TokenType = Bearer deriving (Show, Eq)


instance ToJSON TokenType where
    toJSON _ = String "bearer"

data AccessTokenResponse = AccessTokenResponse
  { accessToken  :: ByteString
  , tokenType    :: TokenType
  , expiresIn    :: TokenTTL
  , refreshToken :: Maybe ByteString
  , scope        :: Maybe ByteString
  } deriving (Show, Eq)

instance ToJSON AccessTokenResponse where
    toJSON (AccessTokenResponse t tt ex mr ms) =
        let expires = round ex :: Int
        in object $ [ "access_token" .= TE.decodeUtf8 t
                    , "token_type"   .= tt
                    , "expires_in"   .= expires
                    ] ++ maybe [] (\r -> ["refresh_token" .= TE.decodeUtf8 r]) mr
                      ++ maybe [] (\s -> ["scope"         .= TE.decodeUtf8 s]) ms

-- See http://tools.ietf.org/html/rfc6749#section-5.2 for error handling
data TokenError = InvalidRequest Text        |
                  InvalidClient              |
                  InvalidGrant Text          |
                  UnauthorizedClient Text    |
                  UnsupportedGrantType       |
                  InvalidScope Text
                  deriving (Show, Eq)

instance ToJSON TokenError where
    toJSON e = object $ ("error" .= err) : maybe [] (\m -> ["error_description" .= m]) desc
      where
        (err, desc) = case e of
                      InvalidRequest m -> ("invalid_request" :: Text, Just m)
                      InvalidClient    -> ("invalid_client", Nothing)
                      InvalidGrant   m -> ("invalid_grant",  Just m)
                      UnauthorizedClient m -> ("unauthorized_client", Just m)
                      UnsupportedGrantType -> ("unsupported_grant_type", Nothing)
                      InvalidScope m       -> ("invalid_scope", Just m)

processTokenRequest :: Monad m => Map Text [Text]
                    -> Client
                    -> POSIXTime
                    -> LoadAuthorization m
                    -> AuthenticateResourceOwner m
                    -> CreateAccessToken m
                    -> DecodeRefreshToken m
                    -> m (Either TokenError AccessTokenResponse)
processTokenRequest env client now getAuthorization authenticateResourceOwner createAccessToken decodeRefreshToken = runEitherT $ do
    grantType <- getGrantType
    (!mUser, !tokenGrantType, !grantedScope) <- case grantType of
        AuthorizationCode -> do
            code  <- requireParam env "code"
            authz <- lift (getAuthorization code) >>= maybe (left $ InvalidGrant "Invalid authorization code") return
            mURI  <- maybeParam env "redirect_uri"
            validateAuthorization authz client now mURI
            return (Just $ authorizedSubject authz, AuthorizationCode, authorizedScope authz)

        ClientCredentials -> do
            s <- getClientScope
            return (Nothing, ClientCredentials, s)

        ResourceOwner -> do
            username <- requireParam env "username"
            password <- requireParam env "password"
            s <- getResourceOwnerScope
            mUser <- lift $ authenticateResourceOwner username password
            case mUser of
                Nothing -> left $ InvalidGrant "authentication failed"
                _       -> return (mUser, ResourceOwner, s)

        RefreshToken -> do
            rt <- requireParam env "refresh_token"
            AccessGrant mu cid gt' gs gexp <- lift (decodeRefreshToken client rt) >>= maybe (left $ InvalidGrant "Invalid refresh token") return
            s <- getRefreshScope gs
            checkExpiry gexp
            if cid /= clientId client
                then left $ InvalidGrant "Refresh token was issued to a different client"
                else return (mu, gt', s)

        Implicit -> left $ InvalidGrant "Implicit grant is not supported by the token endpoint"


    (token, mRefreshToken, tokenTTL) <- lift $ createAccessToken mUser client tokenGrantType grantedScope now
    return AccessTokenResponse
              { accessToken = token
              , tokenType   = Bearer
              , expiresIn   = tokenTTL
              , refreshToken = mRefreshToken
              , scope        = Nothing
              }

  where
    checkExpiry t = when (t < now) $ left $ InvalidGrant "Refresh token has expired"

    getGrantType = do
        gt <- requireParam env "grant_type"
        case lookup gt grantTypes of
            Nothing -> left UnsupportedGrantType
            Just g  -> if g `elem` authorizedGrantTypes client
                       then right g
                       else left $ UnauthorizedClient $ T.append "Client is not authorized to use grant: " gt
    getClientScope = do
        mScope <- getRequestedScope
        either (left . InvalidScope) right $ I.checkClientScope client mScope

    getResourceOwnerScope = getClientScope

    getRefreshScope existingScope = do
        mScope <- getRequestedScope
        either (left . InvalidScope) right $ I.checkRequestedScope existingScope mScope

    getRequestedScope = maybeParam env "scope" >>= \ms -> return $ fmap (T.splitOn " ") ms

validateAuthorization :: (Monad m) => Authorization -> Client -> NominalDiffTime -> Maybe Text -> EitherT TokenError m ()
validateAuthorization (Authorization _ issuedTo issuedAt _ authzURI) client now mURI
    | mURI /= authzURI = left . InvalidGrant $ case mURI of
                                                  Nothing -> "Missing redirect_uri"
                                                  _       -> "Invalid redirect_uri"
    | clientId client /= issuedTo = left $ InvalidGrant "Code was issue to another client"
    | now - issuedAt > authCodeTTL = left $ InvalidGrant "Expired code"
    | otherwise = return ()

authCodeTTL :: NominalDiffTime
authCodeTTL = 300

requireParam :: (Monad m) => Map Text [Text] -> Text -> EitherT TokenError m Text
requireParam env name = case I.requireParam env name of
                          Right p -> right p
                          Left  m -> left $ InvalidRequest m

maybeParam :: (Monad m) => Map Text [Text] -> Text -> EitherT TokenError m (Maybe Text)
maybeParam env name = case I.maybeParam env name of
                          Right p -> right p
                          Left  m -> left $ InvalidRequest m

