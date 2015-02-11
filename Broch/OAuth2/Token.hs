{-# LANGUAGE BangPatterns, OverloadedStrings #-}

module Broch.OAuth2.Token
    ( TokenType (..)
    , AccessTokenResponse (..)
    , TokenError (..)
    , processTokenRequest
    )
where

import Control.Applicative
import Control.Error
import Control.Monad.Trans (lift)
import Control.Monad (when)
import Data.Aeson hiding (decode)
import Data.Aeson.Types (Parser)
import Data.ByteString (ByteString)
import Data.Map (Map)
import Data.Monoid
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time (NominalDiffTime)
import Data.Time.Clock.POSIX (POSIXTime)
import Jose.Jwt

import Broch.Model
import qualified Broch.OAuth2.Internal as I

data TokenType = Bearer deriving (Show, Eq)

instance ToJSON TokenType where
    toJSON Bearer = String "bearer"

instance FromJSON TokenType where
    parseJSON (String "bearer") = pure Bearer
    parseJSON _                 = mempty

-- TODO: newtypes for tokens scopestring etc
data AccessTokenResponse = AccessTokenResponse
  { accessToken  :: !ByteString
  , tokenType    :: !TokenType
  , expiresIn    :: !TokenTTL
  , idToken      :: !(Maybe Jwt)
  , refreshToken :: !(Maybe ByteString)
  , tokenScope   :: !(Maybe ByteString)
  } deriving (Show, Eq)

instance ToJSON AccessTokenResponse where
    toJSON (AccessTokenResponse t tt ex mi mr ms) =
        let expires = round ex :: Int
        in object $ [ "access_token" .= TE.decodeUtf8 t
                    , "token_type"   .= tt
                    , "expires_in"   .= expires
                    ] ++ maybe [] (\r -> ["refresh_token" .= TE.decodeUtf8 r]) mr
                      ++ maybe [] (\s -> ["scope"         .= TE.decodeUtf8 s]) ms
                      ++ maybe [] (\i -> ["id_token"      .= i]) mi

instance FromJSON AccessTokenResponse where
    parseJSON = withObject "AccessTokenResponse" $ \v ->
        AccessTokenResponse <$> fmap TE.encodeUtf8 (v .: "access_token")
                            <*> v .: "token_type"
                            <*> fmap fromIntegral (v .: "expires_in" :: Parser Int)
                            <*> v .:? "id_token"
                            <*> fmap (fmap TE.encodeUtf8) (v .:? "refresh_token")
                            <*> fmap (fmap TE.encodeUtf8) (v .:? "scope")

-- See http://tools.ietf.org/html/rfc6749#section-5.2 for error handling
-- invalid_client is dealt with in the ClientAuth module
data TokenError = InvalidRequest Text
                | InvalidGrant Text
                | UnauthorizedClient Text
                | UnsupportedGrantType
                | InvalidScope Text
                  deriving (Show, Eq)

instance ToJSON TokenError where
    toJSON e = object $ ("error" .= errr) : maybe [] (\m -> ["error_description" .= m]) desc
      where
        (errr, desc) = case e of
            InvalidRequest m -> ("invalid_request" :: Text, Just m)
            InvalidGrant   m -> ("invalid_grant",  Just m)
            UnauthorizedClient m -> ("unauthorized_client", Just m)
            UnsupportedGrantType -> ("unsupported_grant_type", Nothing)
            InvalidScope m       -> ("invalid_scope", Just m)

processTokenRequest :: (Applicative m, Monad m)
                    => Map Text [Text]
                    -> Client
                    -> POSIXTime
                    -> LoadAuthorization m
                    -> AuthenticateResourceOwner m
                    -> CreateAccessToken m
                    -> CreateIdToken m
                    -> DecodeRefreshToken m
                    -> m (Either TokenError AccessTokenResponse)
processTokenRequest env client now getAuthorization authenticateResourceOwner createAccessToken createIdToken decodeRefreshToken = runEitherT $ do
    grantType <- getGrantType
    (!uid, !idt, !tokenGrantType, !grantedScope) <- case grantType of
        AuthorizationCode -> do
            code  <- requireParam "code"
            authz <- lift (getAuthorization code) >>= maybe (left $ InvalidGrant "Invalid authorization code") return
            mURI  <- maybeParam "redirect_uri"
            validateAuthorization authz client now mURI
            let scp = authzScope authz
                usr = authzSubject authz
            idt <- if OpenID `elem` scp
                       then fmap Just $ lift $ createIdToken usr (authzAuthTime authz) client (authzNonce authz) now Nothing Nothing
                       else return Nothing
            return (Just usr, idt, AuthorizationCode, scp)

        ClientCredentials -> do
            scp <- getClientScope
            return (Nothing, Nothing, ClientCredentials, scp)

        ResourceOwner -> do
            username <- requireParam "username"
            password <- requireParam "password"
            s <- getResourceOwnerScope
            user <- lift $ authenticateResourceOwner username password
            case user of
                Nothing -> left $ InvalidGrant "authentication failed"
                _       -> return (user, Nothing, ResourceOwner, s)

        RefreshToken -> do
            rt <- requireParam "refresh_token"
            AccessGrant mu cid gt' gs gexp <- lift (decodeRefreshToken client rt) >>= maybe (left $ InvalidGrant "Invalid refresh token") return
            scp <- getRefreshScope gs
            checkExpiry gexp
            if cid /= clientId client
                then left $ InvalidGrant "Refresh token was issued to a different client"
                else return (mu, Nothing, gt', scp)

        Implicit -> left $ InvalidGrant "Implicit grant is not supported by the token endpoint"


    (!token, !refToken, !tokenTTL) <- lift $ createAccessToken uid client tokenGrantType grantedScope now
    return AccessTokenResponse
              { accessToken  = token
              , tokenType    = Bearer
              , expiresIn    = tokenTTL
              , idToken      = idt
              , refreshToken = refToken
              , tokenScope   = Nothing
              }

  where
    checkExpiry (IntDate t) = when (t < now) $ left $ InvalidGrant "Refresh token has expired"

    getGrantType = do
        gt <- requireParam "grant_type"
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

    getRequestedScope = maybeParam "scope" >>= \ms -> return $ fmap (map scopeFromName . T.splitOn " ") ms

    requireParam = eitherParam I.requireParam
    maybeParam   = eitherParam I.maybeParam
    eitherParam  f n  = either (left . InvalidRequest) right $ f env n


validateAuthorization :: (Monad m)
                      => Authorization
                      -> Client
                      -> NominalDiffTime
                      -> Maybe Text
                      -> EitherT TokenError m ()
validateAuthorization (Authorization _ issuedTo (IntDate issuedAt) _ _ authzURI _) client now mURI
    | mURI /= authzURI = left . InvalidGrant $ case mURI of
                                                  Nothing -> "Missing redirect_uri"
                                                  _       -> "Invalid redirect_uri"
    | clientId client /= issuedTo    = left $ InvalidGrant "Code was issue to another client"
    | now - issuedAt   > authCodeTTL = left $ InvalidGrant "Expired code"
    | otherwise = return ()

authCodeTTL :: NominalDiffTime
authCodeTTL = 300


