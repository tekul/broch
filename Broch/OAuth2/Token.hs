{-# LANGUAGE BangPatterns, OverloadedStrings #-}

module Broch.OAuth2.Token
    ( TokenType (..)
    , AccessTokenResponse (..)
    , TokenError (..)
    , processTokenRequest
    )
where

import Control.Error
import Control.Monad.Trans (lift)
import Control.Monad (when)
import Data.Aeson hiding (decode)
import Data.Aeson.Types (Parser)
import Data.ByteString (ByteString)
import Data.Map (Map)
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time (NominalDiffTime)
import Data.Time.Clock.POSIX (POSIXTime)
import Jose.Jwt

import Broch.Model
import Broch.URI
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
                | InternalError Text
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
            InternalError m      -> ("server_error", Just m)

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
processTokenRequest env client now getAuthorization authenticateResourceOwner createAccessToken createIdToken decodeRefreshToken = runExceptT $ do
    grantType <- getGrantType
    (!uid, !idt, !tokenGrantType, !grantedScope) <- case grantType of
        AuthorizationCode -> do
            code  <- requireParam "code"
            authz <- lift (getAuthorization code) >>= maybe (throwE $ InvalidGrant "Invalid authorization code") return
            uriParam <- maybeParam "redirect_uri"
            mURI <- case uriParam of
                Nothing -> return Nothing
                Just u  -> hoistEither $ fmapL InvalidRequest (Just <$> parseURI u)
            validateAuthorization authz client now mURI
            let scp = authzScope authz
                usr = authzSubject authz
            idt <- if OpenID `elem` scp
                       then fmap Just $ lift $ createIdToken usr (authzAuthTime authz) client (authzNonce authz) now Nothing Nothing
                       else return Nothing
            idt' <- case idt of
                Just (Left jwtErr) -> throwE $ InvalidRequest $ T.pack ("Failed to create id_token: " ++ show jwtErr)
                Just (Right jwt)   -> return (Just jwt)
                Nothing            -> return Nothing

            return (Just usr, idt', AuthorizationCode, scp)

        ClientCredentials -> do
            scp <- getClientScope
            return (Nothing, Nothing, ClientCredentials, scp)

        ResourceOwner -> do
            username <- requireParam "username"
            password <- requireParam "password"
            s <- getResourceOwnerScope
            user <- lift $ authenticateResourceOwner username password
            case user of
                Nothing -> throwE $ InvalidGrant "authentication failed"
                _       -> return (user, Nothing, ResourceOwner, s)

        RefreshToken -> do
            rt <- requireParam "refresh_token"
            AccessGrant mu cid gt' gs gexp <- lift (decodeRefreshToken client rt) >>= maybe (throwE $ InvalidGrant "Invalid refresh token") return
            scp <- getRefreshScope gs
            checkExpiry gexp
            if cid /= clientId client
                then throwE $ InvalidGrant "Refresh token was issued to a different client"
                else return (mu, Nothing, gt', scp)

        Implicit  -> throwE $ InvalidGrant "Implicit grant is not supported by the token endpoint"
        JwtBearer -> throwE UnsupportedGrantType

    (!token, !refToken, !tokenTTL) <- lift (createAccessToken uid client tokenGrantType grantedScope now) >>= hoistEither . fmapL InternalError

    return AccessTokenResponse
        { accessToken  = token
        , tokenType    = Bearer
        , expiresIn    = tokenTTL
        , idToken      = idt
        , refreshToken = refToken
        , tokenScope   = Nothing
        }

  where
    checkExpiry (IntDate t) = when (t < now) $ throwE $ InvalidGrant "Refresh token has expired"

    getGrantType = do
        gt <- requireParam "grant_type"
        case lookup gt grantTypes of
            Nothing -> throwE UnsupportedGrantType
            Just g  -> if g `elem` authorizedGrantTypes client
                       then return g
                       else throwE $ UnauthorizedClient $ T.append "Client is not authorized to use grant: " gt
    getClientScope = do
        mScope <- getRequestedScope
        either (throwE . InvalidScope) return $ I.checkClientScope client mScope

    getResourceOwnerScope = getClientScope

    getRefreshScope existingScope = do
        mScope <- getRequestedScope
        either (throwE . InvalidScope) return $ I.checkRequestedScope existingScope mScope

    getRequestedScope = maybeParam "scope" >>= \ms -> return $ fmap (map scopeFromName . T.splitOn " ") ms

    requireParam = eitherParam I.requireParam
    maybeParam   = eitherParam I.maybeParam
    eitherParam  f n  = either (throwE . InvalidRequest) return $ f env n


validateAuthorization :: (Monad m)
    => Authorization
    -> Client
    -> NominalDiffTime
    -> Maybe URI
    -> ExceptT TokenError m ()
validateAuthorization (Authorization _ issuedTo (IntDate issuedAt) _ _ authzURI _) client now mURI
    | mURI /= authzURI = throwE . InvalidGrant $ maybe "Missing redirect_uri" (const "Invalid redirect_uri") mURI
    | clientId client /= issuedTo    = throwE $ InvalidGrant "Code was issue to another client"
    | now - issuedAt   > authCodeTTL = throwE $ InvalidGrant "Expired code"
    | otherwise = return ()

authCodeTTL :: NominalDiffTime
authCodeTTL = 300
