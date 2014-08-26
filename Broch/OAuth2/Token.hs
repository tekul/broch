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
import Control.Monad (join, when, unless)
import Data.Aeson
import Data.Aeson.Types (Parser)
import Data.Byteable (constEqBytes)
import Data.ByteString (ByteString)
import qualified Data.ByteString.Char8 as B
import qualified Data.ByteString.Base64 as B64
import Data.Map (Map)
import Data.Monoid
import Data.Text (Text)
import qualified Data.Text as T
import qualified Data.Text.Encoding as TE
import Data.Time (NominalDiffTime)
import Data.Time.Clock.POSIX (POSIXTime)

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
  , idToken      :: !(Maybe ByteString)
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
                      ++ maybe [] (\i -> ["id_token"      .= TE.decodeUtf8 i]) mi

instance FromJSON AccessTokenResponse where
    parseJSON = withObject "AccessTokenResponse" $ \v ->
        AccessTokenResponse <$> fmap TE.encodeUtf8 (v .: "access_token")
                            <*> v .: "token_type"
                            <*> fmap fromIntegral (v .: "expires_in" :: Parser Int)
                            <*> fmap (fmap TE.encodeUtf8) (v .:? "id_token")
                            <*> fmap (fmap TE.encodeUtf8) (v .:? "refresh_token")
                            <*> fmap (fmap TE.encodeUtf8) (v .:? "scope")

-- See http://tools.ietf.org/html/rfc6749#section-5.2 for error handling
data TokenError = InvalidRequest Text
                | InvalidClient
                | InvalidClient401
                | InvalidGrant Text
                | UnauthorizedClient Text
                | UnsupportedGrantType
                | InvalidScope Text
                  deriving (Show, Eq)

instance ToJSON TokenError where
    toJSON e = object $ ("error" .= errr) : maybe [] (\m -> ["error_description" .= m]) desc
      where
        invalidClient = ("invalid_client", Nothing)
        (errr, desc) = case e of
            InvalidRequest m -> ("invalid_request" :: Text, Just m)
            InvalidClient    -> invalidClient
            InvalidClient401 -> invalidClient
            InvalidGrant   m -> ("invalid_grant",  Just m)
            UnauthorizedClient m -> ("unauthorized_client", Just m)
            UnsupportedGrantType -> ("unsupported_grant_type", Nothing)
            InvalidScope m       -> ("invalid_scope", Just m)

processTokenRequest :: (Monad m)
                    => Map Text [Text]
                    -> Maybe ByteString
                    -> LoadClient m
                    -> POSIXTime
                    -> LoadAuthorization m
                    -> AuthenticateResourceOwner m
                    -> CreateAccessToken m
                    -> CreateIdToken m
                    -> DecodeRefreshToken m
                    -> m (Either TokenError AccessTokenResponse)
processTokenRequest env authzHeader getClient now getAuthorization authenticateResourceOwner createAccessToken createIdToken decodeRefreshToken = runEitherT $ do
    client    <- authenticateClient
    grantType <- getGrantType client
    (!uid, !idt, !tokenGrantType, !grantedScope) <- case grantType of
        AuthorizationCode -> do
            code  <- requireParam "code"
            authz <- lift (getAuthorization code) >>= maybe (left $ InvalidGrant "Invalid authorization code") return
            mURI  <- maybeParam "redirect_uri"
            validateAuthorization authz client now mURI
            let scp = authzScope authz
                usr = authzSubject authz
            idt <- if OpenID `elem` scp
                       then fmap Just $ lift $ createIdToken usr client (authzNonce authz) now Nothing Nothing
                       else return Nothing
            return (Just usr, idt, AuthorizationCode, scp)

        ClientCredentials -> do
            scp <- getClientScope client
            return (Nothing, Nothing, ClientCredentials, scp)

        ResourceOwner -> do
            username <- requireParam "username"
            password <- requireParam "password"
            s <- getResourceOwnerScope client
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
    checkExpiry (TokenTime t) = when (t < now) $ left $ InvalidGrant "Refresh token has expired"

    getGrantType client = do
        gt <- requireParam "grant_type"
        case lookup gt grantTypes of
            Nothing -> left UnsupportedGrantType
            Just g  -> if g `elem` authorizedGrantTypes client
                       then right g
                       else left $ UnauthorizedClient $ T.append "Client is not authorized to use grant: " gt
    getClientScope client = do
        mScope <- getRequestedScope
        either (left . InvalidScope) right $ I.checkClientScope client mScope

    getResourceOwnerScope = getClientScope

    getRefreshScope existingScope = do
        mScope <- getRequestedScope
        either (left . InvalidScope) right $ I.checkRequestedScope existingScope mScope

    getRequestedScope = maybeParam "scope" >>= \ms -> return $ fmap (map scopeFromName . T.splitOn " ") ms

    -- | Authenticate the client using one of the methods defined in
    -- http://openid.net/specs/openid-connect-core-1_0.html#ClientAuthentication
    -- On failure an invalid_client error is returned with a 400 error
    -- code, or 401 if the client used the Authorization header.
    -- See http://tools.ietf.org/html/rfc6749#section-5.2
    authenticateClient = do
        clid      <- maybeParam "client_id"
        secret    <- maybeParam "client_secret"
        assertion <- maybeParam "client_assertion"
        aType     <- maybeParam "assertion_type"

        client <- case (authzHeader, clid, secret, assertion, aType) of
            (Just h,  _, Nothing, Nothing, Nothing)         -> noteT InvalidClient401 $ basicAuth h
            (Nothing, Just cid, Just sec, Nothing, Nothing) -> noteT InvalidClient    $ checkClientSecret cid sec

            (Nothing, _, Nothing, Just a, Just "urn:ietf:params:oauth:client-assertion-type:jwt-bearer") -> error "client assertion not yet supported" -- decode claims, get client id, check signature
            (Nothing, _, Nothing, Nothing, Nothing) -> left InvalidClient
            _                                       -> left $ InvalidRequest "Multiple authentication credentials/mechanisms or malformed authentication data"
        checkClientId clid client

        return client

    basicAuth h    = do
        (cid, secret) <- hoistMaybe $ decodeHeader h
        checkClientSecret cid secret

    decodeHeader h = case B.split ' ' h of
                       ["Basic", b] -> either (const Nothing) creds $ B64.decode b
                       _            -> Nothing

    creds bs = case T.break (== ':') <$> TE.decodeUtf8' bs of
                 Left _       -> Nothing
                 Right (u, p) -> if T.length p == 0
                                 then Nothing
                                 else Just (u, T.tail p)

    checkClientSecret cid secret = do
        -- TODO: Fixed delay based on cid and secret
        client <- lift $ getClient cid
        hoistMaybe $ case client of
            Nothing -> Nothing
            Just c  -> clientSecret c >>= \s ->
                if constEqBytes (TE.encodeUtf8 s) (TE.encodeUtf8 secret)
                    then Just c
                    else Nothing

    checkClientId cid client = case cid of
        Nothing -> return ()
        Just c  -> unless (c == clientId client) $ left $ InvalidRequest "client_id parameter is invalid"

    requireParam = eitherParam I.requireParam
    maybeParam   = eitherParam I.maybeParam
    eitherParam  f n  = either (left . InvalidRequest) right $ f env n

validateAuthorization :: (Monad m) => Authorization
                      -> Client
                      -> NominalDiffTime
                      -> Maybe Text
                      -> EitherT TokenError m ()
validateAuthorization (Authorization _ issuedTo (TokenTime issuedAt) _ _ authzURI) client now mURI
    | mURI /= authzURI = left . InvalidGrant $ case mURI of
                                                  Nothing -> "Missing redirect_uri"
                                                  _       -> "Invalid redirect_uri"
    | clientId client /= issuedTo    = left $ InvalidGrant "Code was issue to another client"
    | now - issuedAt   > authCodeTTL = left $ InvalidGrant "Expired code"
    | otherwise = return ()

authCodeTTL :: NominalDiffTime
authCodeTTL = 300


