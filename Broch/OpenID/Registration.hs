{-# LANGUAGE OverloadedStrings, DeriveGeneric #-}

module Broch.OpenID.Registration where

import           Control.Applicative (pure, (<$>))
import           Data.Aeson
import           Data.Maybe (fromMaybe)
import           Data.Text (Text)
import           GHC.Generics (Generic)
import           Jose.Jwa
import           Jose.Jwk

import           Broch.Model

data RegistrationError = InvalidRedirectUri
                       | InvalidMetaData Text

instance ToJSON RegistrationError where
    toJSON InvalidRedirectUri  = object ["error" .= ("invalid_redirect_uri" :: Text)]
    toJSON (InvalidMetaData m) = object
        [ "error" .= ("invalid_client_metadata" :: Text)
        , "error_description" .= m
        ]


type RegisterClient m = ClientMetaData
                     -> m (Either RegistrationError Client)

data AppType = Web | Native deriving (Eq, Show)

instance ToJSON AppType where
    toJSON Web    = String "web"
    toJSON Native = String "native"

instance FromJSON AppType where
    parseJSON = withText "AppType" $ \t -> case t of
        "web"    -> pure Web
        "native" -> pure Native
        _        -> fail "Invalid application_type"

data ClientMetaData = ClientMetaData
    { redirect_uris :: [Text]
    , response_types :: Maybe [ResponseType]
    , grant_types :: Maybe [GrantType]
    , application_type :: Maybe AppType
    , contacts :: Maybe [Text]
    , client_name :: Maybe Text
    , logo_uri :: Maybe Text
    , client_uri :: Maybe Text
    , policy_uri :: Maybe Text
    , tos_uri :: Maybe Text
    , jwks_uri :: Maybe Text
    , jwks :: Maybe JwkSet
    , sector_identifier_uri :: Maybe Text
    , subject_type :: Maybe Text
    , id_token_signed_response_alg :: Maybe JwsAlg
    , id_token_encrypted_response_alg :: Maybe JweAlg
    , id_token_encrypted_response_enc :: Maybe Enc
    , userinfo_signed_response_alg :: Maybe JwsAlg
    , userinfo_encrypted_response_alg :: Maybe JweAlg
    , userinfo_encrypted_response_enc :: Maybe Enc
    , request_object_signing_alg :: Maybe JwsAlg
    , request_object_encryption_alg :: Maybe JweAlg
    , request_object_encryption_enc :: Maybe Enc
    , token_endpoint_auth_method :: Maybe ClientAuthMethod
    , token_endpoint_auth_signing_alg :: Maybe JwsAlg
    , default_max_age :: Maybe Int
    , require_auth_time :: Maybe Bool
    , default_acr_values :: Maybe [Text]
    , initiate_login_uri :: Maybe Text
    , request_uris :: Maybe [Text]
    } deriving (Show, Generic)


makeClient :: ClientId -> Text -> ClientMetaData -> Either RegistrationError Client
makeClient cid csec md = do
    idAlgs     <- makeAlgorithmPrefs (id_token_signed_response_alg md) (id_token_encrypted_response_alg md) (id_token_encrypted_response_enc md)
    infoAlgs   <- makeAlgorithmPrefs (userinfo_signed_response_alg md) (userinfo_encrypted_response_alg md) (userinfo_encrypted_response_enc md)
    reqObjAlgs <- makeAlgorithmPrefs (request_object_signing_alg   md) (request_object_encryption_alg md)   (request_object_encryption_enc md)
    return Client
        { clientId = cid
        , clientSecret = Just csec
        , authorizedGrantTypes = fromMaybe [AuthorizationCode] (grant_types md)
        , redirectURIs = redirect_uris md
        , accessTokenValidity  = 24 * 60 * 60
        , refreshTokenValidity = 30 * 24 * 60 * 60
        , allowedScope = [OpenID, Profile, Email, Address, Phone]
        , autoapprove = False
        , tokenEndpointAuthMethod = fromMaybe ClientSecretBasic $ token_endpoint_auth_method md
        , tokenEndpointAuthAlg    = token_endpoint_auth_signing_alg md
        , clientKeysUri           = jwks_uri md
        , clientKeys              = keys <$> jwks md
        , idTokenAlgs             = idAlgs
        , userInfoAlgs            = infoAlgs
        , requestObjAlgs          = reqObjAlgs
        }
  where
    makeAlgorithmPrefs Nothing   Nothing  Nothing  = return Nothing
    makeAlgorithmPrefs (Just s)  Nothing  Nothing  = return . Just $ AlgPrefs (Just s)        NotEncrypted
    makeAlgorithmPrefs s         (Just a) (Just e) = return . Just $ AlgPrefs s (E a e)
    makeAlgorithmPrefs s         (Just a) Nothing  = return . Just $ AlgPrefs s (E a A128CBC_HS256)
    makeAlgorithmPrefs _         Nothing (Just _)  = Left (InvalidMetaData "Encryption 'alg' must be provided if 'enc' is set")

instance FromJSON ClientMetaData

instance ToJSON ClientMetaData

