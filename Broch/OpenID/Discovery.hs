{-# LANGUAGE OverloadedStrings, DeriveGeneric, RecordWildCards #-}
module Broch.OpenID.Discovery
    ( OpenIDConfiguration (..)
    , mkOpenIDConfiguration
    )
where

import           Data.Aeson
import           Data.Text (Text)
import qualified Data.Text as T
import           GHC.Generics (Generic)
import           Jose.Jwa

import           Broch.Model
import           Broch.Server.Config

data OpenIDConfiguration = OpenIDConfiguration
    { issuer :: Text
    , authorization_endpoint :: Text
    , token_endpoint :: Text
    , userinfo_endpoint :: Text
    , jwks_uri :: Text
    , registration_endpoint :: Maybe Text
    , scopes_supported :: [Text]
    , response_types_supported :: [ResponseType]
    , acr_values_supported :: Maybe [Text]
    , subject_types_supported :: [Text] -- http://openid.net/specs/openid-connect-core-1_0.html#SubjectIDTypes
    , id_token_signing_alg_values_supported :: [JwsAlg]
    , id_token_encryption_alg_values_supported :: [JweAlg]
    , id_token_encryption_enc_values_supported :: [Enc]
    , user_info_signing_alg_values_supported :: [JwsAlg]
    , user_info_encryption_alg_values_supported :: [JweAlg]
    , user_info_encryption_enc_values_supported :: [Enc]
    , request_object_signing_alg_values_supported :: [JwsAlg]
    , request_object_encryption_alg_values_supported :: [JweAlg]
    , request_object_encryption_enc_values_supported :: [Enc]
    , token_endpoint_auth_methods_supported :: [ClientAuthMethod]
    , token_endpoint_auth_signing_alg_values_supported :: [JwsAlg]
    , display_values_supported :: Maybe [Text]
    , claim_types_supported :: Maybe [Text]
    , claims_supported :: [Text]
    , service_documentation :: Maybe Text
    , claims_locales_supported :: Maybe [Text]
    , ui_locales_supported :: Maybe [Text]
    , claims_parameter_supported :: Bool
    , request_parameter_supported :: Bool
    , request_uri_parameter_supported :: Bool
    , op_policy_uri :: Maybe Text
    , op_tos_uri :: Maybe Text
    } deriving (Show, Generic)


instance ToJSON OpenIDConfiguration where
    toJSON = genericToJSON omitNothingOptions

instance FromJSON OpenIDConfiguration where
    parseJSON = genericParseJSON omitNothingOptions

mkOpenIDConfiguration :: Config m s -> OpenIDConfiguration
mkOpenIDConfiguration Config {..} = OpenIDConfiguration
    { issuer = issuerUrl
    , authorization_endpoint = T.concat [url, "oauth/authorize"]
    , token_endpoint         = T.concat [url, "oauth/token"]
    , userinfo_endpoint      = T.concat [url, "connect/userinfo"]
    , jwks_uri               = T.concat [url, ".well-known/jwks"]
    , registration_endpoint  = Just $ T.concat [url, "connect/register"]
    , scopes_supported       = ["openid", "profile", "email", "address", "phone"]
    , response_types_supported = responseTypesSupported
    , acr_values_supported  = Nothing
    , subject_types_supported = ["public"]
    , id_token_signing_alg_values_supported = idTokenSigningAlgs algorithmsSupported
    , id_token_encryption_alg_values_supported = idTokenEncryptionAlgs algorithmsSupported
    , id_token_encryption_enc_values_supported = idTokenEncryptionEncs algorithmsSupported
    , user_info_signing_alg_values_supported = userInfoSigningAlgs algorithmsSupported
    , user_info_encryption_alg_values_supported = userInfoEncryptionAlgs algorithmsSupported
    , user_info_encryption_enc_values_supported = userInfoEncryptionEncs algorithmsSupported
    , request_object_signing_alg_values_supported = requestObjectSigningAlgs algorithmsSupported
    , request_object_encryption_alg_values_supported = requestObjectEncryptionAlgs algorithmsSupported
    , request_object_encryption_enc_values_supported = requestObjectEncryptionEncs algorithmsSupported
    , token_endpoint_auth_methods_supported = clientAuthMethodsSupported
    , token_endpoint_auth_signing_alg_values_supported = clientAuthSigningAlgs algorithmsSupported
    , display_values_supported = Nothing
    , claim_types_supported = Nothing
    , claims_supported = claimsSupported
    , service_documentation = Nothing
    , claims_locales_supported = Nothing
    , ui_locales_supported = Nothing
    , claims_parameter_supported = False
    , request_parameter_supported = False
    , request_uri_parameter_supported = False
    , op_policy_uri = Nothing
    , op_tos_uri    = Nothing
    }
 where
    url = case T.last issuerUrl of
        '/' -> issuerUrl
        _   -> issuerUrl `T.snoc` '/'
