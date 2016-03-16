{-# LANGUAGE OverloadedStrings, DeriveGeneric, RecordWildCards #-}

module Broch.OpenID.Registration where

import           Control.Error (note)
import           Control.Monad (unless, when)
import           Data.Aeson
import           Data.List (nub)
import           Data.Maybe (fromMaybe)
import           Data.Text (Text)
import qualified Data.Text as T
import           GHC.Generics (Generic)
import           Jose.Jwa
import           Jose.Jwk
import           Network.URI (parseAbsoluteURI, uriAuthority, uriRegName)

import           Broch.Model
import           Broch.OpenID.Discovery hiding (jwks_uri)

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


makeClient :: OpenIDConfiguration -> ClientId -> Text -> ClientMetaData -> Either RegistrationError Client
makeClient OpenIDConfiguration {..} cid csec ClientMetaData {..} = do
    checkAlgs
    idAlgs     <- makeAlgorithmPrefs id_token_signed_response_alg id_token_encrypted_response_alg id_token_encrypted_response_enc
    infoAlgs   <- makeAlgorithmPrefs userinfo_signed_response_alg userinfo_encrypted_response_alg userinfo_encrypted_response_enc
    reqObjAlgs <- makeAlgorithmPrefs request_object_signing_alg request_object_encryption_alg request_object_encryption_enc
    checkAuthMethod
    uris <- checkRedirectURIs redirect_uris
    let clientGrantTypes = fromMaybe [AuthorizationCode] grant_types
    when ((Implicit `elem` clientGrantTypes) && (response_types_supported == [Code]))
        (Left (InvalidMetaData "Implicit grant is not supported"))

    -- Calculate sector identifier from redirect_uris if it isn't set.
    sectorId <- getSectorId uris

    return Client
        { clientId = cid
        , clientSecret = Just csec
        , authorizedGrantTypes = clientGrantTypes
        , redirectURIs = redirect_uris
        , accessTokenValidity  = 24 * 60 * 60
        , refreshTokenValidity = 30 * 24 * 60 * 60
        , allowedScope = [OpenID, Profile, Email, Address, Phone]
        , autoapprove = False
        , tokenEndpointAuthMethod = fromMaybe ClientSecretBasic token_endpoint_auth_method
        , tokenEndpointAuthAlg    = token_endpoint_auth_signing_alg
        , clientKeysUri           = jwks_uri
        , clientKeys              = keys <$> jwks
        , idTokenAlgs             = idAlgs
        , userInfoAlgs            = infoAlgs
        , requestObjAlgs          = reqObjAlgs
        , sectorIdentifierURI     = Just sectorId
        }
  where
    checkRedirectURIs [] = Right []
    checkRedirectURIs (r:rs) = case uri of
        Nothing -> Left InvalidRedirectUri
        Just u  -> fmap (u :) (checkRedirectURIs rs)
      where
        -- This will reject URIs with a fragment
        uri = parseAbsoluteURI (T.unpack r)

    getSectorId uris = case sector_identifier_uri of
        Just s  -> do
            uri <- note (InvalidMetaData "sector_identifier_uri is not an absolute URI") $ parseAbsoluteURI (T.unpack s)
            sectorIdentifierFromURI uri
        Nothing -> do
            hosts <- sequence (map sectorIdentifierFromURI uris)
            case nub hosts of
                [h] -> Right h
                []  -> Left (InvalidMetaData "Unable to calculate sector identifier: no redirect_uri set")
                _   -> Left (InvalidMetaData "Unable to calculate sector identifier: redirect_uri hosts are not unique")

    sectorIdentifierFromURI uri =
        fmap (T.pack . uriRegName) $ note (InvalidMetaData "URI has no authority component") (uriAuthority uri)


    makeAlgorithmPrefs Nothing   Nothing  Nothing  = return Nothing
    makeAlgorithmPrefs (Just s)  Nothing  Nothing  = return . Just $ AlgPrefs (Just s) NotEncrypted
    makeAlgorithmPrefs s         (Just a) (Just e) = return . Just $ AlgPrefs s (E a e)
    makeAlgorithmPrefs s         (Just a) Nothing  = return . Just $ AlgPrefs s (E a A128CBC_HS256)
    makeAlgorithmPrefs _         Nothing (Just _)  = Left (InvalidMetaData "Encryption 'alg' must be provided if 'enc' is set")

    checkAlgs = do
        checkSigAlg id_token_signed_response_alg id_token_signing_alg_values_supported "id_token"
        checkJweAlg id_token_encrypted_response_alg id_token_encryption_alg_values_supported "id_token"
        checkJweEnc id_token_encrypted_response_enc id_token_encryption_enc_values_supported "id_token"
        checkSigAlg userinfo_signed_response_alg user_info_signing_alg_values_supported "user_info"
        checkJweAlg userinfo_encrypted_response_alg user_info_encryption_alg_values_supported "user_info"
        checkJweEnc userinfo_encrypted_response_enc user_info_encryption_enc_values_supported "user_info"
        checkSigAlg request_object_signing_alg request_object_signing_alg_values_supported "request_object"
        checkJweAlg request_object_encryption_alg request_object_encryption_alg_values_supported "request_object"
        checkJweEnc request_object_encryption_enc request_object_encryption_enc_values_supported "request_object"
        checkSigAlg token_endpoint_auth_signing_alg token_endpoint_auth_signing_alg_values_supported "token_endpoint_auth"

    checkAuthMethod = case token_endpoint_auth_method of
        Nothing -> return ()
        Just a  -> unless (a `elem` token_endpoint_auth_methods_supported) (Left (InvalidMetaData "Unsupported token_endpoint_auth_method"))

    checkSigAlg Nothing _ _   = return ()
    checkSigAlg (Just s) as t = unless (s `elem` as) (algError t " signing alg value is unsupported")

    checkJweAlg Nothing _ _   = return ()
    checkJweAlg (Just a) as t = unless (a `elem` as) (algError t " encryption alg value is unsupported")

    checkJweEnc Nothing _ _   = return ()
    checkJweEnc (Just e) es t = unless (e `elem` es) (algError t " encryption enc value is unsupported")

    algError t msg = Left (InvalidMetaData (T.concat [t, msg]))

instance FromJSON ClientMetaData

instance ToJSON ClientMetaData
