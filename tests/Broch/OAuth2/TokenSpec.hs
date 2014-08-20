{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-missing-signatures #-}

module Broch.OAuth2.TokenSpec where

import Control.Applicative ((<$>))
import Control.Monad.Identity
import qualified Data.ByteString as B
import qualified Data.ByteString.Base64 as B64
import Data.Map (Map)
import qualified Data.Map as Map
import Data.Text (Text)

import Test.Hspec
import Test.HUnit hiding (Test)

import qualified Data.Text as T
import qualified Data.Text.Encoding as TE

import Broch.Model
import Broch.OAuth2.Token
import Broch.OAuth2.TestData


spec :: Spec
spec = grantTypeParameterErrorsSpec >> authorizationCodeTokenRequestSpec
        >> clientCredentialsTokenRequestSpec >> resourceOwnerGrantSpec
        >> refreshTokenGrantSpec

success t = Right $ AccessTokenResponse t Bearer 987 Nothing (Just "refreshtoken") Nothing

doToken env client = runIdentity $ processTokenRequest env authzHdr (\_ -> return $ Just client) now loadAuthorization authenticateResourceOwner createAccessToken createIdToken decodeRefreshToken
  where
    authzHdr = case clientSecret client of
        Nothing  -> Nothing
        Just sec -> Just $ B.concat ["Basic ", B64.encode $ TE.encodeUtf8 $ T.concat [clientId client, ":", sec]]


grantTypeParameterErrorsSpec =
    describe "A request with grant_type parameter error(s) (5.2)" $ do
      it "returns invalid_request if grant_type is missing" $
        doToken Map.empty appClient @?= (Left $ InvalidRequest "Missing grant_type")

      it "returns invalid_request if grant_type is empty" $
        doToken (Map.singleton "grant_type" [""]) appClient @?= (Left $ InvalidRequest "Empty grant_type")

      it "returns invalid_request if grant_type has multiple values" $
        doToken (Map.singleton "grant_type" ["authorization_code", "authorization_code"]) appClient @?= (Left $ InvalidRequest "Duplicate grant_type")

      it "returns invalid_grant for implicit grant" $
        doToken (Map.singleton "grant_type" ["implicit"]) allClient @?= (Left $ InvalidGrant "Implicit grant is not supported by the token endpoint")

      it "returns unsupported_grant_type for unknown grant type" $
        doToken (Map.singleton "grant_type" ["weird_unknown"]) appClient @?= Left UnsupportedGrantType

authorizationCodeTokenRequestSpec =
    describe "An authorization code token request (4.1)" $ do
      it "is successful if the request is valid" $
        doToken authCodeEnv appClient @?= success "cat:app"

      it "is returns an id_token if openid scope is requested" $ do
        let env = Map.insert "code" ["catoic"] authCodeEnv
        let idt = idToken <$> doToken env appClient
        idt @?= (Right $ Just "an_id_token")

      it "returns invalid_request if code is missing (5.2)" $
        doToken (Map.delete "code" authCodeEnv) appClient @?= (Left $ InvalidRequest "Missing code")

      it "returns invalid_grant if redirect_uri does not equal the authorization value (5.2)" $ do
        let env = Map.insert "redirect_uri" ["http://app2"] authCodeEnv
        doToken env appClient @?= (Left $ InvalidGrant "Invalid redirect_uri")

      -- This is really just a special case of not equal to the authorization value
      it "returns invalid_grant if redirect_uri is missing but was provided at authorization (5.2)" $
        doToken (Map.delete "redirect_uri" authCodeEnv) appClient @?= (Left $ InvalidGrant "Missing redirect_uri")

      it "returns invalid_grant for other client's code (4.1.3, 5.2)" $
        doToken authCodeEnv adminClient @?= (Left $ InvalidGrant "Code was issue to another client")

      it "returns invalid_grant for an expired code" $ do
        let env = Map.insert "code" ["expired"] authCodeEnv
        doToken env appClient @?= (Left $ InvalidGrant "Expired code")

      it "returns invalid_grant for an unknown code" $ do
        let env = Map.insert "code" ["whatcode"] authCodeEnv
        doToken env appClient @?= (Left $ InvalidGrant "Invalid authorization code")


authCodeEnv = Map.insert "code"         ["catcode"]    $
              Map.insert "redirect_uri" ["http://app"] $ createEnv AuthorizationCode

clientCredentialsTokenRequestSpec =
    describe "A client credentials token request" $ do
      it "is successful when the request is valid" $
        doToken (createEnv ClientCredentials) adminClient @?= success ":admin:scope1:scope2:scope3:admin"

      it "returns unauthorized_client when client is not allowed to use this grant (5.2)" $
        doToken (createEnv ClientCredentials) appClient
            @?= (Left $ UnauthorizedClient "Client is not authorized to use grant: client_credentials")

      it "is successful if the requested scope matches allowed scope" $ do
        let env = Map.insert "scope" ["scope3 scope2 scope1 admin"] (createEnv ClientCredentials)
        doToken env adminClient @?= success ":admin:scope3:scope2:scope1:admin"

      it "returns invalid_scope if the requested scope exceeds allowed scope" $ do
        let env = Map.insert "scope" ["scope0 scope1 admin"] (createEnv ClientCredentials)
        doToken env adminClient @?= (Left $ InvalidScope "Requested scope (scope0 scope1 admin) exceeds allowed scope (scope1 scope2 scope3 admin)")

resourceOwnerGrantSpec =
    describe "A resource owner token request" $ do
      it "is successful when the request is valid" $
        doToken env roClient @?= success "cat:ro:scope1:scope2:scope3"

      it "returns invalid_grant if user authentication fails" $
        doToken (Map.insert "password" ["notcat"] env) roClient @?= (Left $ InvalidGrant "authentication failed")
  where
    env = Map.insert "password" ["cat"] $
          Map.insert "username" ["cat"] $ createEnv ResourceOwner

refreshTokenGrantSpec =
    describe "A refresh token request" $ do
      it "is successful when the request is valid" $
        doToken (Map.insert "refresh_token" ["refreshtoken"] env) appClient @?= success "cat:app:scope1:scope2:scope3"
      it "returns invalid_request when the token is missing (5.2)" $
        doToken env appClient @?= (Left $ InvalidRequest "Missing refresh_token")
      it "returns invalid_grant when the token is invalid (5.2)" $
        doToken (Map.insert "refresh_token" ["invalidtoken"] env) appClient @?= (Left $ InvalidGrant "Invalid refresh token")
      it "returns invalid_grant when the token is expired (5.2)" $
        doToken (Map.insert "refresh_token" ["expiredtoken"] env) appClient @?= (Left $ InvalidGrant "Refresh token has expired")
      it "returns invalid_grant when the token was issued to a different client (5.2, 10.4)" $
        doToken (Map.insert "refresh_token" ["notappstoken"] env) appClient @?= (Left $ InvalidGrant "Refresh token was issued to a different client")
  where
    env = createEnv RefreshToken


createEnv :: GrantType -> Map Text [Text]
createEnv gt = Map.fromList [("grant_type", [grantTypeName gt])]

createAccessToken mUser client _ s _ = return (token, Just "refreshtoken", 987)
  where
    u = maybe "" id mUser
    token = TE.encodeUtf8 $ T.intercalate ":" ([u, clientId client] ++ (map scopeName s))

createIdToken :: (Monad m) => CreateIdToken m
createIdToken _ _ _ _ _ _ = return "an_id_token"


decodeRefreshToken _ "refreshtoken" = return $ Just catsGrant
decodeRefreshToken _ "notappstoken" = return $ Just $ catsGrant {granteeId = "otherapp"}
decodeRefreshToken _ "expiredtoken" = return $ Just $ catsGrant {grantExpiry = TokenTime $ now - 10}
decodeRefreshToken _ _              = return Nothing

catsGrant = AccessGrant (Just "cat") "app" AuthorizationCode appClientScope (TokenTime $ now + 999)
