{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-missing-signatures #-}

module Broch.OAuth2.AuthorizationSpec where

import Control.Monad.Identity
import qualified Data.Map as Map
import Data.Text (Text)
import Data.Time.Clock.POSIX
import Test.Hspec
import Test.HUnit hiding (Test)

import Broch.Model
import Broch.OAuth2.Authorize
import Broch.OAuth2.TestData

spec :: Spec
spec = describe "Authorization endpoint requests" $ evilClientErrorSpec >> authzRequestErrorSpec


doAuthz env = runIdentity $ processAuthorizationRequest getClient gc createAuthorization resourceOwnerApproval "cat"  env now

gc = return "acode"

createAuthorization :: Text -> Text -> Client -> POSIXTime -> [Scope] -> Maybe Text -> Identity ()
createAuthorization "acode" "cat" (Client "appclient" _ _ _ _ _ _ _) _ _ _ = return ()
createAuthorization _ _ _ _ _ _ = fail "Invalid authz data"

resourceOwnerApproval _ _ scope _= return scope

evilClientErrorSpec =
    describe "A potentially malicious client request" $ do
      it "returns an error if client_id is unknown" $
        doAuthz (Map.insert "client_id" ["badclient"] env) @?= (Left $ InvalidClient "Client does not exist")
      it "returns an error if client_id is missing" $
        doAuthz (Map.delete "client_id" env) @?= (Left $ InvalidClient "Missing client_id")
      it "returns an error if redirect_uri doesn't match client's" $
        doAuthz (Map.insert "redirect_uri" ["https://badclient"] env) @?= Left InvalidRedirectUri
      it "returns an error if redirect_uri is duplicated" $
        doAuthz (Map.insert "redirect_uri" ["http://app", "http://app"] env) @?= Left InvalidRedirectUri
      it "returns an error if redirect_uri contains a fragment" $
        doAuthz (Map.insert "redirect_uri" ["https://app#bad=yes"] env) @?= Left FragmentInUri
  where
    env = createEnv

authzRequestErrorSpec =
    describe "A malformed authorization request" $ do
      it "returns invalid_request for a duplicate state parameter" $
        doAuthz (Map.insert "state" ["astate", "anotherstate"] createEnv) @=? Right "http://app?error=invalid_request&error_description=Duplicate%20state"
      it "returns invalid_request for a missing response_type" $
        doAuthz (Map.delete "response_type" createEnv) @=? Right "http://app?error=invalid_request&error_description=Missing%20response_type&state=somestate"


createEnv = Map.fromList [("client_id", ["app"]), ("state", ["somestate"]), ("redirect_uri", ["http://app"]), ("response_type", ["code"])]
