{-# LANGUAGE OverloadedStrings #-}
{-# OPTIONS_GHC -fno-warn-missing-signatures #-}

module Broch.OAuth2.AuthorizationSpec where

import Control.Monad.Identity
import qualified Data.Map as Map
import Test.Hspec
import Test.HUnit hiding (Test)

import Broch.Model
import Broch.OAuth2.Authorize
import Broch.OAuth2.TestData

spec :: Spec
spec = describe "Authorization endpoint requests" $ evilClientErrorSpec >> authzRequestErrorSpec

data TestUser = TU SubjectId

instance Subject TestUser where
    subjectId (TU s) = s
    authTime  _      = now

doAuthz env = runIdentity $ processAuthorizationRequest getClient gc createAuthorization resourceOwnerApproval createAccessToken createIdToken (TU "cat") env now

gc = return "acode"

createAuthorization :: CreateAuthorization Identity TestUser
createAuthorization "acode" (TU "cat") Client {clientId = "appclient"} _ _ _ _ = return ()
createAuthorization _ _ _ _ _ _ _ = fail "Invalid authz data"

resourceOwnerApproval _ _ scope _ = return scope

createIdToken = undefined
createAccessToken = undefined

invalidClient   = Left . MaliciousClient . InvalidClient
invalidRedirect = Left $ MaliciousClient InvalidRedirectUri
clientError     = Left . ClientRedirectError

evilClientErrorSpec =
    describe "A potentially malicious client request" $ do
      it "returns an error if client_id is unknown" $
        doAuthz (Map.insert "client_id" ["badclient"] appEnv) @?= invalidClient "Client does not exist"
      it "returns an error if client_id is missing" $
        doAuthz (Map.delete "client_id" appEnv) @?= invalidClient "Missing client_id"
      it "returns an error if redirect_uri doesn't match client's" $
        doAuthz (Map.insert "redirect_uri" ["https://badclient"] appEnv) @?= invalidRedirect
      it "returns an error if redirect_uri is duplicated" $
        doAuthz (Map.insert "redirect_uri" ["http://app", "http://app"] appEnv) @?= invalidRedirect
      it "returns an error if redirect_uri contains a fragment" $
        doAuthz (Map.insert "redirect_uri" ["https://app#bad=yes"] appEnv) @?= Left (MaliciousClient FragmentInUri)
      it "returns an error if redirect_uri is missing for a client with multiple redirect_uris" $
        doAuthz (Map.delete "redirect_uri" appEnv) @?= Left (MaliciousClient MissingRedirectUri)
      it "missing redirect_uri is ok if client only has one registered" $
        doAuthz adminEnv @?= Right "http://admin?state=somestate&code=acode&scope=scope1%20scope2%20scope3%20admin"

authzRequestErrorSpec =
    describe "A malformed authorization request" $ do
      it "returns invalid_request for a duplicate state parameter" $
        doAuthz (Map.insert "state" ["astate", "anotherstate"] appEnv) @?= clientError "http://app?error=invalid_request&error_description=Duplicate%20state"
      it "returns invalid_request for a missing response_type" $
        doAuthz (Map.delete "response_type" appEnv) @?= clientError "http://app?state=somestate&error=invalid_request&error_description=Missing%20response_type"


appEnv = Map.fromList [("client_id", ["app"]), ("state", ["somestate"]), ("redirect_uri", ["http://app"]), ("response_type", ["code"])]
adminEnv = Map.insert "client_id" ["admin"] $ Map.insert "redirect_uri" ["http://admin"] $ appEnv
