{-# LANGUAGE TypeFamilies, OverloadedStrings, GADTs,
             FlexibleContexts, MultiParamTypeClasses,
             GeneralizedNewtypeDeriving #-}

module Broch.Handler.Authorize
    ( getAuthorizeR
    , YesodOAuth2Server (..)
    )
where

import Yesod.Core
import Yesod.Auth

import Control.Monad.Error

import Data.List ((\\))
import Data.Maybe (fromMaybe)
import Data.Text (Text)
import qualified Data.Text as T
import Data.Time.Clock.POSIX
import Network.HTTP.Types
import qualified Data.Map as Map
import qualified Data.Text.Encoding as TE

import Broch.Class
import Broch.Model
import Broch.OAuth2.Authorize


class OAuth2Server site => YesodOAuth2Server site where
    approvalRoute :: site -> Route site


{-
  GET Request to the authorization endpoint.

  Used by authorization code and implicit grants.
 -}
getAuthorizeR :: (YesodOAuth2Server site, YesodAuth site, AuthId site ~ Text) => HandlerT site IO Html
getAuthorizeR = do
    user    <- maybeAuthId >>= maybe redirectLogin return
    env     <- liftM (toMap . reqGetParams) getRequest
    srvr    <- getYesod
    (client, mURI) <- either evilClientError return =<< (liftIO $ getClientAndRedirectURI (getClient srvr) env)
    let redirectURI = fromMaybe (defaultRedirectURI client) mURI
    -- From this point, all errors can be safely returned to the client
    maybeState   <- either (errorResponse redirectURI Nothing) return $ getState env
    (responseType, requestedScope) <- either (errorResponse redirectURI maybeState) return $ getGrantData env user client
    now     <- liftIO getPOSIXTime

    -- The scope approved by the user
    scope <- resourceOwnerApproval user client requestedScope now

    -- let scope = requestedScope
    -- TODO: Refactor to processAuthzRequest then either render approvals
    -- page or send response
    -- Parameter checking and extraction in the processauthzrequest part
    -- to give (user, client, redirectURI, state, scope, responsetype)

    case responseType of
      Code  -> do
                code <- liftIO generateCode
                liftIO $ createAuthorization srvr (TE.decodeUtf8 code) user client now scope mURI
                authzCodeResponse redirectURI maybeState code scope
      Token -> permissionDenied "Implicit grant not supported"
      _     -> permissionDenied "Response type not (yet) supported"
  where
    -- | Report a "bad client" error to the user without a redirect
    evilClientError :: EvilClientError -> HandlerT site IO a
    evilClientError = sendResponseStatus status400 . RepPlain . toContent . show

    -- | Reports an error to the client itself, via a redirect
    errorResponse :: Text -> Maybe Text -> AuthorizationError -> HandlerT site IO a
    errorResponse rURI mState e = redirectWith status302 $ authzErrorURL rURI mState e
    authzCodeResponse rURI mState code scope = redirectWith status302 $ authzCodeResponseURL rURI mState code scope

    resourceOwnerApproval uid client requestedScope now = do
        -- Try to load a previous approval
        site <- getYesod
        maybeApproval <- liftIO $ getApproval site uid client now
        case maybeApproval of
            -- TODO: Check scope overlap and allow asking for extra scope
            -- not previously granted
            Just (Approval _ _ scope _) -> return (scope \\ requestedScope)
            -- Nothing exists: Redirect to approval handler with scopes and client id
            Nothing -> redirectApproval (clientId client) requestedScope

redirectApproval :: YesodOAuth2Server site => ClientId -> [Scope] -> HandlerT site IO a
redirectApproval cid scope = do
    y <- getYesod
    setUltDestCurrent
    let query = [("client_id", cid), ("scope", T.intercalate " " scope)]
    redirect (approvalRoute y, query)


redirectLogin :: Yesod site => HandlerT site IO a
redirectLogin = do
    y <- getYesod
    setUltDestCurrent
    case authRoute y of
        Just z -> redirect z
        Nothing -> permissionDenied "Please configure authRoute"

toMap :: [(Text, a)] -> Map.Map Text [a]
toMap = Map.unionsWith (++) . map (\(x, y) -> Map.singleton x [y])
