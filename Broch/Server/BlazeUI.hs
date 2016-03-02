{-# LANGUAGE OverloadedStrings #-}

module Broch.Server.BlazeUI where

import           Control.Monad (forM_)
import           Data.Int (Int64)
import           Data.Text (Text)
import           Data.Time.Clock.POSIX

import           Text.Blaze.Html5 as H
import           Text.Blaze.Html5.Attributes as A hiding (scope)

import Broch.Model (Scope, scopeName, Client (..))

loginPage :: Maybe Text -> Html
loginPage requestId = html $ do
    H.head $ do
        H.title "Login"
        link ! rel "stylesheet" ! href "css/login.css"
    body $ do
        H.div ! class_ "logo" $ ""
        H.div ! class_ "loginform cf" $
            H.form ! method "post" ! action "/login" ! acceptCharset "utf-8" $ do
                case requestId of
                    Just rid -> input ! type_ "hidden" ! name "_rid" ! value (textValue rid)
                    Nothing  -> return ()
                ul $ do
                    li $ do
                        H.label ! for "username" $ "Username"
                        input ! type_ "text" ! name "username" ! placeholder "username" ! required ""
                    li $ do
                        H.label ! for "password" $ "Password"
                        input ! type_ "password" ! name "password" ! placeholder "password" ! required ""
                    li $
                        input ! type_ "submit" ! value "Login"

approvalPage :: Client -> [Scope] -> Int64 -> Html
approvalPage client scopes now = docTypeHtml $ html $ do
    H.head $
        H.title "Approvals"
    body $ do
        h2 "Authorization Approval Request"
        H.form ! method "post" ! action "/approval" $ do
            input ! type_ "hidden" ! name "client_id" ! value (toValue (clientId client))
            forM_ scopes $ \s ->
                input ! type_ "hidden" ! name "requested_scope" ! value (toValue (scopeName s))
            H.label ! for "expiry" $ "Expires after"
            select ! name "expiry" $ do
                option ! value (toValue oneDay) ! selected "" $ "One day"
                option ! value (toValue oneWeek) $ "One week"
                option ! value (toValue oneMonth) $ "30 days"
            forM_ scopes $ \s -> do
                input ! type_ "checkBox" ! name "scope" ! value (toValue (scopeName s)) ! checked ""
                toHtml (scopeName s)
                br

            input ! type_ "submit" ! value "Approve"
  where
    aDay    = round posixDayLength :: Int64
    oneDay  = now + aDay
    oneWeek = now + 7*aDay
    oneMonth = now + 30*aDay
