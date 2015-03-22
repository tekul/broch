{-# LANGUAGE OverloadedStrings #-}

module Broch.Server.BlazeUI where

import           Control.Monad (forM_)
import           Data.Int (Int64)
import           Data.Text (Text)
import           Data.Time.Clock.POSIX

import           Text.Blaze.Html5 as H
import           Text.Blaze.Html5.Attributes hiding (scope, id)

import Broch.Model (Client (..))

loginPage :: Html
loginPage = html $ do
    H.head $
        H.title "Login"
    body $
        H.form ! method "post" ! action "/login" $ do
            input ! type_ "text" ! name "username"
            input ! type_ "password" ! name "password"
            input ! type_ "submit" ! value "Login"

approvalPage :: Client -> [Text] -> Int64 -> Html
approvalPage client scopes now = docTypeHtml $ html $ do
    H.head $
        H.title "Approvals"
    body $ do
        h2 "Authorization Approval Request"
        H.form ! method "post" ! action "/approval" $ do
            input ! type_ "hidden" ! name "client_id" ! value (toValue (clientId client))
            H.label ! for "expiry" $ "Expires after"
            select ! name "expiry" $ do
                option ! value (toValue oneDay) ! selected "" $ "One day"
                option ! value (toValue oneWeek) $ "One week"
                option ! value (toValue oneMonth) $ "30 days"
            forM_ scopes $ \s -> do
                input ! type_ "checkBox" ! name "scope" ! value (toValue s) ! checked ""
                toHtml s
                br

            input ! type_ "submit" ! value "Approve"
  where
    aDay    = round posixDayLength :: Int64
    oneDay  = now + aDay
    oneWeek = now + 7*aDay
    oneMonth = now + 30*aDay
