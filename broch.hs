{-# LANGUAGE TypeFamilies, OverloadedStrings, GADTs,
             FlexibleContexts, MultiParamTypeClasses, TemplateHaskell,
             GeneralizedNewtypeDeriving, QuasiQuotes #-}


import Yesod.Core (toWaiApp)
import Database.Persist.Sqlite (createSqlitePool)
import Network.Wai.Middleware.RequestLogger (logStdoutDev)
import Network.Wai.Handler.Warp (run)

import Broch.Model
import Broch.TestApp


lookupClient = findClient clients
  where
    findClient []   _  = Nothing
    findClient (c:cs) cid
        | cid == clientId c = Just c
        | otherwise         = findClient cs cid

clients =
    [ Client "admin" (Just "adminsecret") [ClientCredentials]                []                            300 300 [] True []
    , Client "cf"    Nothing              [ResourceOwner]                    ["http://cf.com"]             300 300 [] True []
    , Client "app"   (Just "appsecret")   [AuthorizationCode, RefreshToken]  ["http://localhost:8080/app"] 300 300 [] False []
    ]

main :: IO ()
main = createSqlitePool "broch.db3" 5 >>= makeTestApp >>= toWaiApp >>= \waiApp -> run 4000 $ logStdoutDev waiApp

