{-# LANGUAGE TypeFamilies, OverloadedStrings, GADTs,
             FlexibleContexts, MultiParamTypeClasses, TemplateHaskell,
             GeneralizedNewtypeDeriving, QuasiQuotes #-}


import Yesod.Core (toWaiApp)
import Database.Persist.Sqlite (createSqlitePool)
import Network.Wai.Middleware.RequestLogger (logStdoutDev)
import Network.Wai.Handler.Warp (run)

import Broch.TestApp

main :: IO ()
main = createSqlitePool "broch.db3" 5 >>= makeTestApp testClients >>= toWaiApp >>= run 4000 . logStdoutDev

