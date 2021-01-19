import Foundation
import Capacitor
import FirebaseAuth

class AppleWebProviderHandler: NSObject, ProviderHandler {
    var provider: OAuthProvider? = nil
    var plugin: CapacitorFirebaseAuth? = nil
    
    func initialize(plugin: CapacitorFirebaseAuth) {
        print("Initializing Apple Provider Handler")
        self.plugin = plugin
        
        self.provider = OAuthProvider(providerID: "apple.com")
        
        self.provider?.customParameters = [
            "lang": self.plugin?.languageCode ?? "en"
        ]
    }

    func signIn(call: CAPPluginCall) {
        DispatchQueue.main.async {
            self.provider?.getCredentialWith(nil) { credential, error in
              if error != nil {
                print(error?.localizedDescription ?? "A failure occurs in Apple sign in.")
                self.plugin!.handleError(message: "A failure occurs in Apple sign in.")
                return
              }
              if credential != nil {
                Auth.auth().signIn(with: credential!) { (authResult, error) in
                    if error != nil {
                      print(error?.localizedDescription ?? "A failure occurs in Apple sign in.")
                      self.plugin!.handleError(message: "A failure occurs in Apple sign in.")
                      return
                    }
                    self.plugin?.handleAuthCredentials(credential: (authResult?.credential!)!);
                }
                
              }
            }
        }
    }
    
    func isAuthenticated() -> Bool {
        return false
    }
    
    func fillResult(credential: AuthCredential?, data: PluginResultData) -> PluginResultData {
        var jsResult: PluginResultData = [:]
        
        data.forEach { (key, value) in
            jsResult[key] = value
        }
        
        let twitterCredential = credential as! OAuthCredential
        
        jsResult["idToken"] = twitterCredential.accessToken
        jsResult["secret"] = twitterCredential.secret
        
        return jsResult
    }
    
    func signOut() {
        // there is nothing to do here
        print("AppleWebProviderHandler.signOut called.");
    }
}
