package com.baumblatt.capacitor.firebase.auth.handlers;

import android.app.Activity;
import android.content.Context;
import android.content.Intent;
import android.util.Log;

import com.baumblatt.capacitor.firebase.auth.CapacitorFirebaseAuth;
import com.baumblatt.capacitor.firebase.auth.R;
import com.getcapacitor.JSObject;
import com.getcapacitor.PluginCall;
import com.google.firebase.auth.AuthCredential;

import com.google.firebase.auth.FirebaseUser;
import com.google.firebase.auth.TwitterAuthProvider;
import com.twitter.sdk.android.core.Callback;
import com.twitter.sdk.android.core.Result;
import com.twitter.sdk.android.core.Twitter;
import com.twitter.sdk.android.core.TwitterApiClient;
import com.twitter.sdk.android.core.TwitterAuthConfig;
import com.twitter.sdk.android.core.TwitterConfig;
import com.twitter.sdk.android.core.TwitterCore;
import com.twitter.sdk.android.core.TwitterException;
import com.twitter.sdk.android.core.TwitterSession;
import com.twitter.sdk.android.core.identity.TwitterLoginButton;



public class TwitterProviderHandler implements ProviderHandler {

    public static final int RC_TWITTER_SIGN_IN = 9001;
    private static final String TWITTER_TAG = "TwitterProviderHandler";

    private CapacitorFirebaseAuth plugin;
    private TwitterLoginButton twitterLoginButton;

    @Override
    public void init(final CapacitorFirebaseAuth plugin) {
        this.plugin = plugin;

        TwitterAuthConfig authConfig =  new TwitterAuthConfig(
                this.plugin.getContext().getString(R.string.twitter_consumer_key),
                this.plugin.getContext().getString(R.string.twitter_consumer_secret));

        TwitterConfig twitterConfig = new TwitterConfig.Builder(this.plugin.getContext())
                .twitterAuthConfig(authConfig)
                .build();

        Twitter.initialize(twitterConfig);

        this.twitterLoginButton = new TwitterLoginButton(this.plugin.getActivity());
        this.twitterLoginButton.setCallback(new Callback<TwitterSession>() {
            @Override
            public void success(Result<TwitterSession> result) {
                Log.d(TWITTER_TAG, "twitterLogin:success" + result);
                handleTwitterSession(result.data);
            }

            @Override
            public void failure(TwitterException exception) {
                Log.w(TWITTER_TAG, "twitterLogin:failure", exception);
                plugin.handleFailure("Twitter Sign In failure.", exception);
            }
        });
    }

    @Override
    public void signIn(PluginCall call) {
        Log.d(TWITTER_TAG, "Twitter SignIn starts..");
        this.twitterLoginButton.performClick();
    }

    @Override
    public int getRequestCode() {
        return TwitterAuthConfig.DEFAULT_AUTH_REQUEST_CODE;
    }

    @Override
    public void handleOnActivityResult(int requestCode, int resultCode, Intent data) {
        this.twitterLoginButton.onActivityResult(requestCode, resultCode, data);
    }

    private void handleTwitterSession(TwitterSession session) {
        Log.d(TWITTER_TAG, "handleTwitterSession:" + session);

        AuthCredential credential = TwitterAuthProvider.getCredential(
                session.getAuthToken().token,
                session.getAuthToken().secret);

        this.plugin.handleAuthCredentials(session.getAuthToken().token, credential);
    }

    @Override
    public void fillUser(JSObject jsUser, FirebaseUser user) {
        TwitterSession session = TwitterCore.getInstance().getSessionManager().getActiveSession();
        jsUser.put("secret", session.getAuthToken().secret);
    }

    @Override
    public void signOut() {
        TwitterCore.getInstance().getSessionManager().clearActiveSession();
    }
}