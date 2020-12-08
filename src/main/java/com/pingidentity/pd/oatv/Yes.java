package com.pingidentity.pd.oatv;

import com.unboundid.directory.sdk.common.types.LogSeverity;
import com.unboundid.directory.sdk.http.config.OAuthTokenHandlerConfig;
import com.unboundid.directory.sdk.http.types.HTTPServerContext;
import com.unboundid.ldap.sdk.DN;
import com.unboundid.ldap.sdk.LDAPException;
import com.unboundid.ldap.sdk.ResultCode;
import com.unboundid.scim.sdk.OAuthToken;
import com.unboundid.scim.sdk.OAuthTokenStatus;
import com.unboundid.scim.sdk.SCIMRequest;
import com.unboundid.directory.sdk.http.api.OAuthTokenHandler;
import com.unboundid.util.args.ArgumentException;
import com.unboundid.util.args.ArgumentParser;
import com.unboundid.util.args.DNArgument;
import com.unboundid.util.args.StringArgument;

import java.util.List;

public class Yes extends OAuthTokenHandler {

    public static final String USER_DN = "user.dn";
    private DN userDN = null;
    private HTTPServerContext sc;

    @Override
    public String getExtensionName() {
        return "Yes";
    }

    @Override
    public String[] getExtensionDescription() {
        return new String[]{"Happy OAuth Token HAndler always says yes"};
    }

    @Override
    public void defineConfigArguments(ArgumentParser parser) throws ArgumentException {
        parser.addArgument(new DNArgument(null, USER_DN,"the user ID to return"));
    }

    @Override
    public void initializeTokenHandler(HTTPServerContext serverContext, OAuthTokenHandlerConfig config, ArgumentParser parser) throws LDAPException {
        sc = serverContext;
        applyConfiguration(config,parser,null,null);
    }

    @Override
    public ResultCode applyConfiguration(OAuthTokenHandlerConfig config, ArgumentParser parser, List<String> adminActionsRequired, List<String> messages) {
        userDN = parser.getDNArgument(USER_DN).getValue();
        return ResultCode.SUCCESS;
    }

    @Override
    public OAuthToken decodeOAuthToken(String s) {
        return new OAuthToken("{}");
    }

    @Override
    public boolean isTokenExpired(OAuthToken oAuthToken) {
        info("isTokenExpired called with "+oAuthToken.getFormattedValue());
        return false;
    }

    @Override
    public boolean isTokenAuthentic(OAuthToken oAuthToken) {
        info("isTokenAuthentic called with "+oAuthToken.getFormattedValue());
        return true;
    }

    @Override
    public boolean isTokenForThisServer(OAuthToken oAuthToken) {
        info("isTokenForThisServer called with "+oAuthToken.getFormattedValue());
        return true;
    }

    @Override
    public OAuthTokenStatus validateToken(OAuthToken oAuthToken, SCIMRequest scimRequest) {
        info("validateToken called with "+oAuthToken.getFormattedValue());
        return new OAuthTokenStatus(OAuthTokenStatus.ErrorCode.OK);
    }

    @Override
    public DN getAuthzDN(OAuthToken oAuthToken) {
        info("getAuthzDN called with "+oAuthToken.getFormattedValue());
        return userDN;
    }

    private final void exc(final Throwable t){
        sc.debugCaught(t);
    }

    private final void  out(final LogSeverity severity, final String msg) {
        sc.logMessage(LogSeverity.INFO,msg);
    }
    private final void info(final String msg) {
        System.out.println(msg);
        out(LogSeverity.INFO,msg);
    }
    private final void err(final String msg){
        out(LogSeverity.SEVERE_ERROR,msg);
    }
    private final void debug(final String msg){
        out(LogSeverity.DEBUG,msg);
    }
}
