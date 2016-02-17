/*
 * Copyright 2015 floragunn UG (haftungsbeschränkt)
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 */

package com.floragunn.searchguard.authentication.backend.ldap;

import org.apache.directory.api.ldap.model.cursor.EntryCursor;
import org.apache.directory.api.ldap.model.entry.Entry;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.message.SearchScope;
import org.apache.directory.ldap.client.api.LdapConnection;
import org.elasticsearch.common.inject.Inject;
import org.elasticsearch.common.logging.ESLogger;
import org.elasticsearch.common.logging.Loggers;
import org.elasticsearch.common.settings.Settings;

import com.floragunn.searchguard.authentication.AuthCredentials;
import com.floragunn.searchguard.authentication.AuthException;
import com.floragunn.searchguard.authentication.LdapUser;
import com.floragunn.searchguard.authentication.User;
import com.floragunn.searchguard.authentication.backend.NonCachingAuthenticationBackend;
import com.floragunn.searchguard.authorization.ldap.LDAPAuthorizator;
import com.floragunn.searchguard.util.ConfigConstants;
import com.floragunn.searchguard.util.SecurityUtil;

import org.apache.commons.io.IOUtils;
import org.json.JSONObject;

import org.apache.http.HttpEntity;
import org.apache.http.NameValuePair;
import org.apache.http.HttpResponse;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.entity.UrlEncodedFormEntity;
import org.apache.http.message.BasicNameValuePair;
import org.apache.http.util.EntityUtils;
import org.apache.http.protocol.HTTP;

import java.util.ArrayList;
import java.util.List;
import java.io.UnsupportedEncodingException;
import org.json.JSONArray;

public class LDAPAuthenticationBackend implements NonCachingAuthenticationBackend {

    protected final ESLogger log = Loggers.getLogger(this.getClass());
    private final Settings settings;

    @Inject
    public LDAPAuthenticationBackend(final Settings settings) {
        this.settings = settings;
    }

    private User apiAuthenticate(final AuthCredentials authCreds, String apiUrl) throws AuthException, UnsupportedEncodingException {
        log.debug("LDAP auth using API");

        String cn, dn;
        String user = authCreds.getUsername();
        String passwd = String.valueOf(authCreds.getPassword());
        authCreds.clear();
        CloseableHttpClient httpclient = HttpClients.createDefault();

        ArrayList<String> memberOf = new ArrayList<String>();
        ArrayList<String> groups = new ArrayList<String>();
        try {
            HttpPost httpPost = new HttpPost(apiUrl);
            List <NameValuePair> data = new ArrayList <NameValuePair>();
            data.add(new BasicNameValuePair("name", user));
            data.add(new BasicNameValuePair("passwd", passwd));
            httpPost.setEntity(new UrlEncodedFormEntity(data, HTTP.UTF_8));
            HttpResponse response = httpclient.execute(httpPost);
            HttpEntity entity = response.getEntity();
            if(entity == null)
                throw new AuthException("LDAP API error");
            String jsonStr = EntityUtils.toString(entity);
            EntityUtils.consume(entity);
            log.debug("LDAP API return: " + jsonStr);
            JSONObject obj = new JSONObject(jsonStr);
            if (obj.getInt("status") != 0 || obj.getString("cn") == null)
                throw new AuthException("No user " + user + " found");
            cn = obj.getString("cn");
            dn = obj.getString("dn");
            String [] groupArr = dn.split(",OU=");
            // remove CN at head and DC at tail
            for (int i = 1; i < groupArr.length - 1; i++)
                groups.add(groupArr[i]);
            /*
            JSONArray memberof = obj.getJSONArray("memberof");
            if (memberof != null)
                for (int i = 0; i < memberof.length(); i++)
                    memberOf.add(memberof.get(i).toString());
            */

        }
        catch (final Exception e) {
            log.error(e.toString(), e);
            throw new AuthException(e);
        }
        return new User(cn, groups);
    }

    @Override
    public User authenticate(final AuthCredentials authCreds) throws AuthException {
        final String apiUrl = settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_LDAP_API, null);

        try {
            if (apiUrl != null)
                return this.apiAuthenticate(authCreds, apiUrl);
        } catch (Exception e) {
            log.error(e.toString(), e);
            throw new AuthException(e);
        }

        LdapConnection ldapConnection = null;
        final String user = authCreds.getUsername();

        final char[] password = authCreds.getPassword();
        authCreds.clear();

        EntryCursor result = null;

        try {

            ldapConnection = LDAPAuthorizator.getConnection(settings);

            final String bindDn = settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_LDAP_BIND_DN, null);

            if (bindDn != null) {
                ldapConnection.bind(bindDn, settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_LDAP_PASSWORD, null));
            } else {
                ldapConnection.anonymousBind();
            }

            result = ldapConnection.search(settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_LDAP_USERBASE, ""),
                    settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_LDAP_USERSEARCH, "(sAMAccountName={0})").replace("{0}", user),
                    SearchScope.SUBTREE);

            if (!result.next()) {
                throw new AuthException("No user " + user + " found");
            }

            final Entry entry = result.get();
            final String dn = entry.getDn().toString();

            if (result.next()) {
                throw new AuthException("More than one user found");
            }

            log.trace("Disconnect {}", bindDn == null ? "anonymous" : bindDn);

            SecurityUtil.unbindAndCloseSilently(ldapConnection);
            ldapConnection = LDAPAuthorizator.getConnection(settings);

            log.trace("Try to authenticate dn {}", dn);

            ldapConnection.bind(dn, new String(password));

            final String usernameAttribute = settings.get(ConfigConstants.SEARCHGUARD_AUTHENTICATION_LDAP_USERNAME_ATTRIBUTE, null);
            String username = dn;

            if (usernameAttribute != null && entry.get(usernameAttribute) != null) {
                username = entry.get(usernameAttribute).getString();
            }

            log.debug("Authenticated username {}", username);

            return new LdapUser(username, entry);

        } catch (final Exception e) {
            log.error(e.toString(), e);
            throw new AuthException(e);
        } finally {
            if (result != null) {
                result.close();
            }

            SecurityUtil.unbindAndCloseSilently(ldapConnection);
        }

    }

}
