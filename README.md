# Search Guard Security Plugin for ES 1.5
Elasticsearch security for free.

Search Guard is a free and open source plugin for Elasticsearch which provides security features.

![Logo](https://raw.githubusercontent.com/floragunncom/sg-assets/master/logo/sg_logo_small.jpg) 

This is a fork of [floragunncom/search-guard](https://github.com/floragunncom/search-guard) which additionally provides LDAP authentication using an LDAP web api. For detailed usage, please refer to the original project.

To use LDAP web API authentication feature, configure `searchguard.authentication.ldap.api` in `elasticsearch.yml` to your LDAP web api URL. 

Your API should conform to certain format, specifically, accepts `GET` parameters `name` and `passwd`, and returns a JSON string which contains at least the keys `dn`(for user groups) and `sn`(for username), for detail, please refer to `src/php/ldap.php`.
