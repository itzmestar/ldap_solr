# ldap_solr

`Apache solr` doesn't implictly provide support for ldap authentication. 
Provided `BasicAuthPlugin.java` file enables the solr to work with ldap authentication as well.

Notes: these changes will enable ldap authentication along with basic authentication in solr. It doesn't disable basic authentication.

Steps to compile & configure solr are as followed:

# Compile solr with changes:
1. Download the solr source code: https://github.com/apache/lucene-solr/tree/releases/lucene-solr/7.1.0

2. Unzip it & goto following path:
`lucene-solr-releases-lucene-solr-7.1.0\solr\core\src\java\org\apache\solr\security\`

3. Replace the `BasicAuthPlugin.java` file with provided one.

4. Goto `lucene-solr-releases-lucene-solr-7.1.0\solr\core` directory & compile:
  ```$ ant compile```

5. Once compilation is finished. Make jar:
  ```$ ant dist```
  
6. Updated jar file would be present inside:
`lucene-solr-releases-lucene-solr-7.1.0\solr\build\solr-core\`

# Configure Solr with changes:

1. Enable basic authentication on solr. (follow solr guidelines)
2. Add these 3 lines in security.json file below "blockUnknown":true, as shown:

 ```
    "blockUnknown":true,
  
    "ldapURL":"127.0.0.1:10389/",
  
    "ldapBase":"o=sevenSeas",
  
    "ldapObjectClass":"inetOrgPerson",
  ```
  Note: replace with appropriate ldap server parameters.

3. update `security.json` file in solr (follow solr guidelines).

4. Stop `solr`

5. Upload the solr-core jar file created earlier to following path in solr setup: `/opt/solr/server/solr-webapp/webapp/WEB-INF/lib/`

6. Replace the original jar with new one:
```$ mv solr-core-7.1.0-SNAPSHOT.jar solr-core-7.1.0.jar```

7. start solr

8. access the solr gui with ldap users. Voila.






    
