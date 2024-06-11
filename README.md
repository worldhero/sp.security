# sp.security
Защита для WP любых версий.

# Установка:
Добавить в .htaccess
```
# BEGIN WordPress
<IfModule mod_rewrite.c>
RewriteEngine On
RewriteBase /
RewriteRule ^(.*)\.(php|inc|hphp|phtml|php4|php5|module)$ 		        sp.security.php [L]
RewriteRule ^(.*)\.(php|inc|hphp|phtml|php4|php5|module)\?(.*)$ 		sp.security.php [L]
RewriteRule ^index\.php$ - [L]
RewriteCond %{REQUEST_FILENAME} !-f
RewriteCond %{REQUEST_FILENAME} !-d
RewriteRule . /index.php [L]
</IfModule>

# END WordPress
```
