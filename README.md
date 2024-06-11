# sp.security (легаси код)
Защита для WP любых версий.

# Установка:

Требуемая версия php: Любая начиная с 4й

Файлы разместить в корне проекта.

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

Добавить каталоги: 
sp_logs (возможно изменить в конфигурациях)
tmp_files (возможно изменить в конфигурациях)

Для более тонкой настройки используйте: sp.security.conf.php
