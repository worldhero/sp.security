<?php
/*
 * CONFIG v 0.8
 */
return array(
    /**
     * ===============================================
     * -------------- GLOBAL CONFIG ------------------
     * ===============================================
     */
    /*
     * Исключения файлов и папок на проверку
     * массив exclusions - file содержит перечень файлов относительно начала (с указанием / в начале)
     * например /admin/index.php
     * массив exclusions - dir содержит перечень папок относительно начала (подпапки также входят)
     */
    'exclusions' => array(
        'file'=>array(
            //'/index.php'
        ),
        'dir'=>array(
            '/wp-admin'
        ),
    ),
    /*
     * Основные настройки защиты.
     * 1. преобразование скриптовых символов в html сущности.
     * 2. преобразование вредоносных php команд в html сущности.
     * 3. простое но эффективное средство от sql иньекций (обратные слешы)
     * 4. блокировка загрузки php файлов (с расширением и содержащих php код)
     * 5. логирование обращений к файлам, где есть подозрительные php команды
     * 6. логирование обращений, позволит найти брешь в защите если вдруг смогут обойти защиту
     * 7. доступ к административной папке через секретный файл (не изменяя название папки администратора).
     */
    'config_security' => array(
        'sym_code'          => TRUE, //Преобразовывать символы в HTML сущность
        'php'               => TRUE, //Преобразовывать php команды
        'sql'               => TRUE, //Ставить обратные слешь для ковычек
        //Запретить загрузку php файлов
        'uploand_php_file'  => TRUE,
        /* Запретить загрузку файлов где есть теги <?php  или <?, <%
         * FALSE или указать папку куда будет временно скопирован фаил для проверки
         */
        'uploand_php_code_file' => '/tmp_files',
        //Оповещать и писать логи к файлам где есть подозрительные команды
        'warning'           => TRUE,
        /*
         * Путь к папке (от корня sp.security.php) куда будем писать логи обращений (FALSE - не пишем логи)
         */
        'logs'              => '/sp_logs',
        /*
         * Путь к папке/файлам администратора.
         * если указан - то для входа используйте /sp.admin.php (рекомендуем переименовать)
         */
        'admin'             => array(
            'dir' => array(
                '/wp-admin'
            ),
            'file' => array(
                //'/file.php'
            ),
        ),
    ),
    /**
     * REDIRECTS INDEX
     * Перенаправления для обращения к index файлам.
     * Преднозначен больше для SEO чем для защиты.
     */
    //Куда редиректим, если попали на index страницу (url)
    'redirect_index' => '/',
    //Загрузочная страница
    'DirectoryIndex' => 'index.php',
    //индекс страници
    'index' => array(
        '/index.php',
        '/index.html',
        '/index.htm',
        '/index.phtml',
        '/index.hphp',
        '/index.php4',
        '/index.php5',
        '/index.inc',
        '/index.module',
    ),
    //форматы php файлов
    'php_format'=>array(
        '.php',
        '.phtml',
        '.hphp',
        '.php4',
        '.php5',
        '.inc',
        '.module',
    ),
    /**
     * ===============================================
     * ------------------ POLICE ---------------------
     * ===============================================
     */
    //Определяем в файлах сайта подозрительные команды (что бы потом проверить, нет ли дырки)
    'sp_warning' => array(
        'config' => array(
            'dir_logs' => '/sp_logs', //Куда пишем логи с файлами содержащие подозрительные команды
            'email_send' => FALSE, //куда шлем информацию о файле с подозрительной командой
        ),
        'exclusions' => array( //Исключения
            'file'=>array(
                //'/index.php'
            ),
            'dir'=>array(
                //'/phpMyAdmin'
            ),
        ),
        'code' => array( //Подозрительные команды в php файлах
            'exec',
            'system',
            'shell_exec',
            'eval',
            'strrev',
        ),
    ),
    /*
     * Скрипты разработчика
     * А также любые скрипты к которым необходимо запретить доступ из вне.
     */
    'sp_scripts' => array(
        '/sp.security.conf.php',
        '/sp.security.php',
        //'/sp.img.php',
        //'/sp.admin.php',
    ),
    /*
     * Запрещенные php команды в запросах
     * данные команды будут приобразованы в html сущности.
     */
    'php_code_html' => array(
        'mail',
        'exec',
        'system',
        'passthru',
        'popen',
        'shell_exec',
        'proc_open',
        'proc_close',
        'proc_nice',
        'get_current_user',
        'getmyuid',
        'posix_getpwuid',
        'apache_get_modules',
        'virtual',
        'posix_getgrgid',
        'getmyinode',
        'fileowner',
        'filegroup',
        'getmypid',
        'apache_get_version',
        'apache_getenv',
        'apache_note',
        'apache_setenv',
        'disk_free_space',
        'diskfreespace',
        'dl',
        'ini_restore',
        'openlog',
        'syslog',
        'highlight_file',
        'show_source',
        'symlink',
        'disk_total_space',
        'ini_get_all',
        'get_current_user',
        'posix_uname',
        'select',
        'update',
        'insert',
        'delete',
        'echo',
        'var_dump',
        'die',
        'exit',
        'fopen',
        'fputs',
        'fwrite',
        'file_put_contents',
        'php_strip_whitespace',
        'mkdir',
        'eval',
        'base64_encode',
        'base64_decode',
        'rawurldecode',
        'rawurlencode',
        'urldecode',
        'urlencode',
        'convert_uuencode',
        'convert_uudecode',
        'convert_cyr_string',
        'htmlspecialchars_decode',
        'html_entity_decode',
        'quoted_printable_decode'.
        'quoted_printable_encode',
        'chunk_split',
        'bin2hex',
        'hex2bin',
        'pack',
        'unpack',
        'chr',
        'str_​getcsv',
        'str_​ireplace',
        'str_​pad',
        'str_​repeat',
        'str_​replace',
        'str_​rot13',
        'str_​shuffle',
        'str_​split',
        'str_​word_​count',
        'strcasecmp',
        'strchr',
        'strcmp',
        'strcoll',
        'strcspn',
        'strip_​tags',
        'stripcslashes',
        'stripos',
        'stripslashes',
        'stristr',
        'strlen',
        'strnatcasecmp',
        'strnatcmp',
        'strncasecmp',
        'strncmp',
        'strpbrk',
        'strpos',
        'strrchr',
        'strrev',
        'strripos',
        'strrpos',
        'strspn',
        'strstr',
        'strtok',
        'strtolower',
        'strtoupper',
        'strtr',
        'substr_​compare',
        'substr_​count',
        'substr_​replace',
        'substr',
        'join',

    ),
    /*
     * Запрещенные символы в php запросах
     * К удалению не рекомендуеться.
     */
    'php_code_sym' => array(
        '<?'    => '&#060;&#063;',
        "\\"    => '&#092;',
        '$'     => '&#036;',
        '<%'     => '&#060;&#037;',
    ),
    //Символы преобразования (для сущностей - не удалять)
    'html_special_char' => array(
        'A' => '&#065;',
        'B' => '&#066;',
        'C' => '&#067;',
        'D' => '&#068;',
        'E' => '&#069;',
        'F' => '&#070;',
        'G' => '&#071;',
        'H' => '&#072;',
        'I' => '&#073;',
        'J' => '&#074;',
        'K' => '&#075;',
        'L' => '&#076;',
        'M' => '&#077;',
        'N' => '&#078;',
        'O' => '&#079;',
        'P' => '&#080;',
        'Q' => '&#081;',
        'R' => '&#082;',
        'S' => '&#083;',
        'T' => '&#084;',
        'U' => '&#085;',
        'V' => '&#086;',
        'W' => '&#087;',
        'X' => '&#088;',
        'Y' => '&#089;',
        'Z' => '&#090;',

        'a' => '&#097;',
        'b' => '&#098;',
        'c' => '&#099;',
        'd' => '&#100;',
        'e' => '&#101;',
        'f' => '&#102;',
        'g' => '&#103;',
        'h' => '&#104;',
        'i' => '&#105;',
        'j' => '&#106;',
        'k' => '&#107;',
        'l' => '&#108;',
        'm' => '&#109;',
        'n' => '&#110;',
        'o' => '&#111;',
        'p' => '&#112;',
        'q' => '&#113;',
        'r' => '&#114;',
        's' => '&#115;',
        't' => '&#116;',
        'u' => '&#117;',
        'v' => '&#118;',
        'w' => '&#119;',
        'x' => '&#120;',
        'y' => '&#121;',
        'z' => '&#122;',
    ),
);