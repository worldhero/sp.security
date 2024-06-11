<?php
/**
 * Developer: Nikitin Yuriy Alexandrovich.
 * Development Version: 2.4
 * Company: HOST-PROTECTION.COM
 * Contacts:
 * E-mail:hostprotection@gmail.com
 *
 * Please do not delete the copyright.
 *
 * Class sp_security_php
 */
class sp_security_php {
    var $htsc;
    var $symblNormal = array(
        '-',
        '_',
        '=',
        '/',
    );

    function clear_slashes ($array) {
        foreach ($array as $key=>$val) {
            if (is_array($val)) {
                $array[$key] = $this->clear_slashes ($val);
                continue;
            }
            $array[$key] = stripslashes($val);
        }
        return $array;
    }

    function add_slashes ($array) {
        foreach ($array as $key=>$val) {
            if (is_array($val)) {
                $array[$key] = $this->add_slashes ($val);
                continue;
            }
            if (ini_get('magic_quotes_sybase')) {
                $val = str_replace(array("''"), array("'"),$val);
            } else {
                if (ini_get('magic_quotes_gpc')) {
                    $val = stripslashes($val);
                }
            }
            $array[$key] = addslashes($val);
        }
        return $array;
    }

    function switch_sym ($array,$sym) {
        foreach ($array as $key=>$val) {
            if (is_array($val)) {
                $array[$key] = $this->switch_sym($val, $sym);
                continue;
            }
            $array[$key] = str_ireplace(array_keys($sym),array_values($sym),$val);
        }
        return $array;
    }

    function clear_php ($array,$php,$cookies=FALSE) {
        foreach ($array as $key=>$val) {
            if (is_array($val)) {
                $array[$key] = $this->clear_php($val,$php);
                continue;
            }
            if (in_array(mb_strtolower(trim($val)),$php)) {
                $array[$key] = $val;
                continue;
            }
            if (strlen($val)>1000
                and !strpos($val,' ')
                and !strpos($val,"\r")
                and !strpos($val,"\t")
                and !strpos($val,"\n")
                and !strpos($val,"\v")
            ) continue;
            $array[$key] = $this->search_replace_command($val,$php,$cookies);
        }
        return $array;
    }
    function text_decoder_replace($text) {
        $decode = FALSE;
        if (hex2bin($text)) {
            $text = hex2bin($text);
            $decode = 'hex2bin';
        }
        if (str_rot13($text)) {
            $text = str_rot13($text);
            $decode = 'str_rot13';
        }
        if (base64_decode($text)) {
            $text = base64_decode($text);
            $decode = 'base64_decode';
        }

        return $text;
    }
    function search_replace_command ($text,array $data,$cookies=FALSE) {
        if (!$cookies and strlen($text) >= 250 and strripos($text,' ') === FALSE)
            $text = $this->text_decoder_replace($text);
        foreach ($data as $search) {
            preg_match_all("/\b{$search}\b/i", $text, $matches, PREG_OFFSET_CAPTURE);
            if ($matches) {
                foreach ($matches as $val_search) {
                    $count = 0;
                    foreach ($val_search as $all_search) {
                        if (empty($all_search[0])) {
                            continue;
                        }
                        $count_start = $all_search[1] + $count;
                        $text_found = $all_search[0];
                        $probel_e = substr($text, ($count_start+strlen($text_found)), 1);
                        if (in_array($probel_e,$this->symblNormal)) {
                            continue;
                        }
                        if ($count_start>0) {
                            $probel_n = substr($text,($count_start-1),1);
                            if ($probel_n != ' '
                                AND $probel_n != '%20'
                                AND $probel_n != '@'
                                AND $probel_n != '='
                                AND $probel_n != ';'
                                AND $probel_n != '"'
                                AND $probel_n != "'") {
                                continue;
                            }
                        }
                        if ($probel_e != ' '
                            AND $probel_e != '%20'
                            AND $probel_e != '@'
                            AND $probel_e != '"'
                            AND $probel_e != "'"
                            AND $probel_e != '('
                            AND $probel_e != ';') {
                            continue;
                        }
                        $new_text = '';
                        $new_text .= substr($text, 0, $count_start);
                        $new_text_found = str_replace(
                            array_keys($this->htsc),
                            array_values($this->htsc),
                            $text_found);
                        $count_plus = strlen($new_text_found) - strlen($text_found);
                        if ($count_plus > 0) {
                            $count = $count + $count_plus;
                        } else if ($count_plus < 0) {
                            $count = $count - $count_plus;
                        }
                        $new_text .= $new_text_found;
                        $new_text .= substr($text, ($count_start + strlen($text_found)));
                        $text = $new_text;
                    }
                }
            }
        }
        return $text;
    }

    function dir_file ($file,$open_file=NULL) {
        if (empty($open_file)) {
            $open_file = $file;
        }
        if (!is_file($file)) {
            $this->error_display($open_file);
        }
    }

    function error_display ($open_file) {
        header($_SERVER['SERVER_PROTOCOL']." 404 Not Found");
        die('
            <h1>Error 404 Not Found</h1>
            <br>
            No file ('.$open_file.').
            <br>
            Php-code security
            <br>
            Protection against hacking
            <br><br>
            Creator <a href="http://host-protection.com" target="_blank">HOST-PROTECTION</a>
        ');
    }
    function parse_request ($REQUEST_URI) {
        $url_array = explode('/',$REQUEST_URI);
        $file_and_query = array_pop($url_array);
        $url_array_tmp = array();
        foreach ($url_array as $key=>$val) {
            if ($val=='..' OR $val == '') {
                continue;
            }
            if (strpos($val,'.php?') !== FALSE) {
                $file_and_query=$val;
                break;
            }
            $url_array_tmp[]=$val;
        }
        $url_array = $url_array_tmp;
        $url_array_tmp = NULL;

        $file = $file_and_query;
        $line = strpos($file_and_query,'?');
        if ($line !== FALSE) {
            $file = substr($file_and_query,0,$line);
        }
        $line = NULL;

        $dir = implode(DIRECTORY_SEPARATOR,$url_array);

        return array('dir'=>$dir,'file'=>$file);
    }

    function clear_redirect ($REDIRECT_URL) {
        return substr($REDIRECT_URL,0,1) == DIRECTORY_SEPARATOR ? substr($REDIRECT_URL,1) : $REDIRECT_URL;
    }


    function start () {
        $array_file = $this->parse_request ($_SERVER['REQUEST_URI']);

        $file_conf = realpath(__DIR__.DIRECTORY_SEPARATOR.'sp.security.conf.php');
        //Check the configuration file
        $this->dir_file($file_conf);
        //CONFIG LOAD
        $config = include $file_conf;
        if (empty($config['index']))                { $config['index'] = array(); }
        if (empty($config['exclusions']['file']))   { $config['exclusions']['file'] = array(); }
        if (empty($config['exclusions']['dir']))    { $config['exclusions']['dir'] = array(); }
        if (empty($config['sp_scripts']))           { $config['sp_scripts'] = array(); }
        if (empty($config['php_format']))           { $config['php_format'] = array(
            '.php',
            '.phtml',
            '.hphp',
            '.php4',
            '.php5',
            '.inc',
            '.module',
        ); }


        $refresh_url = FALSE;
        //The real path to the file
        if (empty($array_file['file']) AND !empty($_SERVER['REDIRECT_URL'])) {
            $array_file['file'] = $this->clear_redirect($_SERVER['REDIRECT_URL']);
            $refresh_url = TRUE;
        }
        if (empty($array_file['file'])) {
            $array_file['file'] = 'index.php';
            $refresh_url = TRUE;
        }
        if (!in_array(
                substr($array_file['file'],strripos($array_file['file'],'.')),
                $config['php_format']
            )
            AND !empty($_SERVER['REDIRECT_URL'])) {
            $array_file['file'] = $this->clear_redirect($_SERVER['REDIRECT_URL']);;
            $refresh_url = TRUE;
        }

        //NEW FILE
        if ($refresh_url) {
            $array_file = $this->parse_request ($array_file['file']);
        }

        //REAL DIR FILE
        $real_dir_open = __DIR__;
        if (!empty($array_file['dir'])) {
            $real_dir_open .= DIRECTORY_SEPARATOR.$array_file['dir'];
        }
        $real_dir_open  = realpath($real_dir_open);
        $real_file_open = realpath($real_dir_open.DIRECTORY_SEPARATOR.$array_file['file']);
        if (!$real_file_open) {
            $this->error_display(DIRECTORY_SEPARATOR.$array_file['dir'].DIRECTORY_SEPARATOR.$array_file['file']);
        }

        $url_file_open = '';
        if (!empty($array_file['dir'])) {
            $url_file_open .= DIRECTORY_SEPARATOR.$array_file['dir'];
        }
        $url_file_open  .= DIRECTORY_SEPARATOR.$array_file['file'];

        //INDEX FILE - REDIRECT
        if (in_array($url_file_open,$config['index']) AND !$refresh_url) {
            header( 'Location: '.(empty($config['redirect_index']) ? '/' : $config['redirect_index']) );
            die();
        }

        //Admin access DIR -R
        if (!empty($config['config_security']['admin']['dir'])) {
            $admin_dir = $config['config_security']['admin']['dir'];
            if (is_array($admin_dir)) {
                foreach ($admin_dir as $vAdminDir) {
                    if (empty($vAdminDir)) continue;
                    $vAdminDir = realpath(__DIR__.DIRECTORY_SEPARATOR.$vAdminDir);
                    if ($vAdminDir) {
                        $len_ex_dir = strlen($vAdminDir);
                        $dir_no_len = substr($real_dir_open, 0, $len_ex_dir);
                        //var_dump($dir_no_len);
                        if ($dir_no_len == $vAdminDir) {
                            $cookie_hash = hash_file('md5', $file_conf);
                            if (empty($_COOKIE['sp_admin']) or $_COOKIE['sp_admin'] != $cookie_hash) {
                                $this->error_display($url_file_open);
                            }
                        }
                    }
                }
            }
        }
        //Admin access FILES
        if (!empty($config['config_security']['admin']['file'])) {
            $admin_file = $config['config_security']['admin']['file'];
            if (is_array($admin_file)) {
                foreach ($admin_file as $vAdminFile) {
                    if (empty($vAdminFile)) continue;
                    $vAdminFile = realpath(__DIR__.DIRECTORY_SEPARATOR.$vAdminFile);
                    if ($vAdminFile) {
                        if ($real_file_open == $vAdminFile) {
                            $cookie_hash = hash_file('md5', $file_conf);
                            if ($_COOKIE['sp_admin'] != $cookie_hash) {
                                $this->error_display($url_file_open);
                            }
                        }
                    }
                }
            }
        }

        //Exclusions DIR -R
        foreach ($config['exclusions']['dir'] as $exclusions_dir) {
            $exclusions_dir = realpath(__DIR__.DIRECTORY_SEPARATOR.$exclusions_dir);
            if ($exclusions_dir) {
                $len_ex_dir = strlen($exclusions_dir);
                $dir_no_len = substr($real_dir_open, 0, $len_ex_dir);
                if ($dir_no_len == $exclusions_dir) {
                    return array(
                        'real_dir_open' => $real_dir_open,
                        'real_file_open' => $real_file_open,
                        'url_file_open' => $url_file_open,
                    );
                }
            }
        }
        //Exclusions FILES
        foreach ($config['exclusions']['file'] as $exclusions_file) {
            $exclusions_file = realpath(__DIR__.DIRECTORY_SEPARATOR.$exclusions_file);
            if ($exclusions_file) {
                if ($real_file_open == $exclusions_file) {
                    return array(
                        'real_dir_open' => $real_dir_open,
                        'real_file_open' => $real_file_open,
                        'url_file_open' => $url_file_open,
                    );
                }
            }
        }

        //Blocking a protected script
        if ($real_file_open == __FILE__) {
            $this->error_display($url_file_open);
        }
        if ($real_file_open == $file_conf) {
            $this->error_display($url_file_open);
        }
        if (in_array($url_file_open,$config['sp_scripts'])) {
            $this->error_display($url_file_open);
        }


        //Check the file with the code
        $this->dir_file($real_file_open,$url_file_open);

        if (empty($config['php_code_html'])) { $config['php_code_html'] = array(); }
        if (empty($config['php_code_sym'])) { $config['php_code_sym'] = array(); }
        if (empty($config['html_special_char'])) { $config['html_special_char'] = array(); }
        if (!isset($config['config_security']['php']))              { $config['config_security']['php']             = TRUE; }
        if (!isset($config['config_security']['sql']))              { $config['config_security']['sql']             = TRUE; }
        if (!isset($config['config_security']['sym_code']))         { $config['config_security']['sym_code']        = TRUE; }
        if (!isset($config['config_security']['uploand_php_file'])) { $config['config_security']['uploand_php_file']= TRUE; }
        if (!isset($config['config_security']['uploand_php_code_file'])) { $config['config_security']['uploand_php_code_file']= FALSE; }
        if (!isset($config['config_security']['warning']))          { $config['config_security']['warning']         = FALSE; }
        if (!isset($config['config_security']['logs']))             { $config['config_security']['logs']            = FALSE; }
        $this->htsc=$config['html_special_char'];

        //POLICE
        if ($config['config_security']['logs']) {
            $logs_dir = (string) $config['config_security']['logs'];
            $logs_dir = str_replace(DIRECTORY_SEPARATOR.DIRECTORY_SEPARATOR,'',$logs_dir);
            if (substr($logs_dir,0,1) === DIRECTORY_SEPARATOR) $logs_dir = substr($logs_dir,1);
            $log_save = TRUE;
            if (!is_dir($logs_dir)) {
                @$mkdir = mkdir($logs_dir,755);
                if (!$mkdir) $log_save = FALSE;
            }
            $logs_dir = realpath(__DIR__.DIRECTORY_SEPARATOR.$logs_dir);
            if ($real_dir_open == $logs_dir) $this->error_display($url_file_open);

            if ($log_save) {
                $file_name_logs = date('Y-m-d').'.log';
                @$fo = fopen($logs_dir.DIRECTORY_SEPARATOR.$file_name_logs,'a');
                if ($fo) {
                    $string_logs = '';
                    $string_logs .= date('Y-m-d H:i:s');
                    $string_logs .= ';  ';
                    $string_logs .= $this->get_ip();
                    $string_logs .= ';  ';
                    $string_logs .= $real_file_open;
                    $string_logs .= ';  ';
                    $string_logs .= 'GET=';
                    $string_logs .= base64_encode(serialize($_GET));
                    $string_logs .= ';  ';
                    $string_logs .= 'POST=';
                    $string_logs .= base64_encode(serialize($_POST));
                    $string_logs .= ';  ';
                    $string_logs .= 'COOKIE=';
                    $string_logs .= base64_encode(serialize($_COOKIE));
                    $string_logs .= "\n";
                    @fwrite($fo,$string_logs);
                    fclose($fo);
                }
            }
        }

        if ($config['config_security']['warning']) {
            $serach_code_php_file = TRUE;
            if (empty ($config['sp_warning']['config']['exclusions']['file']))
                $config['sp_warning']['config']['exclusions']['file'] = array();
            if (empty ($config['sp_warning']['config']['exclusions']['dir']))
                $config['sp_warning']['config']['exclusions']['dir'] = array();
            //Exclusions DIR -R
            foreach ($config['sp_warning']['config']['exclusions']['dir'] as $exclusions_dir) {
                $exclusions_dir = realpath(__DIR__.DIRECTORY_SEPARATOR.$exclusions_dir);
                $len_ex_dir = strlen($exclusions_dir);
                $dir_no_len = substr($real_dir_open,0,$len_ex_dir);
                if ($dir_no_len == $exclusions_dir) {
                    $serach_code_php_file = FALSE;
                }
            }
            //Exclusions FILES
            foreach ($config['sp_warning']['config']['exclusions']['file'] as $exclusions_file) {
                $exclusions_file = realpath(__DIR__.DIRECTORY_SEPARATOR.$exclusions_file);
                if ($real_file_open == $exclusions_file) {
                    $serach_code_php_file = FALSE;
                }
            }
            //Search warning php code is file
            if ($serach_code_php_file) {
                $warning_log = FALSE;
                $string_logs = '';
                if (empty($config['sp_warning']['config']['code']))
                    $config['sp_warning']['config']['code'] = array('exec','system','shell_exec','eval',);
                @$file_contents_php = file_get_contents($real_file_open);
                if ($file_contents_php) {
                    foreach ($config['sp_warning']['config']['code'] as $warning_php) {
                        //TODO::Сделать проверку покруче
                        $file_contents_php = mb_strtolower($file_contents_php);
                        preg_match("/([\ \t\;\=\+\-\@]?){$warning_php}([ \t]*?)\(/i",$file_contents_php,$match);
                        $match_line = FALSE;
                        $array_line = explode("\n",$file_contents_php);
                        foreach ($array_line as $text_line) {
                            $text_line = trim($text_line);
                            if (strlen($text_line) > 500) $match_line = TRUE;
                            if (strlen($text_line) > 200 and
                                    (
                                        strpos($text_line,'chr') or
                                        strpos($text_line,'\x')
                                    )
                            ) $match_line = TRUE;
                        }
                        if (!empty($match) or $match_line) {
                            //$sym_mat = substr($match[1],-1);
                            $warning_log = TRUE;
                            $string_logs .= date('Y-m-d H:i:s');
                            $string_logs .= ';  ';
                            $string_logs .= $this->get_ip();
                            $string_logs .= ';  ';
                            $string_logs .= $real_file_open;
                            $string_logs .= "\n";
                            break;
                        }
                    }
                }
                if ($warning_log && !empty($config['sp_warning']['config']['dir_logs'])) {
                    $logs_dir = (string)$config['sp_warning']['config']['dir_logs'];
                    $logs_dir = str_replace(DIRECTORY_SEPARATOR.DIRECTORY_SEPARATOR,'',$logs_dir);
                    if (substr($logs_dir,0,1) === DIRECTORY_SEPARATOR) $logs_dir = substr($logs_dir,1);
                    $log_save = TRUE;
                    if (!is_dir($logs_dir)) {
                        @$mkdir = mkdir($logs_dir, 755);
                        if (!$mkdir) $log_save = FALSE;
                    }
                    $logs_dir = realpath(__DIR__ . DIRECTORY_SEPARATOR . $logs_dir);
                    if ($real_dir_open == $logs_dir) $this->error_display($url_file_open);

                    if ($log_save) {
                        $file_name_logs = 'warning.'.date('Y-m-d').'.log';
                        @$fo = fopen($logs_dir.DIRECTORY_SEPARATOR.$file_name_logs,'a');
                        if ($fo) {
                            @fwrite($fo,$string_logs);
                            fclose($fo);
                        }
                    }
                }
                if ($warning_log && !empty($config['sp_warning']['config']['email_send'])) {
                    $type_text = 'text/plain';
                    $from = "websecurity@".$_SERVER['SERVER_NAME'];
                    $headers  = 'MIME-Version: 1.0' . "\r\n";
                    $headers .= 'Content-type: '.$type_text.'; charset=UTF-8' . "\r\n";
                    $headers .= 'From: '.$from.' <'.$from.'>' . "\r\n";
                    // Отправляем
                    @mail($config['sp_warning']['config']['email_send'], 'Warning! SP. SECURITY! FILE COMMAND!', $string_logs, $headers);
                }
            }
        }

        //TODO::Сделать проверку и для KEY не только для VALUE
        if (!empty($config['php_code_sym']) AND $config['config_security']['sym_code']) {
            $_GET = $this->switch_sym ($_GET,$config['php_code_sym']);
            $_POST = $this->switch_sym ($_POST,$config['php_code_sym']);
            $_REQUEST = $this->switch_sym ($_REQUEST,$config['php_code_sym']);
            $_COOKIE = $this->switch_sym ($_COOKIE,$config['php_code_sym']);
        }
        if (!empty($config['php_code_html']) AND $config['config_security']['php']) {
            $_GET = $this->clear_php ($_GET,$config['php_code_html']);
            $_POST = $this->clear_php ($_POST,$config['php_code_html']);
            $_REQUEST = $this->clear_php ($_REQUEST,$config['php_code_html'],TRUE);
            $_COOKIE = $this->clear_php ($_COOKIE,$config['php_code_html'],TRUE);
        }


        if ($config['config_security']['sql']) {
            /*
            $_GET = $this->clear_slashes($_GET);
            $_POST = $this->clear_slashes($_POST);
            $_REQUEST = $this->clear_slashes($_REQUEST);
            */
            $_GET = $this->add_slashes($_GET);
            $_POST = $this->add_slashes($_POST);
            $_REQUEST = $this->add_slashes($_REQUEST);
            $_COOKIE = $this->add_slashes($_COOKIE);
        }

        if ($config['config_security']['uploand_php_file']) {
            $_FILES =$this->no_php_uploand($_FILES,$config['php_format']);
        }
        if ($config['config_security']['uploand_php_code_file']) {
            $tmp_files = (string) $config['config_security']['uploand_php_code_file'];
            if (!empty($tmp_files)) {
                $tmp_files = str_replace('//','/',__DIR__.DIRECTORY_SEPARATOR.$tmp_files);
                if (!is_dir($tmp_files)) {
                    @$mkdir = mkdir($tmp_files, 755);
                    if (!$mkdir) $tmp_files = FALSE;
                }
            }
            if ($tmp_files) {
                if ($real_dir_open == $tmp_files) $this->error_display($url_file_open);
                $_FILES =$this->no_php_code_uploand($_FILES,$tmp_files);
            }
        }

        //OPEN FILE
        return array(
            'real_dir_open' =>$real_dir_open,
            'real_file_open'=>$real_file_open,
            'url_file_open' =>$url_file_open,
        );
    }
    //
    /********************
     * УДАЛЕНИЕ ФАЙЛОВ С РАСШИРЕНИЕМ PHP
     */
    function no_php_uploand ($files = array(),$format_php) {
        foreach($files as $keys=>$val) {
            if (is_array($val["name"])) {
                $delete = $this->tt ($val["name"],'name',$format_php);
                $files[$keys]["name"] = $this->delete_files($val["name"],$delete);
                $files[$keys]["type"] = $this->delete_files($val["type"],$delete);
                $files[$keys]["tmp_name"] = $this->delete_files($val["tmp_name"],$delete,'tmp_name');
                $files[$keys]["error"] = $this->delete_files($val["error"],$delete);
                $files[$keys]["size"] = $this->delete_files($val["size"],$delete);
                continue;
            }
            $name = $val["name"];
            if ($len = strripos($name,'.')) {
                $format = substr($name,$len);
                if (in_array(mb_strtolower(trim($format)),$format_php)) {
                    //Удалим фаил
                    @unlink($val['tmp_name']);
                    unset ($files[$keys]["name"]);
                    unset ($files[$keys]["type"]);
                    unset ($files[$keys]["tmp_name"]);
                    unset ($files[$keys]["error"]);
                    unset ($files[$keys]["size"]);
                }
            }
        }
        return $files;
    }
    function no_php_code_uploand ($files = array(), $tmp_file = '/tmp_file') {
        if ($tmp_file) {
            $tmp_file =str_replace('//','/',$tmp_file.'/tmpFile');
        }
        foreach($files as $keys=>$val) {
            if (is_array($val["tmp_name"])) {
                $delete = $this->tt ($val["tmp_name"],'tmp_name',array(),$tmp_file);
                $files[$keys]["name"] = $this->delete_files($val["name"],$delete);
                $files[$keys]["type"] = $this->delete_files($val["type"],$delete);
                $files[$keys]["tmp_name"] = $this->delete_files($val["tmp_name"],$delete,'tmp_name');
                $files[$keys]["error"] = $this->delete_files($val["error"],$delete);
                $files[$keys]["size"] = $this->delete_files($val["size"],$delete);
                continue;
            }
            $tmp_name = $files[$keys]["tmp_name"];
            if ($tmp_file) {
                if (copy($tmp_name,$tmp_file)) {
                    $tmp_name = $tmp_file;
                }
            }
            $content = file_get_contents($tmp_name);
            $result = FALSE;
            if (strpos($content,'<?') !== FALSE) $result = TRUE;
            if (strpos($content,'<?php') !== FALSE) $result = TRUE;
            if (strpos($content,'<%') !== FALSE) $result = TRUE;
            if ($result) {
                //Удалим фаил
                @unlink($files[$keys]["tmp_name"]);
                unset ($files[$keys]["name"]);
                unset ($files[$keys]["type"]);
                unset ($files[$keys]["tmp_name"]);
                unset ($files[$keys]["error"]);
                unset ($files[$keys]["size"]);
            }
        }
        //var_dump($files);
        return $files;
    }
    function tt ( array $tmp, $type = 'tmp_name', array $format_php = array(), $tmp_file = NULL) {
        $array_delete = array();
        foreach ($tmp as $k => $v) {
            if (is_array($v)) {
                $re = $this->tt($v,$type,$format_php,$tmp_file);
                if (!empty($re)) {
                    $array_delete[$k] = $re;
                }
                continue;
            }
            if ($type === 'name') {
                if ($len = strripos($v,'.')) {
                    $format = substr($v, $len);
                    if (in_array(mb_strtolower(trim($format)), $format_php)) {
                        $array_delete[$k] = $k;
                    }
                }
            }
            if ($type === 'tmp_name') {
                $files = $v;
                if ($tmp_file) {
                    if (copy($files,$tmp_file)) {
                        $files = $tmp_file;
                    }
                }
                $content = file_get_contents($files);
                $result = FALSE;
                if (strpos($content, '<?') !== FALSE) $result = TRUE;
                if (strpos($content, '<?php') !== FALSE) $result = TRUE;
                if (strpos($content, '<%') !== FALSE) $result = TRUE;
                if ($result) {
                    $array_delete[$k] = $k;
                }
            }
        }
        return $array_delete;
    }
    function delete_files (array $data, array $array_delete, $t = 'data') {
        foreach ($array_delete as $k=>$del) {
            if (is_array($del)) {
                $data[$k] = $this->delete_files ($data[$k], $del, $t);
                if (empty($data[$k])) unset ($data[$k]);
                continue;
            }
            if ($t === 'tmp_name') {
                @unlink($data[$k]);
            }
            unset ($data[$k]);
        }
        return $data;
    }

    //
    /********************
     * ДОПОЛНИТЕЛЬНЫЕ ФУНКЦИИ
     */
    function get_ip ($proxy = TRUE) {
        if ($proxy && !empty($_SERVER['HTTP_CLIENT_IP']) && $_SERVER['HTTP_CLIENT_IP']!= null) {
            $ip = $_SERVER['HTTP_CLIENT_IP'];
        } else if ($proxy && !empty($_SERVER['HTTP_X_FORWARDED_FOR']) && $_SERVER['HTTP_X_FORWARDED_FOR'] != null) {
            $ip = $_SERVER['HTTP_X_FORWARDED_FOR'];
        } else {
            $ip = $_SERVER['REMOTE_ADDR'];
        }
        return $ip;
    }
}


$sp_security_php = new sp_security_php();
$sp_security_php_result = $sp_security_php->start();

chdir($sp_security_php_result['real_dir_open']);
$_SERVER['SCRIPT_FILENAME'] = $sp_security_php_result['real_file_open'];
$_SERVER['SCRIPT_NAME'] = $sp_security_php_result['url_file_open'];
$_SERVER['PHP_SELF'] = $sp_security_php_result['url_file_open'];

/*
echo "GET: ";
var_dump($_GET);
echo '<hr> FILE: ';
var_dump($_FILES);
echo '<hr>';
*/

require $sp_security_php_result['real_file_open'];