<?php
$file_conf = realpath(__DIR__.DIRECTORY_SEPARATOR.'sp.security.conf.php');
//Check the configuration file
$sp_security_php->dir_file($file_conf);


//CONFIG LOAD
$config = include $file_conf;
$cookie = hash_file('md5',$file_conf);

$dir_admin = array();
$file_admin = array();
if (!empty($config['config_security']['admin']['dir'])) {
    $dir_admin = $config['config_security']['admin']['dir'];
}
if (!empty($config['config_security']['admin']['file'])) {
    $file_admin = $config['config_security']['admin']['file'];
}
if (empty($dir_admin) AND empty($file_admin)) {
    $sp_security_php->error_display($sp_security_php_result['url_file_open']);
}

//$_COOKIE['sp_admin']
setcookie('sp_admin',$cookie);

?> <!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml">
<head>
    <meta http-equiv="Content-Type" content="text/html; charset=utf-8" />
    <title>SP. ADMIN OPEN</title>
</head>

<body>
<center>
    <h2>Доступ к административной части, успешно получен.</h2>
    <br>
    <?php foreach ($dir_admin as $dir): ?>
        <a href="<?php echo $dir?>"><?php echo $dir ?></a><br>
    <?php endforeach; ?>
    <hr>
    <?php foreach ($file_admin as $dir): ?>
        <a href="<?php echo $dir?>"><?php echo $dir ?></a><br>
    <?php endforeach; ?>
</center>
</body>
</html>
