# phpSimpleErrorHandler

Simple Error Handler, caught fatal error message in error_log

## Requirement

PHP 5.3+

## Usage

### Standalone WowLog library

```
include '../src/Wow/Exception/WowSimpleShutdownHandler.php';

ini_set('error_log','error.log');

new Wow\Exception\WowSimpleErrorHandler();

try{
    echo $foo;
}
catch(Exception $e) {
    var_dump($e);
}
```

### Work with Composer

#### Edit `composer.json`

```
{
    "require": {
        "yftzeng/wow-simple-error-handler": "dev-master"
    }
}
```

#### Update composer

```
$ php composer.phar update
```

#### Sample code
```
include 'vendor/autoload.php';

ini_set('error_log','error.log');

new Wow\Exception\WowSimpleErrorHandler();

try{
    echo $foo;
}
catch(Exception $e) {
    var_dump($e);
}
```

## License

the MIT License
