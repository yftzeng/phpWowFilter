# phpWowFilter

Eazy Secure Filter

## Requirement

PHP 5.2+

## Usage

### Standalone WowLog library

```
include 'src/Wow/Security/WowFilter.php';

use Wow\Security\WowFilter;

$t = WowFilter::v('123abc!@#', 'string');
$t = WowFilter::v('123abc!@#', 'string', array('min'=>9, 'max'=>9));
```

### Work with Composer

#### Edit `composer.json`

```
{
    "require": {
        "yftzeng/wowfilter": "dev-master"
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

use Wow\Security\WowFilter;

$t = WowFilter::v('123abc!@#', 'string');
$t = WowFilter::v('123abc!@#', 'string', array('min'=>9, 'max'=>9));
```

## Example

```
$t = WowFilter::v('123abc!@#', 'string');
$t = WowFilter::v('123abc!@#', 'string', array('min'=>9, 'max'=>9));
$t = WowFilter::v('許蓋功', 'utf8-string', array('min'=>4, 'max'=>4));
$t = WowFilter::v('1', 'boolean');
$t = WowFilter::v('123', 'int', array('min'=>123, 'max'=>123));
$t = WowFilter::v('123', 'float', array('min'=>123, 'max'=>123));
$t = WowFilter::v('http://www.google.com', 'url', array('min'=>5, 'max'=>255));
$t = WowFilter::v('test@abc.com', 'mail', array('min'=>1, 'max'=>255));
$t = WowFilter::v('2013-12-12', 'db-date');
$t = WowFilter::v('2013-12-12 11:11:11', 'db-time');
```

## License

the MIT License
