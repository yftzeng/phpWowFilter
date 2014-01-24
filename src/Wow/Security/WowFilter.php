<?php
/**
 * Wow Filter
 *
 * PHP version 5
 *
 * Compatible with PHP 5.2+
 * Ref:
 *     http://www.php.net/manual/en/filter.filters.validate.php
 *     http://www.php.net/manual/en/filter.filters.sanitize.php
 *
 * @category Wow
 * @package  WowFilter
 * @author   Tzeng, Yi-Feng <yftzeng@gmail.com>
 * @license  http://www.opensource.org/licenses/mit-license.php MIT License
 * @link     http://blog.gcos.me/
 */

namespace Wow\Security;

/**
 * WowFilter class
 *
 * @category Wow
 * @package  WowFilter
 * @author   Tzeng, Yi-Feng <yftzeng@gmail.com>
 * @license  http://www.opensource.org/licenses/mit-license.php MIT License
 * @link     http://blog.gcos.me/
 */

class WowFilter
{
    /**
     * Strip unvalidated string of array
     * For version before PHP 5.2
     *
     * "\0" including array("\x00", "\x0a", "\x0d", "\x1a)
     *                array('\0',   '\n',   '\r',   '\Z')
     *
     * @var array
     */
    static private $_extra_strip_array = array(
        "\0", "%0a", "%0A", "%0d", "%0D", "%00", "%1d", "%1D"
    );


    /**
     * @param string $input Value for filtering
     *
     * @comment Safe check variable
     *
     * @return bool
     */
    public static function check($input)
    {
        if (empty($input) && $input != '0') {
            return false;
        }
        return true;
    }

    /**
     * @comment Clean general danergous variable
     *
     * @return void
     */
    public static function cleanDefault()
    {
        if (PHP_VERSION >= 5.2) {
            $_SERVER['PHP_SELF'] = filter_var(
                $_SERVER['PHP_SELF'],
                FILTER_SANITIZE_URL
            );
            if (isset($_SERVER['HTTP_REFERER'])) {
                $_SERVER['HTTP_REFERER'] = filter_var(
                    $_SERVER['HTTP_REFERER'],
                    FILTER_SANITIZE_URL
                );
            }
            if (isset($_SERVER['HTTP_USER_AGENT'])) {
                $_SERVER['HTTP_USER_AGENT'] = filter_var(
                    $_SERVER['HTTP_USER_AGENT'],
                    FILTER_SANITIZE_STRING,
                    FILTER_FLAG_STRIP_LOW | FILTER_FLAG_STRIP_HIGH
                );
            }
        } else {
            $_SERVER['PHP_SELF'] = htmlentities(
                str_replace(
                    self::$extra_strip_array, "",
                    strip_tags($_SERVER['PHP_SELF'])
                )
            );
            if (isset($_SERVER['HTTP_REFERER'])) {
                $_SERVER['HTTP_REFERER'] = htmlentities(
                    str_replace(
                        self::$extra_strip_array, "",
                        strip_tags($_SERVER['HTTP_REFERER'])
                    )
                );
            }
            if (isset($_SERVER['HTTP_USER_AGENT'])) {
                $_SERVER['HTTP_USER_AGENT'] = htmlentities(
                    str_replace(
                        self::$extra_strip_array, "",
                        strip_tags($_SERVER['HTTP_USER_AGENT'])
                    )
                );
            }
        }
    }

    /**
     * @param string $input   Value for filtering
     * @param string $filter  Filtering
     * @param array  $options Filtering options
     *
     * @comment Clean value by type
     *
     * @return mixed
     */
    public static function v($input, $filter, $options = array())
    {
        $filter = htmlspecialchars($filter, ENT_NOQUOTES, 'UTF-8');
        switch ($filter) {
        case 'string':
            $input = filter_var(
                $input, FILTER_SANITIZE_STRING,
                FILTER_FLAG_STRIP_LOW | FILTER_FLAG_STRIP_HIGH
            );
            if (array_key_exists('min', $options)) {
                if (strlen($input) < $options['min']) {
                    return false;
                }
            }
            if (array_key_exists('max', $options)) {
                if (strlen($input) > $options['max']) {
                    return false;
                }
            }
            return $input;
        case 'utf8-string':
            $input = filter_var(
                $input, FILTER_SANITIZE_STRING, FILTER_FLAG_STRIP_LOW
            );
            if (array_key_exists('min', $options)) {
                if (strlen(utf8_decode($input)) < $options['min']) {
                    return false;
                }
            }
            if (array_key_exists('max', $options)) {
                if (strlen(utf8_decode($input)) > $options['max']) {
                    return false;
                }
            }
            return $input;
        case 'boolean':
            return filter_var(
                $input, FILTER_VALIDATE_BOOLEAN
            );
            return $input;
        case 'int':
            // This may got another security issue,
            // For example, when string will map to int, and int is not validate.
            // If you think it is not a issue, you can uncomment next line.
            //$input = filter_var($input, FILTER_SANITIZE_NUMBER_INT);
            //
            $input = filter_var($input, FILTER_VALIDATE_INT);
            if (array_key_exists('min', $options)) {
                if ($input < (int)$options['min']) {
                    return false;
                }
            }
            if (array_key_exists('max', $options)) {
                if ($input > (int)$options['max']) {
                    return false;
                }
            }
            return $input;
        case 'float':
            $input = filter_var($input, FILTER_VALIDATE_FLOAT);
            if (array_key_exists('min', $options)) {
                if ($input < (float)$options['min']) {
                    return false;
                }
            }
            if (array_key_exists('max', $options)) {
                if ($input > (float)$options['max']) {
                    return false;
                }
            }
            return $input;
        case 'url':
            $input =  filter_var($input, FILTER_VALIDATE_URL);
            if (array_key_exists('min', $options)) {
                if (strlen($input) < $options['min']) {
                    return false;
                }
            }
            if (array_key_exists('max', $options)) {
                if (strlen($input) > $options['max']) {
                    return false;
                }
            }
            return $input;
        case 'ip':
        case 'ipv4':
            return filter_var(
                $input, FILTER_VALIDATE_IP,
                FILTER_FLAG_IPV4 | FILTER_FLAG_NO_PRIV_RANGE |
                FILTER_FLAG_NO_RES_RANGE
            );
        case 'ipv6':
            return filter_var(
                $input, FILTER_VALIDATE_IP, FILTER_FLAG_IPV6 |
                FILTER_FLAG_NO_PRIV_RANGE | FILTER_FLAG_NO_RES_RANGE
            );
        case 'mail':
        case 'email':
            $input = filter_var($input, FILTER_VALIDATE_EMAIL);
            if (array_key_exists('min', $options)) {
                if (strlen($input) < $options['min']) {
                    return false;
                }
            }
            if (array_key_exists('max', $options)) {
                if (strlen($input) > $options['max']) {
                    return false;
                }
            }
            return $input;
        case 'html':
            return filter_var(
                $input, FILTER_SANITIZE_SPECIAL_CHARS,
                FILTER_FLAG_STRIP_LOW | FILTER_FLAG_STRIP_HIGH
            );
        case 'utf8-html':
            return filter_var(
                $input, FILTER_SANITIZE_SPECIAL_CHARS,
                FILTER_FLAG_STRIP_LOW
            );
        case 'db-date':
            $input = trim($input);
            if (preg_match(
                "/^(\d{4})-(\d{2})-(\d{2})$/", $input, $matches
            )
            ) {
                if (checkdate($matches[2], $matches[3], $matches[1])) {
                    return $matches[1] . '-' .
                        $matches[2] . '-' . $matches[3];
                }
            }
            if (preg_match(
                "/^(\d{2})-(\d{2})-(\d{4})$/", $input, $matches
            )
            ) {
                if (checkdate($matches[2], $matches[1], $matches[3])) {
                    return $matches[3] . '-' .
                        $matches[2] . '-' . $matches[1];
                }
            }
            return false;
        case 'db-time':
            $input = trim($input);
            if (preg_match(
                "/^(\d{4})-(\d{2})-(\d{2})\ (\d{2}):(\d{2}):(\d{2})$/",
                $input,
                $matches
            )
            ) {
                if (checkdate($matches[2], $matches[3], $matches[1])) {
                    $hour = $matches[4];
                    $min  = $matches[5];
                    $sec  = $matches[6];

                    if ($hour < 0 || $hour > 23 || !is_numeric($hour)) {
                        return false;
                    }
                    if ($min < 0 || $min > 59 || !is_numeric($min)) {
                        return false;
                    }
                    if ($sec < 0 || $sec > 59 || !is_numeric($sec)) {
                        return false;
                    }
                    return $matches[1] . '-' .
                        $matches[2] . '-' .
                        $matches[3] . ' ' . $hour . ':' . $min . ':' . $sec;
                }
            }
            return false;
        case 'phone': // Telephone, p is for USA
            $length = strlen($input);
            for ($i=0; $i<$length; $i++) {
                if (!((is_numeric($input[$i]))
                    || ($input[$i] === '+')
                    || ($input[$i] === '*')
                    || ($input[$i] === 'p')
                    || ($input[$i] === '#')
                    || ($input[$i] === '-'))
                ) {
                        return false;
                }
            }
            return $input;
        case 'pin':
            if ((strlen($input) != 13) || (!is_numeric($input))) {
                return false;
            }
            return $input;
        case 'json':
            // json_encode/json_decode do everything!
            return str_replace(' ', '+', $input);
        case 'base64_safe_encode':
            return strtr($input, '+/', '-_');
        case 'base64_safe_decode':
            return strtr($data, '-_', '+/');
        default:
            return false;
        }
    }

    /**
     * @param string $input Value for filtering
     *
     * @comment Deep stripslashes
     *
     * @return array
     */
    public static function deepStripslashes($input)
    {
        return is_array($input) ?
            array_map('self::deepStripslashes', $input) : stripslashes($input);
    }

    /**
     * @param string $input Value for filtering
     *
     * @comment Deep clean
     *
     * @return array
     */
    public static function deepClean($input)
    {
        return is_array($input) ?
            array_map('self::deepClean', $input) :
            filter_var($input, FILTER_SANITIZE_STRING, FILTER_FLAG_STRIP_LOW);
    }
}
