<?php
namespace App\Http\Library;

class SignOption
{
    const EXPIRATION_IN_SECONDS = 'expirationInSeconds';

    const HEADERS_TO_SIGN = 'headersToSign';

    const TIMESTAMP = 'timestamp';

    const DEFAULT_EXPIRATION_IN_SECONDS = 1800;

    const MIN_EXPIRATION_IN_SECONDS = 300;

    const MAX_EXPIRATION_IN_SECONDS = 129600;
}

class HttpUtil
{
    // 根据RFC 3986，除了：
    //   1.大小写英文字符
    //   2.阿拉伯数字
    //   3.点'.'、波浪线'~'、减号'-'以及下划线'_'
    // 以外都要编码
    public static $PERCENT_ENCODED_STRINGS;

    //填充编码数组
    public static function __init()
    {
        HttpUtil::$PERCENT_ENCODED_STRINGS = array();
        for ($i = 0; $i < 256; ++$i) {
            HttpUtil::$PERCENT_ENCODED_STRINGS[$i] = sprintf("%%%02X", $i);
        }

        //a-z不编码
        foreach (range('a', 'z') as $ch) {
            HttpUtil::$PERCENT_ENCODED_STRINGS[ord($ch)] = $ch;
        }

        //A-Z不编码
        foreach (range('A', 'Z') as $ch) {
            HttpUtil::$PERCENT_ENCODED_STRINGS[ord($ch)] = $ch;
        }

        //0-9不编码
        foreach (range('0', '9') as $ch) {
            HttpUtil::$PERCENT_ENCODED_STRINGS[ord($ch)] = $ch;
        }

        //以下4个字符不编码
        HttpUtil::$PERCENT_ENCODED_STRINGS[ord('-')] = '-';
        HttpUtil::$PERCENT_ENCODED_STRINGS[ord('.')] = '.';
        HttpUtil::$PERCENT_ENCODED_STRINGS[ord('_')] = '_';
        HttpUtil::$PERCENT_ENCODED_STRINGS[ord('~')] = '~';
    }

    //在uri编码中不能对'/'编码
    public static function urlEncodeExceptSlash($path)
    {
        return str_replace("%2F", "/", HttpUtil::urlEncode($path));
    }

    //使用编码数组编码
    public static function urlEncode($value)
    {
        $result = '';
        for ($i = 0; $i < strlen($value); ++$i) {
            $result .= HttpUtil::$PERCENT_ENCODED_STRINGS[ord($value[$i])];
        }
        return $result;
    }

    //生成标准化QueryString
    public static function getCanonicalQueryString(array $parameters)
    {
        //没有参数，直接返回空串
        if (count($parameters) == 0) {
            return '';
        }

        $parameterStrings = array();
        foreach ($parameters as $k => $v) {
            //跳过Authorization字段
            if (strcasecmp('Authorization', $k) == 0) {
                continue;
            }
            if (!isset($k)) {
                throw new \InvalidArgumentException(
                    "parameter key should not be null"
                );
            }
            if (isset($v)) {
                //对于有值的，编码后放在=号两边
                $parameterStrings[] = HttpUtil::urlEncode($k)
                    . '=' . HttpUtil::urlEncode((string) $v);
            } else {
                //对于没有值的，只将key编码后放在=号的左边，右边留空
                $parameterStrings[] = HttpUtil::urlEncode($k) . '=';
            }
        }
        //按照字典序排序
        sort($parameterStrings);

        //使用'&'符号连接它们
        return implode('&', $parameterStrings);
    }

    //生成标准化uri
    public static function getCanonicalURIPath($path)
    {
        //空路径设置为'/'
        if (empty($path)) {
            return '/';
        } else {
            //所有的uri必须以'/'开头
            if ($path[0] == '/') {
                return HttpUtil::urlEncodeExceptSlash($path);
            } else {
                return '/' . HttpUtil::urlEncodeExceptSlash($path);
            }
        }
    }

    //生成标准化http请求头串
    public static function getCanonicalHeaders($headers)
    {
        //print 'getCanonicalHeaders:'.var_export($headers, true);
        //如果没有headers，则返回空串
        if (count($headers) == 0) {
            return '';
        }

        $headerStrings = array();
        foreach ($headers as $k => $v) {
            //跳过key为null的
            if ($k === null) {
                continue;
            }
            //如果value为null，则赋值为空串
            if ($v === null) {
                $v = '';
            }
            //trim后再encode，之后使用':'号连接起来
            $headerStrings[] = HttpUtil::urlEncode(strtolower(trim($k))) . ':' . HttpUtil::urlEncode(trim($v));
        }
        //字典序排序
        sort($headerStrings);

        //用'\n'把它们连接起来
        return implode("\n", $headerStrings);
    }
}
HttpUtil::__init();


class SampleSigner
{

    const BCE_AUTH_VERSION = "bce-auth-v1";
    const BCE_PREFIX = 'x-bce-';

    //不指定headersToSign情况下，默认签名http头，包括：
    //    1.host
    //    2.content-length
    //    3.content-type
    //    4.content-md5
    public static $defaultHeadersToSign;

    public static function  __init()
    {
        SampleSigner::$defaultHeadersToSign = array(
            "host",
            "content-length",
            "content-type",
            "content-md5",
        );
    }

    //签名函数
    public function sign(
        array $credentials,
        $httpMethod,
        $path,
        $headers,
        $params,
        $options = array()
    ) {
        //设定签名有效时间
        if (!isset($options[SignOption::EXPIRATION_IN_SECONDS])) {
            //默认值1800秒
            $expirationInSeconds = SignOption::DEFAULT_EXPIRATION_IN_SECONDS;
        } else {
            $expirationInSeconds = $options[SignOption::EXPIRATION_IN_SECONDS];
        }

        //解析ak sk
        $accessKeyId = $credentials['ak'];
        $secretAccessKey = $credentials['sk'];

        //设定时间戳，注意：如果自行指定时间戳需要为UTC时间
        if (!isset($options[SignOption::TIMESTAMP])) {
            //默认值当前时间
            $timestamp = new \DateTime();
        } else {
            $timestamp = $options[SignOption::TIMESTAMP];
        }
        $timestamp->setTimezone(new \DateTimeZone("GMT"));

        //生成authString
        $authString = SampleSigner::BCE_AUTH_VERSION . '/' . $accessKeyId . '/'
            . $timestamp->format("Y-m-d\TH:i:s\Z") . '/' . $expirationInSeconds;

        //使用sk和authString生成signKey
        $signingKey = hash_hmac('sha256', $authString, $secretAccessKey);

        //生成标准化URI
        $canonicalURI = HttpUtil::getCanonicalURIPath($path);

        //生成标准化QueryString
        $canonicalQueryString = HttpUtil::getCanonicalQueryString($params);

        //填充headersToSign，也就是指明哪些header参与签名
        $headersToSign = null;
        if (isset($options[SignOption::HEADERS_TO_SIGN])) {
            $headersToSign = $options[SignOption::HEADERS_TO_SIGN];
        }

        //生成标准化header
        $canonicalHeader = HttpUtil::getCanonicalHeaders(
            SampleSigner::getHeadersToSign($headers, $headersToSign)
        );

        //整理headersToSign，以';'号连接
        $signedHeaders = '';
        if ($headersToSign !== null) {
            $signedHeaders = strtolower(
            //trim(implode(";", array_keys($headersToSign)))
                trim(implode(";", $headersToSign))
            );
        }

        //组成标准请求串
        $canonicalRequest = "$httpMethod\n$canonicalURI\n"
            . "$canonicalQueryString\n$canonicalHeader";
        //$canonicalRequest = "$httpMethod\n$canonicalURI\n\nhost:sms.bj.baidubce.com";
        //print var_export($canonicalRequest, true);
        //使用signKey和标准请求串完成签名
        $signature = hash_hmac('sha256', $canonicalRequest, $signingKey);

        //组成最终签名串
        $authorizationHeader = "$authString/$signedHeaders/$signature";

        return $authorizationHeader;
    }

    //根据headsToSign过滤应该参与签名的header
    public static function getHeadersToSign($headers, $headersToSign)
    {

        //print 'headers:' .var_export($headers, true);
        //print 'headersToSign:' .var_export($headersToSign, true);
        //value被trim后为空串的header不参与签名
        $filter_empty = function($v) {
            return trim((string) $v) !== '';
        };
        $headers = array_filter($headers, $filter_empty);

        //处理headers的key：去掉前后的空白并转化成小写
        $trim_and_lower = function($str){
            return strtolower(trim($str));
        };
        $temp = array();
        $process_keys = function($k, $v) use(&$temp, $trim_and_lower) {
            $temp[$trim_and_lower($k)] = $v;
        };
        array_map($process_keys, array_keys($headers), $headers);
        //array_map($process_keys, array_keys($headersToSign), $headersToSign);
        $headers = $temp;
        //print 'headers123:' .var_export($headers, true);
        //取出headers的key以备用
        $header_keys = array_keys($headers);
        // print 'header_keys:' .var_export($header_keys, true);
        $filtered_keys = null;
        if ($headersToSign !== null) {
            //如果有headersToSign，则根据headersToSign过滤

            //预处理headersToSign：去掉前后的空白并转化成小写
            $headersToSign = array_map($trim_and_lower, $headersToSign);
            //print 'headersToSign4321:' .var_export($headersToSign, true);
            //只选取在headersToSign里面的header
            $filtered_keys = array_intersect_key($header_keys, $headersToSign);

        } else {
            //如果没有headersToSign，则根据默认规则来选取headers
            $filter_by_default = function($k) {
                return SampleSigner::isDefaultHeaderToSign($k);
            };
            $filtered_keys = array_filter($header_keys, $filter_by_default);
        }
        //print 'headersToSign123:' .var_export($headersToSign, true);
        //print 'filtered_keys123:' .var_export($filtered_keys, true);
        //print 'headers4321:' .var_export($headers, true);
        //$filtered_keys = array('host');
        //返回需要参与签名的header
        return array_intersect_key($headers, array_flip($filtered_keys));
    }

    //检查header是不是默认参加签名的：
    //1.是host、content-type、content-md5、content-length之一
    //2.以x-bce开头
    public static function isDefaultHeaderToSign($header)
    {
        $header = strtolower(trim($header));
        if (in_array($header, SampleSigner::$defaultHeadersToSign)) {
            return true;
        }
        return substr_compare($header, SampleSigner::BCE_PREFIX, 0, strlen(SampleSigner::BCE_PREFIX)) == 0;
    }
}
SampleSigner::__init();


/*****************************************************************************/


class BaiduSms{
    //终端，默认为sms.bj.baidubce.com
    protected static $endPoint;
    //AK
    protected static $accessKey;
    //SK
    protected static $secretAccessKey;

    function __construct(array $config) {

    }

    /**
    * $message = array(
    *     "invokeId" => "2ZWOI6xV-AgpZ-2zIz",          //你申请的签名ID
    *     "phoneNumber" => "18852983890",  //手机电话号码
    *     "templateCode" => "smsTpl:e7476122a1c24e37b3b0de19d04ae901",  //模板的唯一标识
    *     "contentVar" => array(
    *       "code" =>  "283789",  //模板里面的key变量  ${key}
    *     ),
    *   );
    *
    *   返回一个数组:
    *   成功：array( 'code' => '1000', 'message' => '成功', 'requestId' => '45e1235-3b07-4421-83f8-cf4c74b1232c', )
    *   失败：array( 'requestId' => 'a1145bba-95c0-4341-83de-115d41741f0f', 'code' => '401', 'message' => '权限认证失败', )
    */

    static function sms($message_array,$config=null) {
        self::$endPoint = isset($config['endPoint']) ? $config['endPoint'] : 'sms.bj.baidubce.com';
        self::$accessKey = isset($config['accessKey']) ? $config['accessKey'] : '**********42d69bb01f************';
        self::$secretAccessKey = isset($config['secretAccessKey']) ? $config['secretAccessKey'] : '****537ca049949f********';
        $init_array = [
            "invokeId" => "2ZWOI6xV-A8pZ-****",
            "templateCode" => "smsTpl:e7476122a1c24*********"
        ];
        $message_array = array_merge($init_array,$message_array);
        //生成json格式
        $json_data = json_encode($message_array);

        //生成签名
        $signer = new SampleSigner();
        $credentials = array("ak" => self::$accessKey,"sk" => self::$secretAccessKey);
        $httpMethod = "POST";
        $path = "/bce/v2/message";
        $params = array();
        $timestamp = new \DateTime();
        $timestamp->setTimezone(new \DateTimeZone("GMT"));
        $datetime = $timestamp->format("Y-m-d\TH:i:s\Z");
        $datetime_gmt = $timestamp->format("D, d M Y H:i:s T");

        $headers = array("Host" => self::$endPoint);
        $str_sha256 = hash('sha256', $json_data);
        $headers['x-bce-content-sha256'] = $str_sha256;
        $headers['Content-Length'] = strlen($json_data);
        $headers['Content-Type'] = "application/json";
        $headers['x-bce-date'] = $datetime;
        $options = array(SignOption::TIMESTAMP => $timestamp, SignOption::HEADERS_TO_SIGN =>array('host', 'x-bce-content-sha256',),);
        $ret = $signer->sign($credentials, $httpMethod, $path, $headers, $params, $options);
        $headers_curl = [
            'Content-Type:application/json',
            'Host:' . self::$endPoint,
            'x-bce-date:' . $datetime,
            'Content-Length:' . strlen($json_data),
            'x-bce-content-sha256:' . $str_sha256,
            'Authorization:' . $ret,
            "Accept-Encoding: gzip,deflate",
            'User-Agent: Mozilla/5.0 (Windows; U; Windows NT 5.1; zh-CN; rv:1.9) Gecko/2008052906 Firefox/3.0',
            'Date:' .$datetime_gmt,
        ];


        $url = 'http://' . self::$endPoint . $path;
        $curl = curl_init();
        curl_setopt($curl, CURLOPT_URL, $url);
        curl_setopt($curl, CURLOPT_SSL_VERIFYPEER, FALSE);
        curl_setopt($curl, CURLOPT_SSL_VERIFYHOST, 2);
        curl_setopt($curl, CURLOPT_POST, 1);
        curl_setopt($curl, CURLOPT_POSTFIELDS, $json_data);
        curl_setopt($curl, CURLOPT_HTTPHEADER, $headers_curl);
        curl_setopt($curl, CURLOPT_RETURNTRANSFER, 1);
        $result = curl_exec($curl);
        curl_close($curl);
        return json_decode($result);
    }

}
