<?php

use Tool as GlobalTool;

class Tool
{
   // private static $mcryptKey = 'xmwk@2013';
    private static $mcryptKey = '9a85dbc588e0d4e5bdf96748e3a9d81';

    private static $_use_openssl = false;
    /**
     *
     * @param string $str |自动去除前后的空格,验证时要注意
     * @return string
     */
    public static function setMcryptKey($key) {
        self::$mcryptKey = $key;
        return true;
    }

    public static function getMcryptKey() {
        return self::$mcryptKey ;
    }

    public static function encodeId($str) {
        $str = trim($str);
        if (!strlen($str)) {
            return false;
        }
        if( self::$_use_openssl){
            return self::openSslencrypt($str);
        }
       $mc_key = md5(self::$mcryptKey);
          $td = @mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_ECB, '');
         $iv = @mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
         $key = substr($mc_key, 0, @mcrypt_enc_get_key_size($td));
         @mcrypt_generic_init($td, $key, $iv);
         $ret = base64_encode(@mcrypt_generic($td, $str));
         @mcrypt_generic_deinit($td);
         @mcrypt_module_close($td);
         return $ret;
        /*$data = openssl_encrypt($str,'AES-128-ECB',$mc_key);
       // return base64_encode($data);
        return $data;*/
    }


    public static function decodeId($str) {

       $str = base64_decode($str);
        if (!strlen($str)) {
            return false;
        }

        if( self::$_use_openssl){
            return self::openSsldecrypt($str);
        }

        $mc_key = md5(self::$mcryptKey);
        
      $td = @mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_ECB, '');
      $iv = @mcrypt_create_iv(mcrypt_enc_get_iv_size($td), MCRYPT_RAND);
      $key = substr($mc_key, 0, @mcrypt_enc_get_key_size($td));
      @mcrypt_generic_init($td, $key, $iv);
      $ret = trim(@mdecrypt_generic($td, $str));
      @mcrypt_generic_deinit($td);
      @mcrypt_module_close($td);
      return $ret;
     /*   $decrypted = openssl_decrypt( $str, 'AES-128-ECB',$mc_key);
        return $decrypted;*/
    }

  

    public static function mcryptEncrypt($input, $key='') {
      
      $key = md5(self::$mcryptKey);
      $size = mcrypt_get_block_size(MCRYPT_RIJNDAEL_128, MCRYPT_MODE_ECB);
      $input = self::pkcs5Pad($input, $size);
      $td = mcrypt_module_open(MCRYPT_RIJNDAEL_128, '', MCRYPT_MODE_ECB, '');
      $iv = mcrypt_create_iv (mcrypt_enc_get_iv_size($td), MCRYPT_RAND);//MCRYPT_DEV_URANDOM
      mcrypt_generic_init($td, $key, $iv);
      $data = mcrypt_generic($td, $input);
      mcrypt_generic_deinit($td);
      mcrypt_module_close($td);
      $data = base64_encode($data);
      return $data;
  }
  /**
   * PK5计算
   * @param  [type] $text
   * @param  [type] $blocksize
   * @return [type]
   */
  public static function pkcs5Pad($text, $blocksize) {
      $pad = $blocksize - (strlen($text) % $blocksize);
      return $text . str_repeat(chr($pad), $pad);
  }
  
  /**
   *  PHP7用这个方法，没经过测试
   * @param $sStr
   * @param $sKey
   * @param string $method
   * @return string
   */
  public static  function opensslNewEncrypt($sStr, $sKey='', $method = 'AES-256-ECB'){
    $skey = md5(self::$mcryptKey);
    $key =  $skey;
    //加密 不需要OPENSSL_ZERO_PADDING
    $chiperRaw = openssl_encrypt($sStr, 'aes-256-ecb', $key,OPENSSL_RAW_DATA);;
    return trim(base64_encode($chiperRaw));
      
  }

  public static  function openSslNewDecrypt($str) { 
    $mc_key = md5(self::$mcryptKey);
     //解密 需要OPENSSL_ZERO_PADDING
    $decrypted =  openssl_decrypt(base64_decode($str), 'aes-256-ecb', $mc_key, OPENSSL_RAW_DATA|OPENSSL_ZERO_PADDING);
    return $decrypted;
}



  
}




$rawStr = '{"uname":"king","price":100.01,"singpirce":12}';


$oStr = Tool::encodeId($rawStr);
echo 'encodeId: ', $oStr,PHP_EOL;
$oStr = 'IOX/uc5cufvu1SNk+NWfwUcLkD0ZvVaskGePEgjnQbkcWq4sStJjZHBmMk2urWt3';
$oStr1 = Tool::openSslNewDecrypt($oStr);
echo 'openSslNewDecrypt: ',$oStr1,PHP_EOL;

$iStr = Tool::decodeId($oStr);
echo 'decodeId: ',  $iStr ,PHP_EOL;





$oStr = Tool::opensslNewEncrypt($rawStr);
echo 'opensslNewEncrypt: ', $oStr,PHP_EOL;
//$iStr = Tool::decodeId($oStr);
//echo 'decodeId: ',$iStr ,PHP_EOL;
$oStr1 = Tool::openSslNewDecrypt($oStr);
echo 'openSslNewDecrypt: ',$oStr1,PHP_EOL;


/* $oStr = Tool::openSslencrypt($rawStr);
echo $oStr,PHP_EOL;
$iStr = Tool::openSsldecrypt($oStr);
echo $iStr ,PHP_EOL; */
