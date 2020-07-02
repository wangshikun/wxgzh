<?php

namespace  wsk\wxgzh;
/**
 * Prpcrypt class
 *
 * 提供接收和推送给公众平台消息的加解密接口.
 */
class PrpCrypt
{
	public $key;
	protected $method='AES-256-CBC';
	function __construct($k)
	{
		$this->key = base64_decode($k . "=");
	}

	/**
	 * 对明文进行加密
	 * @param string $text 需要加密的明文
	 * @param string $app_id app_id
	 * @return array 加密后的密文
	 */
	public function encrypt($text, $app_id)
	{
		try {
			//获得16位随机字符串，填充到明文之前
			$random = $this->getRandomStr();
			//16位随机数+二级制+加密原文+app_id
			$text = $random . pack("N", strlen($text)) . $text . $app_id;
			$iv = substr($this->key, 0, 16);
			//使用自定义的填充方式对明文进行补位填充
			$pkc_encoder = new PKCS7Encoder;
			$text = $pkc_encoder->encode($text);
			$encrypted=openssl_encrypt($text,$this->method,$this->key,OPENSSL_RAW_DATA,$iv);
			return array(ErrorCode::$OK, base64_encode($encrypted));
		} catch (Exception $e) {
			return array(ErrorCode::$EncryptAESError, null);
		}
	}

	/**
	 * 对密文进行解密
	 * @param string $encrypted 需要解密的密文
	 * @param string $app_id  app_id
	 * @return array 解密得到的明文
	 */
	public function decrypt($encrypted, $app_id)
	{
		try {
			$iv = substr($this->key, 0, 16);
			$decrypted =openssl_decrypt(base64_decode($encrypted),$this->method,$this->key,OPENSSL_RAW_DATA,$iv);
		} catch (Exception $e) {
			return array(ErrorCode::$EncryptAESError, null);
		}
		try {
			//去除补位字符
			$pkc_encoder = new PKCS7Encoder;
			$result = $pkc_encoder->decode($decrypted);
			//去除16位随机字符串,网络字节序和AppId
			if (strlen($result) < 16)
				return "";
			$content = substr($result, 16, strlen($result));
			$len_list = unpack("N", substr($content, 0, 4));
			$xml_len = $len_list[1];
			$xml_content = substr($content, 4, $xml_len);
			$from_appid = substr($content, $xml_len + 4);
		} catch (Exception $e) {
			//print $e;
			return array(ErrorCode::$IllegalBuffer, null);
		}
		if ($from_appid != $app_id)
			return array(ErrorCode::$ValidateAppidError, null);
		return array(0, $xml_content);

	}


	/**
	 * 随机生成16位字符串
	 * @return string 生成的字符串
	 */
	function getRandomStr()
	{
		$str = "";
		$str_pol = "ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789abcdefghijklmnopqrstuvwxyz";
		$max = strlen($str_pol) - 1;
		for ($i = 0; $i < 16; $i++) {
			$str .= $str_pol[mt_rand(0, $max)];
		}
		return $str;
	}

}