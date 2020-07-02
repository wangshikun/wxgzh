<?php

namespace  wsk\wxgzh;
/**
 * Prpcrypt class
 *
 * �ṩ���պ����͸�����ƽ̨��Ϣ�ļӽ��ܽӿ�.
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
	 * �����Ľ��м���
	 * @param string $text ��Ҫ���ܵ�����
	 * @param string $app_id app_id
	 * @return array ���ܺ������
	 */
	public function encrypt($text, $app_id)
	{
		try {
			//���16λ����ַ�������䵽����֮ǰ
			$random = $this->getRandomStr();
			//16λ�����+������+����ԭ��+app_id
			$text = $random . pack("N", strlen($text)) . $text . $app_id;
			$iv = substr($this->key, 0, 16);
			//ʹ���Զ������䷽ʽ�����Ľ��в�λ���
			$pkc_encoder = new PKCS7Encoder;
			$text = $pkc_encoder->encode($text);
			$encrypted=openssl_encrypt($text,$this->method,$this->key,OPENSSL_RAW_DATA,$iv);
			return array(ErrorCode::$OK, base64_encode($encrypted));
		} catch (Exception $e) {
			return array(ErrorCode::$EncryptAESError, null);
		}
	}

	/**
	 * �����Ľ��н���
	 * @param string $encrypted ��Ҫ���ܵ�����
	 * @param string $app_id  app_id
	 * @return array ���ܵõ�������
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
			//ȥ����λ�ַ�
			$pkc_encoder = new PKCS7Encoder;
			$result = $pkc_encoder->decode($decrypted);
			//ȥ��16λ����ַ���,�����ֽ����AppId
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
	 * �������16λ�ַ���
	 * @return string ���ɵ��ַ���
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