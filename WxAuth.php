<?php
namespace  wxgzh;

use wxgzh\WXBizMsgCrypt;
/**
 * Class WxAuth
 * @package wxgzh
 * @property WXBizMsgCrypt pc
 */
class WxAuth{

	protected $encodingAesKey;
	protected $token;
	protected $nonce;
	protected $appId;
	protected $pc;
	public function __construct($config)
	{
		$this->token=$config['token'];
		$this->encodingAesKey=$config['encodingAesKey'];
		$this->appId=$config['appId'];
		$this->pc=new WXBizMsgCrypt($this->token, $this->encodingAesKey, $this->appId);
	}

	/**
	 * 第三方发送消息给公众号
	 * @param  string $text 内容
	 * @param string  $nonce 自定义
	 * @param int     $timeStamp 时间戳
	 * @return array  加密的内容
	 */
	public  function comment($text,$nonce,$timeStamp){
		// 第三方发送消息给公众平台
		$encryptMsg ='';
		$errCode = $this->pc->encryptMsg($text, $timeStamp, $nonce,$encryptMsg);
		if ($errCode == 0) {
			$res['code']=0;
			$res['msg']=$encryptMsg;
		} else {
			$res['code']=0;
		}
		return $res;
	}

	/**
	 * 第三方收到公众平台发送的消息解密
	 * @param string $encryptMsg  需要解密的内容
	 * @param string $timeStamp  时间戳
	 * @param string $nonce   自定义参数
	 * @return array  解密内容
	 */
	public function deComment($encryptMsg,$timeStamp,$nonce){
		$xml_tree = new \DOMDocument();
		$xml_tree->loadXML($encryptMsg);
		$array_e = $xml_tree->getElementsByTagName('Encrypt');
		$array_s = $xml_tree->getElementsByTagName('MsgSignature');
		$encrypt = $array_e->item(0)->nodeValue;
		$msg_sign = $array_s->item(0)->nodeValue;
		$format = "<xml><ToUserName><![CDATA[toUser]]></ToUserName><Encrypt><![CDATA[%s]]></Encrypt></xml>";
		$from_xml = sprintf($format, $encrypt);
		$msg = '';
		$errCode = $this->pc->decryptMsg($msg_sign, $timeStamp, $nonce, $from_xml, $msg);
		if ($errCode == 0) {
			$res['code']=0;
			$res['msg']=$msg;
		} else {
			$res['code']=0;
		}
		return $res;
	}

	/**
	 * 验证票据
	 *component_verify_ticket解密
	 * @param  string $encryptMsg 需要解密的参数
	 * @param  string $timeStamp 时间戳
	 * @param   string $nonce   自定义参数
	 * @param   string $msg_sign 验证值
	 * @return  array	解密内容
	 */
	public function deComponentVerifyTicket($encryptMsg,$timeStamp,$nonce,$msg_sign){
		$xml_tree = new \DOMDocument();
		$xml_tree->loadXML($encryptMsg);
		$array_e = $xml_tree->getElementsByTagName('Encrypt');
		$encrypt = $array_e->item(0)->nodeValue;
		$format = "<xml><ToUserName><![CDATA[toUser]]></ToUserName><Encrypt><![CDATA[%s]]></Encrypt></xml>";
		$from_xml = sprintf($format, $encrypt);
		$msg = '';
		$errCode = $this->pc->ticketDecryptMsg($msg_sign, $timeStamp, $nonce, $from_xml, $msg);
		if ($errCode == 0) {
			$res['code']=0;
			$res['msg']=$msg;
		} else {
			$res['code']=0;
		}
		return $res;
	}

}

