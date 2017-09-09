<?php

namespace Hcode\Model;

use \Hcode\DB\Sql;
use \Hcode\Model;
use \Hcode\Mailer;

class User extends Model{

	const SESSION = "User";
	const SECRET = "HcodePhp7_secret";

	public static function login($user, $password){

		$sql = new Sql();

		$results = $sql->select("SELECT * FROM tb_users WHERE deslogin = :LOGIN", array(
			":LOGIN" => $user
		));

		if(count($results) === 0){
			throw new \Exception("Usuário inexistente ou senha inválida.");
		}

		$data = $results[0];

		if(password_verify($password, $data['despassword']) === true){
			
			$user = new User();

			$user->setData($data);

			$_SESSION[User::SESSION] = $user->getValues();

		}else{
			throw new \Exception("Usuário inexistente ou senha inválida.");
		}

	}


	public static function verifyLogin($inadmin = true){

		if(!isset($_SESSION[User::SESSION]) 
			|| 
			!$_SESSION[User::SESSION] 
			|| 
			!(int)$_SESSION[User::SESSION]['iduser'] > 0
			||
			(bool)$_SESSION[User::SESSION]['inadmin'] != $inadmin
		) {
			header("Location: /admin/login");
			exit;
		}

	}

	public static function logout(){
		$_SESSION[User::SESSION] = NULL;
	}

	public static function listAll(){

		$sql = new Sql();

		return $sql->select("SELECT * FROM tb_users u INNER JOIN tb_persons p USING(idperson) ORDER BY desperson");

	}

	public function save(){
		$sql = new Sql();

		$results = $sql->select("CALL sp_users_save(:desperson, :deslogin, :despassword, :desemail, :nrphone, :inadmin)", array(
			":desperson"=>$this->getdesperson(),
			":deslogin"=>$this->getdeslogin(),
			":despassword"=>$this->getdespassword(),
			":desemail"=>$this->getdesemail(),
			":nrphone"=>$this->getnrphone(),
			":inadmin"=>$this->getinadmin()
		));

		$this->setData($results[0]);

	}

	public function get($iduser){
		$sql = new Sql();

		$results = $sql->select("SELECT * FROM tb_users u INNER JOIN tb_persons p USING(idperson) WHERE u.iduser = :iduser", array(
			":iduser"=>$iduser
		));

		$this->setData($results[0]);
	}

	public function update(){
		$sql = new Sql();

		$results = $sql->select("CALL sp_usersupdate_save(:iduser, :desperson, :deslogin, :despassword, :desemail, :nrphone, :inadmin)", array(
			":iduser"=>$this->getiduser(),
			":desperson"=>$this->getdesperson(),
			":deslogin"=>$this->getdeslogin(),
			":despassword"=>$this->getdespassword(),
			":desemail"=>$this->getdesemail(),
			":nrphone"=>$this->getnrphone(),
			":inadmin"=>$this->getinadmin()
		));

		$this->setData($results[0]);

	}

	public function delete(){

		$sql = new Sql();

		$sql->query("CALL sp_users_delete(:iduser)", array(
			":iduser"=>$this->getiduser()	
		));

	}

	public static function getForgot($email){
		
		$sql = new Sql();
		$results = $sql->select("
			SELECT * FROM tb_persons a 
			INNER JOIN tb_users b USING(idperson)
			WHERE a.desemail = :email;
			", array(":email"=>$email
				));

		if(count($results) === 0){
			throw new \Exception("Não foi possível recuperar a senha.", 1);
		}else{

			$data = $results[0];
			$results2 = $sql->select("CALL sp_userspasswordsrecoveries_create(:iduser, :desip)", array(
				":iduser"=>$data["iduser"],
				":desip"=>$_SERVER["REMOTE_ADDR"]
				));

			if(count($results2) === 0){
				throw new \Exeption("Não foi possível recuprera a senha");
			}else{
				$dataRecovery = $results2[0];
				$code = base64_encode(mcrypt_encrypt(MCRYPT_RIJNDAEL_128, User::SECRET, $dataRecovery['idrecovery'], MCRYPT_MODE_ECB));
				$link = "http://udemy-ecommerce.com/admin/forgot/reset?code=" . urlencode($code);

				$mailer = new Mailer($data['desemail'], $data['desperson'], "Redefinir Senha da Hcode Store", "forgot", 
					array(
						"name"=>$data['desperson'],
						"link"=>$link
					));
					echo $link;
					//die;
				try{
					$opa = $mailer->send();
				}catch (Exception $e){
					echo 'Não rolou';
					echo 'Erro: ' . $mailer->getmail->ErrorInfo;
					die;
				}
				return $data;

			}
		}

	}


	public static function validForgotDecrypt($code){

		$idrecovery = mcrypt_decrypt(MCRYPT_RIJNDAEL_128, User::SECRET, base64_decode($code), MCRYPT_MODE_ECB);

		echo "{$code}";
		echo '<br>';
		echo $idrecovery;
		echo '<br>';

		
		$sql = new Sql();

		$results = $sql->select("
				SELECT *
				FROM tb_userspasswordsrecoveries upr
				INNER JOIN tb_users u USING(iduser)
				INNER JOIN tb_persons p USING(idperson)
				WHERE
					upr.idrecovery = :idrecovery
					AND
					upr.dtrecovery IS NULL
					AND
					DATE_ADD(upr.dtregister, INTERVAL 1 HOUR) >= NOW();
			", array(
				":idrecovery"=>$idrecovery));

		if(count($results) === 0){
			throw new \Exception("Não foi possível recuperar a senha");
		}else{
			return $results[0];
		}

	}


	public static function setForgotUsed($idrecovery){

		$sql = new Sql();

		$sql->query("UPDATE tb_userspasswordsrecoveries SET dtrecovery = NOW() WHERE idrecovery = :idrecovery", array(
			":idrecovery"=>$idrecovery
		));

	}

	public function setPassword($password){

		$sql = new Sql();

		$sql->query("UPDATE tb_users SET despassword = :password WHERE iduser = :iduser", array(
			":password"=>$password,
			"iduser"=>$this->getiduser()
		));

	}


}