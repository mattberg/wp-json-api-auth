<?php
/*
Controller Name: Auth
Controller Description: Authentication add-on controller for the Wordpress JSON API plugin
Controller Author: Matt Berg
Controller Author Twitter: @mattberg
*/

class JSON_API_Auth_Controller {

	public function validate_auth_cookie() {
		global $json_api;

		if (!$json_api->query->cookie) {
			$json_api->error("You must include a 'cookie' authentication cookie. Use the `create_auth_cookie` Auth API method.");
		}		

    	$valid = wp_validate_auth_cookie($json_api->query->cookie, 'logged_in') ? true : false;

		return array(
			"valid" => $valid
		);
	}

	public function generate_auth_cookie() {
		global $json_api;

		$nonce_id = $json_api->get_nonce_id('auth', 'generate_auth_cookie');
		if (!wp_verify_nonce($json_api->query->nonce, $nonce_id)) {
			$json_api->error("Your 'nonce' value was incorrect. Use the 'get_nonce' API method.");
		}

		if (!$json_api->query->username) {
			$json_api->error("You must include a 'username' var in your request.");
		}
		
		if (!$json_api->query->password) {
			$json_api->error("You must include a 'password' var in your request.");
		}		

    	$user = wp_authenticate($json_api->query->username, $json_api->query->password);
    	if (is_wp_error($user)) {
    		$json_api->error("Invalid username and/or password.", 'error', '401');
    		remove_action('wp_login_failed', $json_api->query->username);
    	}

    	$expiration = time() + apply_filters('auth_cookie_expiration', 1209600, $user->ID, true);

    	$cookie = wp_generate_auth_cookie($user->ID, $expiration, 'logged_in');

		return array(
			"cookie" => $cookie,
			"user" => array(
				"id" => $user->ID,
				"username" => $user->user_login,
				"nicename" => $user->user_nicename,
				"email" => $user->user_email,
				"url" => $user->user_url,
				"registered" => $user->user_registered,
				"displayname" => $user->display_name,
				"firstname" => $user->user_firstname,
				"lastname" => $user->last_name,
				"nickname" => $user->nickname,
				"description" => $user->user_description,
				"capabilities" => $user->wp_capabilities,
			),
		);
	}
	
	public function get_currentuserinfo() {
		global $json_api;

		if (!$json_api->query->cookie) {
			$json_api->error("You must include a 'cookie' var in your request. Use the `generate_auth_cookie` Auth API method.");
		}

		$user_id = wp_validate_auth_cookie($json_api->query->cookie, 'logged_in');
		if (!$user_id) {
			$json_api->error("Invalid authentication cookie. Use the `generate_auth_cookie` Auth API method.");
		}

		$user = get_userdata($user_id);

		return array(
			"user" => array(
				"id" => $user->ID,
				"username" => $user->user_login,
				"nicename" => $user->user_nicename,
				"email" => $user->user_email,
				"url" => $user->user_url,
				"registered" => $user->user_registered,
				"displayname" => $user->display_name,
				"firstname" => $user->user_firstname,
				"lastname" => $user->last_name,
				"nickname" => $user->nickname,
				"description" => $user->user_description,
				"capabilities" => $user->wp_capabilities,
			)
		);
	}	

}