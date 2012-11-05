<?php
/*
Controller Name: Posts
Controller Description: Data manipulation methods for posts with Authentication method added
Controller Author: Matt Berg
Controller Author Twitter: @mattberg
*/

class JSON_API_Posts_Controller {

	public function create_post() {

		global $json_api;

		if (!$json_api->query->nonce) {
			$json_api->error("You must include a 'nonce' value to create posts. Use the `get_nonce` Core API method.");
		}

		if (!$json_api->query->cookie) {
			$json_api->error("You must include a 'cookie' authentication cookie. Use the `create_auth_cookie` Auth API method.");
		}

		$nonce_id = $json_api->get_nonce_id('posts', 'create_post');
		if (!wp_verify_nonce($json_api->query->nonce, $nonce_id)) {
			$json_api->error("Your 'nonce' value was incorrect. Use the 'get_nonce' API method.");
		}

		$user_id = wp_validate_auth_cookie($json_api->query->cookie, 'logged_in');
		if (!$user_id) {
			$json_api->error("Invalid authentication cookie. Use the `generate_auth_cookie` Auth API method.");
		}

		if (!user_can($user_id, 'edit_posts')) {
			$json_api->error("You need to login with a user capable of creating posts.");
		}

		nocache_headers();

		$post = new JSON_API_Post();

		$id = $post->create($_REQUEST);
		if (empty($id)) {
			$json_api->error("Could not create post.");
		}

		return array(
			'post' => $post
		);

	}
  
}