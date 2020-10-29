#[macro_use] extern crate pam;
extern crate rand;
extern crate reqwest;

use pam::module::{PamHandle, PamHooks};
use pam::constants::{PamResultCode, PamFlag, PAM_PROMPT_ECHO_ON, PAM_TEXT_INFO};
use pam::conv::PamConv;
use rand::Rng;
use reqwest::blocking::Client;
use reqwest::StatusCode;
use std::str::FromStr;
use std::ffi::CStr;
use std::fs;

macro_rules! pam_try {
    ($e:expr) => (
        match $e {
            Ok(v) => v,
            Err(e) => return e,
        }
    );
    ($e:expr, $err:expr) => (
        match $e {
            Ok(v) => v,
            Err(e) => {
                println!("Error: {}", e);
                return $err;
            }
        }
    );
}

struct PamSober;
pam_hooks!(PamSober);

impl PamHooks for PamSober {
    // This function performs the task of authenticating the user.
    fn sm_authenticate(pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        println!("Let's make sure you're sober enough to perform basic addition");

        let conv = match pamh.get_item::<PamConv>() {
            Ok(conv) => conv,
            Err(err) => {
                println!("Couldn't get pam_conv");
                return err;
            }
        };

        let mut rng = rand::thread_rng();
        let id = rng.gen::<u32>() % 1000;
        let secret = rng.gen::<u32>() % 100000;

        let client = reqwest::blocking::Client::new();
        let url = fs::read_to_string("/etc/discord-url").expect("Error reading file");
        let payload = [("content", format!("Login token #{}: {}", id, secret))];
        client.post(&url).form(&payload).send().expect("Error sending token");

        let prompt = format!("Token #{}: ", id);

        let password = pam_try!(conv.send(PAM_PROMPT_ECHO_ON, &prompt));

        if password.and_then(|p| u32::from_str(&p).ok()) == Some(secret) {
            return PamResultCode::PAM_SUCCESS;
        }

        println!("Invalid token.");
        return PamResultCode::PAM_AUTH_ERR;
    }

    fn sm_setcred(_pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        println!("set credentials");
        PamResultCode::PAM_SUCCESS
    }

    fn acct_mgmt(_pamh: &PamHandle, _args: Vec<&CStr>, _flags: PamFlag) -> PamResultCode {
        println!("account management");
        PamResultCode::PAM_SUCCESS
    }
}

