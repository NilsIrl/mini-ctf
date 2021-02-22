use askama::Template;

#[derive(Template)]
#[template(path = "search_users.html")]
pub struct SearchTemplate {
    pub users: Vec<crate::User>,
    pub message: Option<String>,
}

#[derive(Template)]
#[template(path = "signup.html")]
pub struct SignupPage {
    message: Option<String>,
}

impl SignupPage {
    pub fn new() -> Self {
        Self { message: None }
    }

    pub fn with_message(message: String) -> Self {
        Self {
            message: Some(message),
        }
    }
}

#[derive(Template)]
#[template(path = "404.html")]
pub struct NotFoundTemplate {}

#[derive(Template)]
#[template(path = "secret.html")]
pub struct SecretTemplate {
    pub flag: String,
}

pub struct Message {
    pub author: String,
    pub message: String,
}

#[derive(Template)]
#[template(path = "home.html", escape = "none")]
pub struct HomeTemplate {
    pub messages: Vec<Message>,
    pub account: Option<String>,
    pub message: Option<String>,
}

#[derive(Template)]
#[template(path = "admin.html")]
pub struct AdminTemplate<'a> {
    pub is_admin: bool,
    pub message: Option<&'a str>,
}
