use actix_session::{CookieSession, Session};
use actix_web::{get, http, middleware::Logger, post, web, App, Either, HttpResponse, HttpServer};
use askama::Template;
use block_modes::BlockMode;
use futures_util::stream::StreamExt;
use serde::Deserialize;
use sqlx::{Executor, Row, SqlitePool};
use tokio::sync::RwLock;

mod templates;

use templates::{
    AdminTemplate, HomeTemplate, Message, NotFoundTemplate, SearchTemplate, SecretTemplate,
    SignupPage,
};

fn home_redirect() -> HttpResponse {
    HttpResponse::Found()
        .header(http::header::LOCATION, "/")
        .finish()
}

#[derive(Deserialize)]
struct Search {
    username: Option<String>,
}

pub struct User {
    id: u32,
    username: String,
}

async fn admin_check(session: Session, conn: web::Data<SqlitePool>) -> bool {
    match session.get::<i32>("id").unwrap() {
        Some(id) => {
            if sqlx::query("SELECT null FROM user WHERE id = ? AND is_admin = 1")
                .bind(id)
                .fetch_optional(&**conn)
                .await
                .unwrap()
                .is_some()
            {
                true
            } else {
                false
            }
        }
        None => false,
    }
}

type Aes256Cbc = block_modes::Cbc<aes::Aes256, block_modes::block_padding::Pkcs7>;

#[derive(Deserialize)]
struct Signature {
    ciphertext: String,
}

#[post("/admin")]
async fn admin_sign(
    decrypt: web::Query<Signature>,
    session: Session,
    conn: web::Data<SqlitePool>,
    secrets: web::Data<Flag>,
) -> AdminTemplate {
    if admin_check(session, conn).await {
        AdminTemplate {
            message: Some(
                {
                    match hex::decode(&decrypt.ciphertext) {
                        Ok(mut ciphertext) => {
                            let cipher = Aes256Cbc::new_var(
                                &secrets.key.read().await.unwrap(),
                                &ciphertext[..16],
                            )
                            .unwrap();
                            match cipher.decrypt(&mut ciphertext[16..]) {
                                Ok(_) => "Signature successfully set",
                                Err(_) => "There was an error setting your signature",
                            }
                        }
                        Err(_) => "Error decoding hex :(",
                    }
                }
                .to_string(),
            ),
            is_admin: true,
        }
    } else {
        AdminTemplate {
            message: None,
            is_admin: false,
        }
    }
}

#[get("/admin")]
async fn admin_page(session: Session, conn: web::Data<SqlitePool>) -> AdminTemplate {
    if admin_check(session, conn).await {
        AdminTemplate {
            message: None,
            is_admin: true,
        }
    } else {
        AdminTemplate {
            message: None,
            is_admin: false,
        }
    }
}

#[get("/search")]
async fn search_users(search: web::Query<Search>, conn: web::Data<SqlitePool>) -> SearchTemplate {
    let mut message = None;

    let users = match &search.username {
        Some(username) => conn
            .fetch_all(
                format!(
                    "SELECT id, username FROM user WHERE username LIKE '%{}%'",
                    username
                )
                .as_str(),
            )
            .await
            .unwrap_or_else(|err| {
                message = Some(err.to_string());
                Vec::new()
            })
            .iter()
            .map(|row| User {
                id: row.try_get("id").unwrap_or_else(|err| {
                    message = Some(err.to_string());
                    0
                }),
                username: row.try_get("username").unwrap_or_else(|err| {
                    message = Some(err.to_string());
                    "".to_string()
                }),
            })
            .collect(),

        None => Vec::new(),
    };

    SearchTemplate { message, users }
}

#[derive(Deserialize)]
struct SignUp {
    username: String,
    password: String,
    signup: Option<String>,
}

#[get("/users")]
async fn signup_page() -> SignupPage {
    SignupPage::new()
}

type SignResult = Either<HttpResponse, SignupPage>;

#[post("/users")]
async fn signup_request(
    form: web::Form<SignUp>,
    conn: web::Data<SqlitePool>,
    session: Session,
) -> SignResult {
    if form.signup.is_some() {
        Either::B(
            match conn
                .execute(
                    format!(
                        "INSERT INTO user (username, password) VALUES ('{}', '{}')",
                        form.username, form.password
                    )
                    .as_str(),
                )
                .await
            {
                Ok(_) => SignupPage::with_message("Successfully created account".to_string()),
                Err(err) => SignupPage::with_message(format!(
                    "Error when creating account: {}",
                    err.to_string()
                )),
            },
        )
    } else {
        match conn
            .fetch_one(&*format!(
                "SELECT id FROM user WHERE username = '{}' AND password = '{}'",
                form.username, form.password
            ))
            .await
        {
            Ok(row) => {
                session.set::<i32>("id", row.get("id")).unwrap();
                Either::A(home_redirect())
            }
            Err(err) => Either::B(SignupPage::with_message(format!(
                "Error logging in: {}",
                err.to_string()
            ))),
        }
    }
}

#[get("/logout")]
async fn logout(session: Session) -> HttpResponse {
    session.remove("id");
    home_redirect()
}

struct Flag {
    flag1: RwLock<String>,
    key: RwLock<Option<[u8; 32]>>,
}

#[derive(Deserialize)]
struct Secret {
    flag: Option<String>,
    key: Option<String>,
}

#[get("/setsecret")]
async fn setsecret(newflag: web::Query<Secret>, secretflag: web::Data<Flag>) -> HttpResponse {
    let mut message = String::new();
    if let Some(flag) = &newflag.flag {
        if secretflag.flag1.read().await.is_empty() {
            *secretflag.flag1.write().await = flag.to_string();
            message.push_str(&format!("Set flag to {}", secretflag.flag1.read().await));
        } else {
            message.push_str("Flag already set.");
        }
    };

    if let Some(key) = &newflag.key {
        if secretflag.key.read().await.is_none() {
            let mut bytes = [0u8; 32];
            match hex::decode_to_slice(key, &mut bytes) {
                Ok(()) => {
                    *secretflag.key.write().await = Some(bytes);
                    message.push_str(&format!(
                        "Set key to {}",
                        hex::encode(secretflag.key.read().await.unwrap())
                    ));
                }
                Err(_) => {
                    message.push_str("Error decoding key from hex.");
                }
            };
        } else {
            message.push_str("Key already set.");
        }
    };

    HttpResponse::Ok().body(message)
}

#[get("/secret")]
async fn secret(session: Session, secretflag: web::Data<Flag>) -> SecretTemplate {
    SecretTemplate {
        flag: if session.get::<i32>("secret").unwrap().unwrap_or(0) == 1337 {
            (*secretflag.flag1.read().await).clone()
        } else {
            "".to_string()
        },
    }
}

async fn home_page_with_message(
    message: Option<String>,
    session: Session,
    conn: web::Data<SqlitePool>,
) -> HomeTemplate {
    HomeTemplate {
        account: match session.get::<i32>("id").unwrap(){
            Some(id) => conn.fetch_one(&*format!(
                        "SELECT username FROM user WHERE id = {}",
                        id)).await.ok().map(|row| row.get("username")),
            None => None,
        },
        messages:
    conn.fetch(
        "SELECT username, message FROM message INNER JOIN user ON user.id = message.authorId ORDER BY message.id DESC",
    ).map(|row| {let row = row.unwrap(); Message {

        message: row.get("message"),
        author: row.get("username")
    }}).collect().await,
        message,
    }
}

#[get("/")]
async fn home_page(session: Session, conn: web::Data<SqlitePool>) -> HomeTemplate {
    home_page_with_message(None, session, conn).await
}

#[derive(Deserialize)]
struct NewMessage {
    message: String,
}

#[post("/")]
async fn new_message(
    form: web::Form<NewMessage>,
    session: Session,
    conn: web::Data<SqlitePool>,
) -> HomeTemplate {
    match session.get::<i32>("id").unwrap() {
        Some(id) => {
            sqlx::query("INSERT INTO message (authorId, message) VALUES(?, ?)")
                .bind(id)
                .bind(&*form.message)
                .execute(&**conn)
                .await
                .unwrap();
            home_page_with_message(None, session, conn).await
        }
        None => {
            home_page_with_message(
                Some("You need to be logged in to send a message.".to_string()),
                session,
                conn,
            )
            .await
        }
    }
}

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    env_logger::init();

    let conn = SqlitePool::connect("sqlite::memory:").await.unwrap();
    conn.execute(
        "CREATE TABLE user (
        id INTEGER PRIMARY KEY,
        username TEXT NOT NULL UNIQUE,
        password TEXT NOT NULL,
        is_admin INTEGER DEFAULT 0)",
    )
    .await
    .unwrap();
    conn.execute(
        "CREATE TABLE message (
            id INTEGER PRIMARY KEY,
            authorId INTEGER REFERENCES user (id),
            message TEXT NOT NULL)",
    )
    .await
    .unwrap();

    conn.execute(
        "INSERT INTO user (username, password, is_admin) VALUES ('admin', 'flag{hunter2}', 1)",
    )
    .await
    .unwrap();

    HttpServer::new(move || {
        App::new()
            .data(conn.clone())
            .data(Flag {
                flag1: RwLock::new(String::new()),
                key: RwLock::new(None),
            })
            .wrap(CookieSession::signed(&[0; 32]).http_only(false))
            .wrap(Logger::default())
            .service(signup_page)
            .service(signup_request)
            .service(search_users)
            .service(logout)
            .service(secret)
            .service(home_page)
            .service(new_message)
            .service(setsecret)
            .service(admin_page)
            .service(admin_sign)
            .route(
                "/robots.txt",
                web::get().to(|| {
                    HttpResponse::Ok().body(
                        "User-agent: *
Disallow: /secret",
                    )
                }),
            )
            .default_service(web::to(|| {
                HttpResponse::NotFound().body(NotFoundTemplate {}.render().unwrap())
            }))
    })
    .bind("127.0.0.1:8080")?
    .run()
    .await
}
