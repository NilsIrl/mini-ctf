use actix_session::{CookieSession, Session};
use actix_web::{get, http, middleware::Logger, post, web, App, Either, HttpResponse, HttpServer};
use askama::Template;
use futures_util::stream::StreamExt;
use serde::Deserialize;
use sqlx::{Executor, Row, SqlitePool};
use tokio::sync::RwLock;

mod templates;

use templates::{
    HomeTemplate, Message, NotFoundTemplate, SearchTemplate, SecretTemplate, SignupPage,
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
}

#[derive(Deserialize)]
struct Secret {
    flag: String,
}

#[get("/setsecret")]
async fn setsecret(newflag: web::Query<Secret>, secretflag: web::Data<Flag>) -> HttpResponse {
    HttpResponse::Ok().body(if secretflag.flag1.read().await.is_empty() {
        *secretflag.flag1.write().await = newflag.flag.clone();
        format!("Sucessfully set flag to: {}", secretflag.flag1.read().await)
    } else {
        "Flag already set".to_string()
    })
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
