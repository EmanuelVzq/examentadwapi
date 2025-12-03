use actix_cors::Cors;
use actix_web::{web, App, HttpRequest, HttpResponse, HttpServer, Responder};
use chrono::{Duration, Utc};
use dotenvy::dotenv;
use jsonwebtoken::{decode, encode, DecodingKey, EncodingKey, Header, Validation};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use sqlx::{Pool, Postgres};
use std::env;
use uuid::Uuid;

// =========================
// Estado global
// =========================

#[derive(Clone)]
struct AppState {
    db_pool: Pool<Postgres>,
    jwt_secret: String,
    http_client: reqwest::Client,
}

// =========================
// Modelos de BD y DTOs
// =========================

#[derive(sqlx::FromRow, Debug, Clone)]
struct DbUser {
    id: Uuid,
    email: String,
    password_hash: String,
    full_name: Option<String>,
    phone: Option<String>,
    role: String,
    last_login: Option<chrono::DateTime<chrono::Utc>>,
    created_at: chrono::DateTime<chrono::Utc>,
}

#[derive(Serialize)]
struct PublicUser {
    id: Uuid,
    email: String,
    full_name: Option<String>,
    phone: Option<String>,
    role: String,
    last_login: Option<chrono::DateTime<chrono::Utc>>,
}

impl From<DbUser> for PublicUser {
    fn from(u: DbUser) -> Self {
        Self {
            id: u.id,
            email: u.email,
            full_name: u.full_name,
            phone: u.phone,
            role: u.role,
            last_login: u.last_login,
        }
    }
}

// ========== Auth DTOs ==========

#[derive(Deserialize)]
struct RegisterRequest {
    email: String,
    password: String,
    full_name: Option<String>,
    phone: Option<String>,
    role: Option<String>, // opcional, por defecto "user"
}

#[derive(Deserialize)]
struct LoginRequest {
    email: String,
    password: String,
}

#[derive(Serialize)]
struct LoginResponse {
    token: String,
    user: PublicUser,
}

#[derive(Deserialize)]
struct ChangePasswordRequest {
    current_password: String,
    new_password: String,
}

// JWT Claims
#[derive(Serialize, Deserialize)]
struct Claims {
    sub: String, // user id
    role: String,
    exp: usize,
}

// =========================
// Utilidades: hash y JWT
// =========================

fn hash_password(password: &str) -> Result<String, argon2::password_hash::Error> {
    use argon2::{
        password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
        Argon2,
    };
    let salt = SaltString::generate(&mut OsRng);
    let argon2 = Argon2::default();
    let hash = argon2.hash_password(password.as_bytes(), &salt)?;
    Ok(hash.to_string())
}

fn verify_password(hash: &str, password: &str) -> bool {
    use argon2::{
        password_hash::{PasswordHash, PasswordVerifier},
        Argon2,
    };
    if let Ok(parsed_hash) = PasswordHash::new(hash) {
        Argon2::default()
            .verify_password(password.as_bytes(), &parsed_hash)
            .is_ok()
    } else {
        false
    }
}

fn generate_jwt(user: &DbUser, secret: &str) -> Result<String, jsonwebtoken::errors::Error> {
    let expiration = Utc::now() + Duration::hours(8); // token de 8 horas
    let claims = Claims {
        sub: user.id.to_string(),
        role: user.role.clone(),
        exp: expiration.timestamp() as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(secret.as_bytes()),
    )
}

fn extract_token(req: &HttpRequest) -> Option<String> {
    let auth_header = req.headers().get("Authorization")?;
    let auth_str = auth_header.to_str().ok()?;
    if !auth_str.starts_with("Bearer ") {
        return None;
    }
    Some(auth_str[7..].to_string())
}

fn decode_jwt(token: &str, secret: &str) -> Option<Claims> {
    let validation = Validation::default();
    let decoded = decode::<Claims>(
        token,
        &DecodingKey::from_secret(secret.as_bytes()),
        &validation,
    )
    .ok()?;
    Some(decoded.claims)
}

// =========================
// Handlers Auth (Etapa 1)
// =========================

// POST /auth/register  (para pruebas / semilla)
async fn register(
    data: web::Data<AppState>,
    payload: web::Json<RegisterRequest>,
) -> impl Responder {
    let password_hash = match hash_password(&payload.password) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Error hasheando contraseña: {e}");
            return HttpResponse::InternalServerError().body("Error interno");
        }
    };

    let role = payload
        .role
        .clone()
        .unwrap_or_else(|| "user".to_string());

    let result = sqlx::query_as::<_, DbUser>(
        r#"
        INSERT INTO users (email, password_hash, full_name, phone, role)
        VALUES ($1, $2, $3, $4, $5)
        RETURNING id, email, password_hash, full_name, phone, role, last_login, created_at
        "#,
    )
    .bind(&payload.email)
    .bind(&password_hash)
    .bind(&payload.full_name)
    .bind(&payload.phone)
    .bind(&role)
    .fetch_one(&data.db_pool)
    .await;

    match result {
        Ok(user) => {
            let public: PublicUser = user.into();
            HttpResponse::Created().json(public)
        }
        Err(e) => {
            eprintln!("Error registrando usuario: {e}");
            HttpResponse::BadRequest().body("No se pudo registrar (¿email duplicado?)")
        }
    }
}

// POST /auth/login
async fn login(
    data: web::Data<AppState>,
    payload: web::Json<LoginRequest>,
) -> impl Responder {
    let user_result = sqlx::query_as::<_, DbUser>(
        r#"
        SELECT id, email, password_hash, full_name, phone, role, last_login, created_at
        FROM users
        WHERE email = $1
        "#,
    )
    .bind(&payload.email)
    .fetch_optional(&data.db_pool)
    .await;

    let user = match user_result {
        Ok(Some(u)) => u,
        Ok(None) => {
            return HttpResponse::Unauthorized().body("Credenciales inválidas");
        }
        Err(e) => {
            eprintln!("Error consultando usuario: {e}");
            return HttpResponse::InternalServerError().body("Error interno");
        }
    };

    // verificar contraseña
    if !verify_password(&user.password_hash, &payload.password) {
        return HttpResponse::Unauthorized().body("Credenciales inválidas");
    }

    // actualizar last_login
    let _ = sqlx::query("UPDATE users SET last_login = NOW() WHERE id = $1")
        .bind(user.id)
        .execute(&data.db_pool)
        .await;

    // generar token
    let token = match generate_jwt(&user, &data.jwt_secret) {
        Ok(t) => t,
        Err(e) => {
            eprintln!("Error generando JWT: {e}");
            return HttpResponse::InternalServerError().body("Error interno");
        }
    };

    // recargar usuario con last_login actualizado (opcional)
    let user = sqlx::query_as::<_, DbUser>(
        r#"
        SELECT id, email, password_hash, full_name, phone, role, last_login, created_at
        FROM users
        WHERE id = $1
        "#,
    )
    .bind(user.id)
    .fetch_one(&data.db_pool)
    .await
    .unwrap_or(user);

    let public: PublicUser = user.into();

    HttpResponse::Ok().json(LoginResponse { token, user: public })
}

// GET /auth/me
async fn me(data: web::Data<AppState>, req: HttpRequest) -> impl Responder {
    let token = match extract_token(&req) {
        Some(t) => t,
        None => return HttpResponse::Unauthorized().body("Falta token"),
    };

    let claims = match decode_jwt(&token, &data.jwt_secret) {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().body("Token inválido"),
    };

    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => return HttpResponse::Unauthorized().body("Token inválido"),
    };

    let result = sqlx::query_as::<_, DbUser>(
        r#"
        SELECT id, email, password_hash, full_name, phone, role, last_login, created_at
        FROM users
        WHERE id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(&data.db_pool)
    .await;

    match result {
        Ok(Some(user)) => {
            let public: PublicUser = user.into();
            HttpResponse::Ok().json(public)
        }
        Ok(None) => HttpResponse::NotFound().body("Usuario no encontrado"),
        Err(e) => {
            eprintln!("Error consultando usuario en /auth/me: {e}");
            HttpResponse::InternalServerError().body("Error interno")
        }
    }
}

// POST /auth/change-password
async fn change_password(
    data: web::Data<AppState>,
    req: HttpRequest,
    payload: web::Json<ChangePasswordRequest>,
) -> impl Responder {
    let token = match extract_token(&req) {
        Some(t) => t,
        None => return HttpResponse::Unauthorized().body("Falta token"),
    };

    let claims = match decode_jwt(&token, &data.jwt_secret) {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().body("Token inválido"),
    };

    let user_id = match Uuid::parse_str(&claims.sub) {
        Ok(id) => id,
        Err(_) => return HttpResponse::Unauthorized().body("Token inválido"),
    };

    // Obtener usuario
    let result = sqlx::query_as::<_, DbUser>(
        r#"
        SELECT id, email, password_hash, full_name, phone, role, last_login, created_at
        FROM users
        WHERE id = $1
        "#,
    )
    .bind(user_id)
    .fetch_optional(&data.db_pool)
    .await;

    let user = match result {
        Ok(Some(u)) => u,
        Ok(None) => return HttpResponse::NotFound().body("Usuario no encontrado"),
        Err(e) => {
            eprintln!("Error consultando usuario en change-password: {e}");
            return HttpResponse::InternalServerError().body("Error interno");
        }
    };

    // Verificar contraseña actual
    if !verify_password(&user.password_hash, &payload.current_password) {
        return HttpResponse::Unauthorized().body("Contraseña actual incorrecta");
    }

    // Hashear nueva contraseña
    let new_hash = match hash_password(&payload.new_password) {
        Ok(h) => h,
        Err(e) => {
            eprintln!("Error hasheando nueva contraseña: {e}");
            return HttpResponse::InternalServerError().body("Error interno");
        }
    };

    // Actualizar en BD
    let update = sqlx::query("UPDATE users SET password_hash = $1 WHERE id = $2")
        .bind(new_hash)
        .bind(user.id)
        .execute(&data.db_pool)
        .await;

    match update {
        Ok(_) => HttpResponse::Ok().body("Contraseña actualizada"),
        Err(e) => {
            eprintln!("Error actualizando contraseña: {e}");
            HttpResponse::InternalServerError().body("Error interno")
        }
    }
}

// =========================
// Etapa 2 – Root y People
// =========================

// Root local tipo:
// {
//   "films": ".../films/",
//   "people": ".../people/",
//   ...
// }
#[derive(Serialize)]
struct LocalRoot {
    films: String,
    people: String,
    planets: String,
    species: String,
    starships: String,
    vehicles: String,
}

async fn api_root() -> impl Responder {
    // En local usas tu host/puerto:
    let base = "http://127.0.0.1:4000/examen/api/v1";

    let res = LocalRoot {
        films: format!("{base}/films/"),
        people: format!("{base}/people/"),
        planets: format!("{base}/planets/"),
        species: format!("{base}/species/"),
        starships: format!("{base}/starships/"),
        vehicles: format!("{base}/vehicles/"),
    };

    HttpResponse::Ok().json(res)
}

// POST /admin/sync/people
// Baja people de SWAPI y las guarda en la tabla `people`
async fn sync_people(
    data: web::Data<AppState>,
    req: HttpRequest,
) -> impl Responder {
    // Verificar token y rol admin
    let token = match extract_token(&req) {
        Some(t) => t,
        None => return HttpResponse::Unauthorized().body("Falta token"),
    };

    let claims = match decode_jwt(&token, &data.jwt_secret) {
        Some(c) => c,
        None => return HttpResponse::Unauthorized().body("Token inválido"),
    };

    if claims.role != "admin" {
        return HttpResponse::Forbidden().body("Solo admin puede sincronizar");
    }

    let client = &data.http_client;
    let mut url = "https://swapi.dev/api/people/".to_string();
    let mut total_insertados = 0;

    loop {
        let resp = match client.get(&url).send().await {
            Ok(r) => r,
            Err(e) => {
                eprintln!("Error llamando SWAPI: {e}");
                return HttpResponse::BadGateway().body("Error llamando SWAPI");
            }
        };

        let json: Value = match resp.json().await {
            Ok(j) => j,
            Err(e) => {
                eprintln!("Error parseando JSON SWAPI: {e}");
                return HttpResponse::InternalServerError().body("Error JSON");
            }
        };

        let results = json["results"]
            .as_array()
            .cloned()
            .unwrap_or_default();

        for person in results {
            if let Some(url_person) = person["url"].as_str() {
                // extraer id: https://swapi.dev/api/people/1/ → 1
                if let Some(id_str) = url_person.trim_end_matches('/').rsplit('/').next() {
                    if let Ok(swapi_id) = id_str.parse::<i32>() {
                        let res = sqlx::query!(
                            r#"
                            INSERT INTO people (swapi_id, data)
                            VALUES ($1, $2)
                            ON CONFLICT (swapi_id) DO UPDATE SET data = EXCLUDED.data
                            "#,
                            swapi_id,
                            person
                        )
                        .execute(&data.db_pool)
                        .await;

                        match res {
                            Ok(_) => total_insertados += 1,
                            Err(e) => eprintln!("Error insertando people {swapi_id}: {e}"),
                        }
                    }
                }
            }
        }

        // siguiente página
        if let Some(next_url) = json["next"].as_str() {
            url = next_url.to_string();
        } else {
            break;
        }
    }

    HttpResponse::Ok().body(format!(
        "Sincronización de people completada ({} registros procesados)",
        total_insertados
    ))
}

// GET /examen/api/v1/people/
#[derive(Serialize)]
struct PeopleResponse {
    count: usize,
    results: Vec<Value>,
}

async fn list_people(data: web::Data<AppState>) -> impl Responder {
    let rows = sqlx::query!(
        r#"
        SELECT data
        FROM people
        ORDER BY swapi_id
        "#
    )
    .fetch_all(&data.db_pool)
    .await;

    match rows {
        Ok(rs) => {
            let results: Vec<Value> = rs.into_iter().map(|r| r.data).collect();
            let res = PeopleResponse {
                count: results.len(),
                results,
            };
            HttpResponse::Ok().json(res)
        }
        Err(e) => {
            eprintln!("Error leyendo people de BD: {e}");
            HttpResponse::InternalServerError().body("Error leyendo BD")
        }
    }
}

// =========================
// main
// =========================

#[actix_web::main]
async fn main() -> std::io::Result<()> {
    dotenv().ok();

    let db_url = env::var("DATABASE_URL").expect("Falta DATABASE_URL");
    let jwt_secret = env::var("JWT_SECRET").expect("Falta JWT_SECRET");

    let db_pool = Pool::<Postgres>::connect(&db_url)
        .await
        .expect("No se pudo conectar a Supabase");

    let http_client = reqwest::Client::new();

    let state = AppState {
        db_pool,
        jwt_secret,
        http_client,
    };

    println!("🚀 Backend en http://127.0.0.1:4000");

    HttpServer::new(move || {
        let cors = Cors::default()
            .allow_any_origin()
            .allow_any_method()
            .allow_any_header();

        App::new()
            .wrap(cors)
            .app_data(web::Data::new(state.clone()))
            // Etapa 1: auth
            .route("/auth/register", web::post().to(register))
            .route("/auth/login", web::post().to(login))
            .route("/auth/me", web::get().to(me))
            .route("/auth/change-password", web::post().to(change_password))
            // Etapa 2: root y people
            .route("/examen/api/v1", web::get().to(api_root))
            .route("/examen/api/v1/people/", web::get().to(list_people))
            .route("/admin/sync/people", web::post().to(sync_people))
    })
    .bind(("127.0.0.1", 4000))?
    .run()
    .await
}

