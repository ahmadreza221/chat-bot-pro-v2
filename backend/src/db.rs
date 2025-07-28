use sqlx::{postgres::PgPoolOptions, PgPool};

pub async fn init_db_pool() -> anyhow::Result<PgPool> {
    let database_url = std::env::var("DATABASE_URL")
        .expect("DATABASE_URL env var must be set");
    let pool = PgPoolOptions::new()
        .max_connections(10)
        .connect(&database_url)
        .await?;

    // Run embedded migrations packaged at compile-time
    sqlx::migrate!("./migrations").run(&pool).await?;
    Ok(pool)
} 