use serde_json::json;

#[tokio::test]
async fn register_and_verify() {
    let base = std::env::var("TEST_API_URL").expect("TEST_API_URL not set");
    let client = reqwest::Client::new();

    // Register user
    let reg = json!({"email":"test@example.com","password":"StrongPass123!"});
    let res = client.post(format!("{}/auth/register", base)).json(&reg).send().await.unwrap();
    assert_eq!(res.status(), 201);

    // Request verification token
    // In real tests we'd intercept email stub logs or query DB; placeholder only.
} 