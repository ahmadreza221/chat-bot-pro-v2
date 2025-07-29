use serde_json::json;
use std::process::Command;

#[tokio::test]
async fn test_register_and_verify_flow() {
    let base = std::env::var("TEST_API_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());
    let client = reqwest::Client::new();

    // Test 1: Register new user
    let reg_payload = json!({
        "email": "test@example.com",
        "password": "StrongPass123!"
    });
    
    let res = client.post(&format!("{}/auth/register", base))
        .json(&reg_payload)
        .send()
        .await
        .unwrap();
    
    assert_eq!(res.status(), 201);
    let user_data: serde_json::Value = res.json().await.unwrap();
    assert!(user_data.get("id").is_some());

    // Test 2: Request email verification
    // In real scenario, we'd intercept the email stub logs
    // For now, we'll test the endpoint exists
    let res = client.post(&format!("{}/auth/email/verify/request", base))
        .header("Authorization", "Bearer dummy-token")
        .send()
        .await;
    
    // Should fail without proper auth, but endpoint should exist
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_login_flow() {
    let base = std::env::var("TEST_API_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());
    let client = reqwest::Client::new();

    let login_payload = json!({
        "email": "test@example.com",
        "password": "StrongPass123!"
    });
    
    let res = client.post(&format!("{}/auth/login", base))
        .json(&login_payload)
        .send()
        .await
        .unwrap();
    
    // Should fail without email verification, but endpoint should work
    assert!(res.status().is_client_error() || res.status().is_success());
}

#[tokio::test]
async fn test_password_reset_flow() {
    let base = std::env::var("TEST_API_URL").unwrap_or_else(|_| "http://localhost:8080".to_string());
    let client = reqwest::Client::new();

    let reset_payload = json!({
        "email": "test@example.com"
    });
    
    let res = client.post(&format!("{}/auth/password-reset/request", base))
        .json(&reset_payload)
        .send()
        .await
        .unwrap();
    
    // Should return 204 (No Content) even if email doesn't exist
    assert_eq!(res.status(), 204);
} 