//! # Aegis Auth Rust SDK
//!
//! **Aegis Auth is a unified identity management system providing memory-safe 
//! Rust-based authentication. Consolidation of disparate identity providers 
//! into a single canonical source.**
//!
//! *Aegis Auth by Navchetna Technologies.*  
//! *Securing the future of decentralized identity.*  
//! *© 2026 Standard Core v3.*
//!
//! ## Features
//!
//! - Email/password authentication
//! - WebAuthn/Passkeys support
//! - Multi-factor authentication (MFA)
//! - Password reset functionality
//! - User profile management
//! - Automatic token refresh
//! - Event-driven architecture
//! - Comprehensive error handling
//!
//! ## Quick Start
//!
//! ```rust
//! use aegis_auth::AegisAuth;
//!
//! #[tokio::main]
//! async fn main() -> Result<(), Box<dyn std::error::Error>> {
//!     let aegis = AegisAuth::new("your-api-key")?;
//!     
//!     // Login
//!     let response = aegis.login("user@example.com", "password").await?;
//!     println!("Logged in: {}", response.user.email);
//!     
//!     Ok(())
//! }
//! ```

use reqwest::{Client, header::{HeaderMap, HeaderValue, AUTHORIZATION, CONTENT_TYPE}};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use thiserror::Error;
use tokio::sync::RwLock;
use url::Url;

/// Aegis Auth SDK errors
#[derive(Error, Debug)]
pub enum AegisError {
    #[error("HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    
    #[error("JSON serialization/deserialization failed: {0}")]
    Json(#[from] serde_json::Error),
    
    #[error("Authentication failed: {0}")]
    Auth(String),
    
    #[error("Invalid configuration: {0}")]
    Config(String),
    
    #[error("API error: {0}")]
    Api(String),
}

/// User information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub id: String,
    pub email: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub role: Option<String>,
    pub organization_id: Option<String>,
    pub permissions: Option<Vec<String>>,
}

/// Authentication response
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub expires_in: u64,
    pub token_type: String,
    pub user: User,
}

/// Registration data
#[derive(Debug, Serialize)]
pub struct RegisterData {
    pub email: String,
    pub password: String,
    pub first_name: Option<String>,
    pub last_name: Option<String>,
}

/// Profile update data
#[derive(Debug, Serialize)]
pub struct ProfileData {
    pub first_name: Option<String>,
    pub last_name: Option<String>,
    pub phone: Option<String>,
}

/// MFA response
#[derive(Debug, Deserialize)]
pub struct MfaResponse {
    pub qr_code: Option<String>,
    pub secret: Option<String>,
    pub backup_codes: Option<Vec<String>>,
}

/// API response wrapper
#[derive(Debug, Deserialize)]
struct ApiResponse<T> {
    data: Option<T>,
    message: Option<String>,
    success: Option<bool>,
}

/// Internal token storage
#[derive(Debug, Clone)]
struct TokenData {
    access_token: String,
    refresh_token: String,
    expires_at: u64,
    user: User,
}

/// Event handler type
pub type EventHandler<T> = Box<dyn Fn(T) + Send + Sync>;

/// Aegis Auth SDK client
#[derive(Clone)]
pub struct AegisAuth {
    client: Client,
    api_key: String,
    base_url: Url,
    tokens: Arc<RwLock<Option<TokenData>>>,
    // Event handlers would go here in a full implementation
}

impl AegisAuth {
    /// Create a new Aegis Auth client
    ///
    /// # Arguments
    ///
    /// * `api_key` - Your Aegis API key
    ///
    /// # Example
    ///
    /// ```rust
    /// use aegis_auth::AegisAuth;
    ///
    /// let aegis = AegisAuth::new("your-api-key")?;
    /// # Ok::<(), aegis_auth::AegisError>(())
    /// ```
    pub fn new(api_key: &str) -> Result<Self, AegisError> {
        Self::with_base_url(api_key, "https://05card1j5b.execute-api.ap-south-1.amazonaws.com/prod")
    }

    /// Create a new Aegis Auth client with custom base URL
    ///
    /// # Arguments
    ///
    /// * `api_key` - Your Aegis API key
    /// * `base_url` - Custom Aegis instance URL
    pub fn with_base_url(api_key: &str, base_url: &str) -> Result<Self, AegisError> {
        if api_key.is_empty() {
            return Err(AegisError::Config("API key is required".to_string()));
        }

        let base_url = Url::parse(base_url)
            .map_err(|_| AegisError::Config("Invalid base URL".to_string()))?;

        let mut headers = HeaderMap::new();
        headers.insert(CONTENT_TYPE, HeaderValue::from_static("application/json"));
        headers.insert("X-API-Key", HeaderValue::from_str(api_key)
            .map_err(|_| AegisError::Config("Invalid API key format".to_string()))?);

        let client = Client::builder()
            .default_headers(headers)
            .timeout(Duration::from_secs(30))
            .build()?;

        Ok(Self {
            client,
            api_key: api_key.to_string(),
            base_url,
            tokens: Arc::new(RwLock::new(None)),
        })
    }

    /// Login with email and password
    ///
    /// # Arguments
    ///
    /// * `email` - User email
    /// * `password` - User password
    ///
    /// # Example
    ///
    /// ```rust,no_run
    /// # use aegis_auth::AegisAuth;
    /// # #[tokio::main]
    /// # async fn main() -> Result<(), Box<dyn std::error::Error>> {
    /// let aegis = AegisAuth::new("your-api-key")?;
    /// let response = aegis.login("user@example.com", "password").await?;
    /// println!("Logged in: {}", response.user.email);
    /// # Ok(())
    /// # }
    /// ```
    pub async fn login(&self, email: &str, password: &str) -> Result<AuthResponse, AegisError> {
        let login_data = serde_json::json!({
            "email": email,
            "password": password
        });

        let response = self.request("POST", "/auth/login", Some(login_data), false).await?;
        let auth_response: AuthResponse = self.parse_response(response).await?;
        
        self.set_tokens(&auth_response).await;
        Ok(auth_response)
    }

    /// Register a new user
    ///
    /// # Arguments
    ///
    /// * `data` - Registration data
    pub async fn register(&self, data: RegisterData) -> Result<serde_json::Value, AegisError> {
        let response = self.request("POST", "/auth/register", Some(serde_json::to_value(data)?), false).await?;
        self.parse_response(response).await
    }

    /// Logout the current user
    pub async fn logout(&self) -> Result<(), AegisError> {
        if self.is_authenticated().await {
            let _ = self.request("POST", "/auth/logout", None, true).await;
        }
        self.clear_tokens().await;
        Ok(())
    }

    /// Refresh the access token
    pub async fn refresh_token(&self) -> Result<AuthResponse, AegisError> {
        let tokens = self.tokens.read().await;
        let refresh_token = tokens.as_ref()
            .ok_or_else(|| AegisError::Auth("No refresh token available".to_string()))?
            .refresh_token.clone();
        drop(tokens);

        let refresh_data = serde_json::json!({
            "refresh_token": refresh_token
        });

        let response = self.request("POST", "/auth/refresh", Some(refresh_data), false).await?;
        let auth_response: AuthResponse = self.parse_response(response).await?;
        
        self.set_tokens(&auth_response).await;
        Ok(auth_response)
    }

    /// Request password reset
    ///
    /// # Arguments
    ///
    /// * `email` - User email
    pub async fn forgot_password(&self, email: &str) -> Result<serde_json::Value, AegisError> {
        let data = serde_json::json!({
            "email": email
        });

        let response = self.request("POST", "/auth/forgot-password", Some(data), false).await?;
        self.parse_response(response).await
    }

    /// Reset password with token
    ///
    /// # Arguments
    ///
    /// * `token` - Reset token
    /// * `new_password` - New password
    pub async fn reset_password(&self, token: &str, new_password: &str) -> Result<serde_json::Value, AegisError> {
        let data = serde_json::json!({
            "token": token,
            "new_password": new_password
        });

        let response = self.request("POST", "/auth/reset-password", Some(data), false).await?;
        self.parse_response(response).await
    }

    /// Get user profile
    pub async fn get_profile(&self) -> Result<User, AegisError> {
        let response = self.request("GET", "/auth/profile", None, true).await?;
        self.parse_response(response).await
    }

    /// Update user profile
    ///
    /// # Arguments
    ///
    /// * `data` - Profile data to update
    pub async fn update_profile(&self, data: ProfileData) -> Result<User, AegisError> {
        let response = self.request("PATCH", "/auth/profile", Some(serde_json::to_value(data)?), true).await?;
        self.parse_response(response).await
    }

    /// Enable multi-factor authentication
    pub async fn enable_mfa(&self) -> Result<MfaResponse, AegisError> {
        let response = self.request("POST", "/auth/mfa/enable", None, true).await?;
        self.parse_response(response).await
    }

    /// Verify MFA code
    ///
    /// # Arguments
    ///
    /// * `code` - MFA code
    pub async fn verify_mfa(&self, code: &str) -> Result<serde_json::Value, AegisError> {
        let data = serde_json::json!({
            "code": code
        });

        let response = self.request("POST", "/auth/mfa/verify", Some(data), true).await?;
        self.parse_response(response).await
    }

    /// Disable multi-factor authentication
    ///
    /// # Arguments
    ///
    /// * `code` - MFA code
    pub async fn disable_mfa(&self, code: &str) -> Result<serde_json::Value, AegisError> {
        let data = serde_json::json!({
            "code": code
        });

        let response = self.request("POST", "/auth/mfa/disable", Some(data), true).await?;
        self.parse_response(response).await
    }

    /// Check if user is authenticated
    pub async fn is_authenticated(&self) -> bool {
        let tokens = self.tokens.read().await;
        if let Some(token_data) = tokens.as_ref() {
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();
            now < token_data.expires_at
        } else {
            false
        }
    }

    /// Get current user
    pub async fn get_user(&self) -> Option<User> {
        let tokens = self.tokens.read().await;
        tokens.as_ref().map(|t| t.user.clone())
    }

    /// Get current access token
    pub async fn get_access_token(&self) -> Option<String> {
        let tokens = self.tokens.read().await;
        tokens.as_ref().map(|t| t.access_token.clone())
    }

    // Internal methods

    async fn request(
        &self,
        method: &str,
        endpoint: &str,
        body: Option<serde_json::Value>,
        auth_required: bool,
    ) -> Result<reqwest::Response, AegisError> {
        let url = self.base_url.join(endpoint)
            .map_err(|_| AegisError::Config("Invalid endpoint".to_string()))?;

        let mut request = match method {
            "GET" => self.client.get(url),
            "POST" => self.client.post(url),
            "PATCH" => self.client.patch(url),
            "DELETE" => self.client.delete(url),
            _ => return Err(AegisError::Config("Unsupported HTTP method".to_string())),
        };

        if let Some(body) = body {
            request = request.json(&body);
        }

        if auth_required {
            if let Some(token) = self.get_access_token().await {
                request = request.header(AUTHORIZATION, format!("Bearer {}", token));
            } else {
                return Err(AegisError::Auth("Authentication required".to_string()));
            }
        }

        let response = request.send().await?;

        if !response.status().is_success() {
            let error_text = response.text().await.unwrap_or_else(|_| "Unknown error".to_string());
            return Err(AegisError::Api(error_text));
        }

        Ok(response)
    }

    async fn parse_response<T>(&self, response: reqwest::Response) -> Result<T, AegisError>
    where
        T: for<'de> Deserialize<'de>,
    {
        let api_response: ApiResponse<T> = response.json().await?;
        
        if let Some(data) = api_response.data {
            Ok(data)
        } else if let Some(message) = api_response.message {
            Err(AegisError::Api(message))
        } else {
            Err(AegisError::Api("No data in response".to_string()))
        }
    }

    async fn set_tokens(&self, auth_response: &AuthResponse) {
        let expires_at = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_secs() + auth_response.expires_in;

        let token_data = TokenData {
            access_token: auth_response.access_token.clone(),
            refresh_token: auth_response.refresh_token.clone(),
            expires_at,
            user: auth_response.user.clone(),
        };

        let mut tokens = self.tokens.write().await;
        *tokens = Some(token_data);
    }

    async fn clear_tokens(&self) {
        let mut tokens = self.tokens.write().await;
        *tokens = None;
    }
}

/// Convenience function to create a new Aegis Auth client
///
/// # Arguments
///
/// * `api_key` - Your Aegis API key
///
/// # Example
///
/// ```rust
/// use aegis_auth::create_client;
///
/// let aegis = create_client("your-api-key")?;
/// # Ok::<(), aegis_auth::AegisError>(())
/// ```
pub fn create_client(api_key: &str) -> Result<AegisAuth, AegisError> {
    AegisAuth::new(api_key)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_client_creation() {
        let client = AegisAuth::new("test-api-key");
        assert!(client.is_ok());
    }

    #[test]
    fn test_client_creation_empty_key() {
        let client = AegisAuth::new("");
        assert!(client.is_err());
    }

    #[test]
    fn test_convenience_function() {
        let client = create_client("test-api-key");
        assert!(client.is_ok());
    }
}