# Aegis Auth - Rust SDK

**Aegis Auth is a unified identity management system providing memory-safe Rust-based authentication. Consolidation of disparate identity providers into a single canonical source.**

*Aegis Auth by Navchetna Technologies.*  
*Securing the future of decentralized identity.*  
*© 2026 Standard Core v3.*

---

Official Rust SDK for the Aegis Authentication System. Supports traditional authentication, WebAuthn/Passkeys, MFA, and more.

## Installation

Add this to your `Cargo.toml`:

```toml
[dependencies]
aegis-auth-navchetna = "1.0"
```

## Quick Start

```rust
use aegis_auth::AegisAuth;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Initialize the client
    let aegis = AegisAuth::new("your-api-key")?;

    // Login
    let response = aegis.login("user@example.com", "password").await?;
    println!("Logged in: {}", response.user.email);

    // Check authentication status
    if aegis.is_authenticated().await {
        println!("User is authenticated");
        if let Some(user) = aegis.get_user().await {
            println!("Current user: {}", user.email);
        }
    }

    Ok(())
}
```

## Authentication Methods

### Email/Password Authentication

```rust
use aegis_auth::{AegisAuth, RegisterData};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let aegis = AegisAuth::new("your-api-key")?;

    // Login
    let response = aegis.login("user@example.com", "password").await?;
    println!("Access token: {}", response.access_token);

    // Register
    let register_data = RegisterData {
        email: "user@example.com".to_string(),
        password: "securePassword123".to_string(),
        first_name: Some("John".to_string()),
        last_name: Some("Doe".to_string()),
    };
    
    let response = aegis.register(register_data).await?;
    println!("Registration successful");

    // Logout
    aegis.logout().await?;

    Ok(())
}
```

### Password Reset

```rust
use aegis_auth::AegisAuth;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let aegis = AegisAuth::new("your-api-key")?;

    // Request password reset
    aegis.forgot_password("user@example.com").await?;
    println!("Password reset email sent");

    // Reset password with token
    aegis.reset_password("reset-token", "newPassword123").await?;
    println!("Password reset successful");

    Ok(())
}
```

### Multi-Factor Authentication (MFA)

```rust
use aegis_auth::AegisAuth;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let aegis = AegisAuth::new("your-api-key")?;
    
    // Login first
    aegis.login("user@example.com", "password").await?;

    // Enable MFA
    let mfa_data = aegis.enable_mfa().await?;
    if let Some(qr_code) = mfa_data.qr_code {
        println!("QR Code: {}", qr_code);
    }
    if let Some(secret) = mfa_data.secret {
        println!("Secret: {}", secret);
    }

    // Verify MFA code
    aegis.verify_mfa("123456").await?;
    println!("MFA verified");

    // Disable MFA
    aegis.disable_mfa("123456").await?;
    println!("MFA disabled");

    Ok(())
}
```

### User Profile Management

```rust
use aegis_auth::{AegisAuth, ProfileData};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let aegis = AegisAuth::new("your-api-key")?;
    
    // Login first
    aegis.login("user@example.com", "password").await?;

    // Get profile
    let profile = aegis.get_profile().await?;
    println!("User profile: {:?}", profile);

    // Update profile
    let profile_data = ProfileData {
        first_name: Some("Jane".to_string()),
        last_name: Some("Smith".to_string()),
        phone: Some("+1234567890".to_string()),
    };
    
    let updated_profile = aegis.update_profile(profile_data).await?;
    println!("Profile updated: {:?}", updated_profile);

    Ok(())
}
```

## Token Management

```rust
use aegis_auth::AegisAuth;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let aegis = AegisAuth::new("your-api-key")?;

    // Check authentication status
    if aegis.is_authenticated().await {
        println!("User is authenticated");
    }

    // Get current user
    if let Some(user) = aegis.get_user().await {
        println!("Current user: {}", user.email);
    }

    // Get access token
    if let Some(token) = aegis.get_access_token().await {
        println!("Access token: {}", token);
    }

    // Manual token refresh
    let response = aegis.refresh_token().await?;
    println!("Token refreshed successfully");

    Ok(())
}
```

## Configuration

```rust
use aegis_auth::{AegisAuth, create_client};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    // Basic configuration
    let aegis = AegisAuth::new("your-api-key")?;

    // Custom base URL
    let aegis = AegisAuth::with_base_url(
        "your-api-key",
        "https://your-aegis-instance.com"
    )?;

    // Using convenience function
    let aegis = create_client("your-api-key")?;

    Ok(())
}
```

## Error Handling

```rust
use aegis_auth::{AegisAuth, AegisError};

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    let aegis = AegisAuth::new("your-api-key")?;

    match aegis.login("user@example.com", "wrongpassword").await {
        Ok(response) => {
            println!("Login successful: {}", response.user.email);
        }
        Err(AegisError::Auth(msg)) => {
            println!("Authentication error: {}", msg);
        }
        Err(AegisError::Http(err)) => {
            println!("Network error: {}", err);
        }
        Err(AegisError::Api(msg)) => {
            println!("API error: {}", msg);
        }
        Err(err) => {
            println!("Other error: {}", err);
        }
    }

    Ok(())
}
```

## Features

- **Memory Safe**: Built with Rust's memory safety guarantees
- **Async/Await**: Full async support with tokio
- **Type Safe**: Strong typing for all API interactions
- **Error Handling**: Comprehensive error types with thiserror
- **Automatic Token Management**: Handles token storage and refresh
- **Configurable**: Support for custom base URLs and timeouts
- **Well Documented**: Comprehensive documentation and examples

## Requirements

- Rust 1.70.0 or later
- tokio runtime for async operations

## Dependencies

- `reqwest` - HTTP client with JSON support
- `serde` - Serialization/deserialization
- `tokio` - Async runtime
- `thiserror` - Error handling
- `chrono` - Date/time handling
- `url` - URL parsing

## Security Best Practices

1. **Never expose your API key** in version control or logs
2. **Use environment variables** to store sensitive configuration
3. **Implement proper error handling** to avoid exposing sensitive information
4. **Use HTTPS** in production environments
5. **Implement logout functionality** to clear tokens when users sign out

## Examples

See the `examples/` directory for more comprehensive examples:

- `basic_auth.rs` - Basic authentication flow
- `mfa_setup.rs` - Multi-factor authentication setup
- `profile_management.rs` - User profile operations
- `error_handling.rs` - Comprehensive error handling

## Support

- Documentation: [https://aegis.navchetna.tech](https://aegis.navchetna.tech)
- Repository: [https://github.com/navchetnaofficialllp/aegis-auth-sdk-rust](https://github.com/navchetnaofficialllp/aegis-auth-sdk-rust)
- Issues: [https://github.com/navchetnaofficialllp/aegis-auth-sdk-rust/issues](https://github.com/navchetnaofficialllp/aegis-auth-sdk-rust/issues)
- Email: hello@navchetna.tech

---

**Aegis Auth by Navchetna Technologies**  
*Securing the future of decentralized identity*  
© 2026 Standard Core v3

## License

MIT License - see LICENSE file for details.