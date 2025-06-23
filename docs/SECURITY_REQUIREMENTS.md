# Sicherheitsanforderungen - nAI Backend v5

## 🚨 KRITISCHE ANFORDERUNGEN - MUSS EINGEHALTEN WERDEN!

### 1. KEINE LOKALE AUTHENTIFIZIERUNG

**VERBOTEN:**
- ❌ Lokale User-Tabellen mit Passwörtern
- ❌ Password-Hash Felder in der Datenbank
- ❌ Login-Endpoints mit Username/Password
- ❌ Passwort-Reset Funktionalität
- ❌ OTP/TOTP als primäre Authentifizierung

**ERLAUBT:**
- ✅ Authentik als einziger Auth-Provider
- ✅ Token Exchange Service
- ✅ Session Sync mit Authentik

### 2. NUR DEVICE-BASIERTE AUTHENTIFIZIERUNG

**PFLICHT-METHODEN:**
```python
ALLOWED_AUTH_METHODS = [
    "webauthn",      # FIDO2/WebAuthn
    "passkey",       # Platform Authenticators
    "device_cert",   # X.509 Device Certificates
    "platform_auth"  # Windows Hello, Touch ID, Face ID
]

# EXPLIZIT VERBOTEN
FORBIDDEN_AUTH_METHODS = [
    "password",
    "sms",
    "email_password",
    "otp",  # nur als Backup nach Device Auth
    "magic_link"  # nur als Fallback
]
```

### 3. DATENBANK-SCHEMA OHNE PASSWÖRTER

```sql
-- RICHTIG: User-Tabelle ohne Passwort-Felder
CREATE TABLE users (
    id UUID PRIMARY KEY,
    external_id VARCHAR(255) UNIQUE NOT NULL,  -- Authentik User ID
    email VARCHAR(255) ENCRYPTED,
    tenant_id UUID NOT NULL,
    -- KEINE password oder password_hash Spalte!
    created_at TIMESTAMP NOT NULL,
    last_device_auth TIMESTAMP
);

-- RICHTIG: Device Authentication Tabelle
CREATE TABLE user_devices (
    id UUID PRIMARY KEY,
    user_id UUID REFERENCES users(id),
    device_type VARCHAR(50) CHECK (device_type IN ('webauthn', 'passkey', 'device_cert')),
    credential_id VARCHAR(255) UNIQUE,
    public_key TEXT,
    aaguid UUID,  -- Authenticator ID
    sign_count INTEGER,
    created_at TIMESTAMP NOT NULL,
    last_used TIMESTAMP
);
```

### 4. API ENDPOINTS OHNE PASSWÖRTER

```python
# ❌ VERBOTEN - Dieser Endpoint darf NICHT existieren!
@app.post("/auth/login")
async def login(username: str, password: str):
    # NIEMALS IMPLEMENTIEREN!
    raise NotImplementedError("Password auth is forbidden!")

# ✅ ERLAUBT - Nur Device-basierte Auth
@app.post("/auth/device/challenge")
async def create_device_challenge(
    device_type: Literal["webauthn", "passkey", "device_cert"],
    device_info: DeviceInfo
):
    # Erstellt Challenge für Device Auth
    return await device_auth_manager.create_challenge(device_type, device_info)

# ✅ ERLAUBT - Token Exchange mit Authentik
@app.post("/auth/token/exchange")
async def exchange_authentik_token(
    authentik_token: str,
    tenant_id: str
):
    # Tauscht Authentik Token gegen internes JWT
    return await token_exchange.exchange(authentik_token, tenant_id)
```

### 5. AUTHENTIK KONFIGURATION

```yaml
# Authentik Flow Configuration
name: "Passwordless Authentication Flow"
slug: "passwordless-authentication"
designation: "authentication"

stages:
  - identification_stage:
      name: "identification"
      user_fields:
        - "email"
        - "username"
      password_stage: null  # KEIN Passwort-Stage!
      
  - authenticator_validate_stage:
      name: "authenticator-validation"
      device_classes:
        - "webauthn"
      not_configured_action: "configure"
      webauthn_user_verification: "required"
```

### 6. ENVIRONMENT VARIABLES

```bash
# Diese MÜSSEN gesetzt sein
DEVICE_AUTH_REQUIRED=true
PASSWORD_AUTH_ENABLED=false
AUTHENTIK_BASE_URL=https://auth.example.com
WEBAUTHN_USER_VERIFICATION=required

# Diese dürfen NICHT existieren
# PASSWORD_MIN_LENGTH=xxx  # VERBOTEN
# PASSWORD_COMPLEXITY=xxx  # VERBOTEN
# ALLOW_PASSWORD_LOGIN=xxx # VERBOTEN
```

### 7. SICHERHEITS-CHECKS

```python
# Startup Security Check
@app.on_event("startup")
async def security_check():
    """Überprüft Sicherheitskonfiguration beim Start."""
    
    # Check 1: Keine Passwort-Auth aktiviert
    if os.getenv("PASSWORD_AUTH_ENABLED", "false").lower() != "false":
        raise SecurityError("PASSWORD_AUTH_ENABLED must be false!")
        
    # Check 2: Device Auth ist Pflicht
    if os.getenv("DEVICE_AUTH_REQUIRED", "true").lower() != "true":
        raise SecurityError("DEVICE_AUTH_REQUIRED must be true!")
        
    # Check 3: Authentik ist konfiguriert
    if not os.getenv("AUTHENTIK_BASE_URL"):
        raise SecurityError("AUTHENTIK_BASE_URL must be configured!")
        
    # Check 4: Keine password-Felder in User Model
    from sqlalchemy import inspect
    mapper = inspect(User)
    for column in mapper.columns:
        if 'password' in column.name.lower():
            raise SecurityError(f"Password field '{column.name}' found in User model!")
            
    logger.info("✅ Security checks passed - Passwordless only!")
```

### 8. CODE REVIEW CHECKLIST

Bei JEDEM Code Review MUSS geprüft werden:

- [ ] Keine Login-Endpoints mit Passwörtern
- [ ] Keine password/password_hash Felder in Models
- [ ] Alle Auth-Flows gehen über Authentik
- [ ] Nur Device-basierte Auth-Methoden implementiert
- [ ] WebAuthn user_verification = "required"
- [ ] Keine Passwort-Validierungslogik
- [ ] Keine Passwort-Reset Funktionen
- [ ] Authentik Token Exchange implementiert

### 9. TESTING REQUIREMENTS

```python
# Test: Passwort-Auth ist blockiert
def test_password_auth_forbidden():
    """Testet dass Passwort-Auth nicht möglich ist."""
    response = client.post("/auth/login", json={
        "username": "test",
        "password": "test123"
    })
    assert response.status_code == 404  # Endpoint existiert nicht!

# Test: Nur Device Auth funktioniert
def test_only_device_auth_works():
    """Testet dass nur Device-basierte Auth funktioniert."""
    # WebAuthn Challenge
    response = client.post("/auth/device/challenge", json={
        "device_type": "webauthn",
        "device_info": {...}
    })
    assert response.status_code == 200
    
    # Password Auth - darf nicht existieren
    with pytest.raises(AttributeError):
        client.post("/auth/password/login")
```

### 10. DEPLOYMENT CHECKLIST

Vor JEDEM Deployment:

1. **Environment Check**
   ```bash
   ./scripts/check-security.sh
   # Prüft: PASSWORD_AUTH_ENABLED=false
   # Prüft: DEVICE_AUTH_REQUIRED=true
   # Prüft: AUTHENTIK_BASE_URL ist gesetzt
   ```

2. **Database Check**
   ```sql
   -- Darf KEINE Ergebnisse liefern!
   SELECT column_name 
   FROM information_schema.columns 
   WHERE table_schema = 'public' 
   AND column_name LIKE '%password%';
   ```

3. **API Check**
   ```bash
   # Darf 404 zurückgeben
   curl -X POST https://api.example.com/auth/login
   
   # Muss 200 zurückgeben
   curl -X POST https://api.example.com/auth/device/challenge
   ```

---

## Konsequenzen bei Nicht-Einhaltung

1. **Code wird NICHT gemerged**
2. **Deployment wird BLOCKIERT**
3. **Security Audit FAILED**
4. **Entwickler muss Security Training wiederholen**

## Ausnahmen

**KEINE AUSNAHMEN!** Diese Anforderungen sind nicht verhandelbar.

---

**Dokument Version**: 1.0  
**Gültig ab**: Sofort  
**Review-Zyklus**: Monatlich  
**Verantwortlich**: Security Team